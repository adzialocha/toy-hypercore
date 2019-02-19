use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{Cursor, Error};
use std::net::{Ipv4Addr, SocketAddr};
use std::rc::Rc;
use std::str;
use std::time::Duration;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use futures::{Future, Stream};
use tokio::timer::Interval;
use tokio_core::reactor::Handle;
use trust_dns::op::{Message, MessageType, Query};
use trust_dns::rr::{Name, RecordType, Record, RData, rdata};
use trust_dns_proto::multicast::{MdnsStream, MdnsQueryType};
use trust_dns_proto::xfer::SerialMessage;

const NAME_SUFFIX: &str = "dat.local";

const MDNS_PORT: u16 = 5353;
const MDNS_ADDRESS: &str = "224.0.0.251";

pub struct DiscoveryPeer {
    addr: Ipv4Addr,
    port: u16,
    token: String,
}

impl DiscoveryPeer {
    pub fn addr(&self) -> Ipv4Addr {
        self.addr
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn token(&self) -> String {
        self.token.clone()
    }

    fn from_message(message: &Message) -> Option<DiscoveryPeer> {
        // Check TXT records of message for needed fields
        message
            .answers()
            .iter()
            .find_map(|rr| if let RData::TXT(ref rdata) = *rr.rdata() {
                // Append only "token" and "peers" fields
                let fields: Vec<Vec<&str>> = rdata
                    .iter()
                    .map(|d| str::from_utf8(d).unwrap())
                    .map(|s| s.splitn(2, "=").collect())
                    .filter_map(|t: Vec<&str>| {
                        if t.len() == 2 && (t[0] == "token" || t[0] == "peers") {
                            Some(t)
                        } else {
                            None
                        }
                    })
                .collect();

                // Both "token" and "peers" should be given
                if fields.len() == 2 {
                    let mut map: HashMap<String, String> = HashMap::with_capacity(2);

                    for field in fields {
                        map.insert(
                            String::from(field[0]),
                            String::from(field[1])
                        );
                    }

                    let token = map.get("token").unwrap().to_owned();
                    let peers = map.get("peers").unwrap();

                    let (addr, port) = DiscoveryPeer::decode_peers_field(&peers);

                    Some(DiscoveryPeer {
                        port,
                        addr,
                        token,
                    })
                } else {
                    None
                }
            } else {
                None
            })
    }

    fn encode_peers_field(&self) -> String {
        let mut writer = Vec::new();

        for octet in self.addr().octets().iter() {
            writer.write_u8(*octet).unwrap();
        }

        writer.write_u16::<BigEndian>(self.port()).unwrap();

        base64::encode(&writer)
    }

    fn decode_peers_field(data: &str) -> (Ipv4Addr, u16) {
        let mut reader = Cursor::new(base64::decode(data).unwrap());

        let addr = Ipv4Addr::new(
            reader.read_u8().unwrap(),
            reader.read_u8().unwrap(),
            reader.read_u8().unwrap(),
            reader.read_u8().unwrap()
        );

        let port = reader.read_u16::<BigEndian>().unwrap();

        (addr, port)
    }
}

struct DiscoveryChannel {
    name: Name,
    peer: DiscoveryPeer,
}

impl DiscoveryChannel {
    fn create_mdns_question(&self) -> Message {
        let mut message = Message::new();

        let mut query = Query::new();
        query.set_query_type(RecordType::TXT);
        query.set_name(self.name.clone());

        message.add_query(query);

        message
    }

    fn create_mdns_answer(&self) -> Message {
        let mut message = self.create_mdns_question();
        message.set_message_type(MessageType::Response);

        let txt_data = vec![
            format!("token={}", self.peer.token()),
            format!("peers={}", self.peer.encode_peers_field()),
        ];

        let mut record = Record::new();
        record.set_name(self.name.clone());
        record.set_record_type(RecordType::TXT);
        record.set_rdata(RData::TXT(rdata::txt::TXT::new(txt_data)));

        message.add_answer(record);

        message
    }
}

pub struct Discovery {
    inner: Rc<RefCell<DiscoveryChannel>>,
    handle: Handle,
}

impl Discovery {
    pub fn new(
        handle: Handle,
        discovery_key_full: &[u8],
        port: u16,
        token: String,
    ) -> Discovery {
        // Shorten and convert hash to 40 hex chars
        let discovery_key_hex = hex::encode(discovery_key_full);
        let discovery_key = discovery_key_hex[..40].to_string();

        // Set DNS name to identify what we are interested in
        let name = Name::from_ascii(
            &format!("{}.{}", discovery_key, NAME_SUFFIX)).unwrap();

        // Define own peer node
        let peer = DiscoveryPeer {
            addr: Ipv4Addr::UNSPECIFIED,
            port,
            token,
        };

        let inner = Rc::new(RefCell::new(DiscoveryChannel {
            name,
            peer,
        }));

        Discovery {
            handle,
            inner,
        }
    }

    pub fn find_peers(&self)
        -> impl Future<Item=impl Stream<Item=DiscoveryPeer, Error=Error>, Error=Error>
    {
        // Create multicast DNS Stream
        let multicast_addr = SocketAddr::new(
            MDNS_ADDRESS.parse().unwrap(), MDNS_PORT);

        let (mdns_stream, mdns_stream_sender) = MdnsStream::new(
            multicast_addr, MdnsQueryType::OneShotJoin, Some(1), None, None);

        let question_query = self.inner.borrow().create_mdns_question().to_vec().unwrap();
        let mdns_stream_sender_clone = mdns_stream_sender.clone();

        // Send queries to find new peers every 60 seconds
        let question_interval = Interval::new_interval(Duration::from_millis(60000))
            .for_each(move |_| {
                let question_message = SerialMessage::new(
                    question_query.clone(),
                    multicast_addr
                );

                mdns_stream_sender_clone
                    .unbounded_send(question_message).unwrap();

                Ok(())
            });

        self.handle.spawn(question_interval.then(|_| { Ok(()) }));

        // Read incoming queries, find interested peers
        // and return them as consumable futures stream
        let inner_clone = self.inner.clone();
        let name_clone = inner_clone.borrow().name.clone();
        let answer_response = inner_clone.borrow().create_mdns_answer().to_vec().unwrap();
        let token_clone = inner_clone.borrow().peer.token.clone();

        mdns_stream.and_then(move |stream| {
            let peer_stream = stream
                .filter_map(move |message_raw| {
                    match Message::from_vec(message_raw.bytes()) {
                        Ok(message) => {
                            // Filter messages looking for same name
                            let has_same_name = message
                                .queries()
                                .iter()
                                .any(|q| q.name().eq_case(&name_clone));

                            if has_same_name {
                                Some(message)
                            } else {
                                None
                            }
                        },
                        Err(_) => None
                    }
                })
                .filter_map(move |message| {
                    match message.message_type() {
                        MessageType::Query => {
                            let answer_message = SerialMessage::new(
                                answer_response.clone(),
                                multicast_addr
                            );

                            // Respond with answer to query
                            mdns_stream_sender
                                .unbounded_send(answer_message).unwrap();

                            None
                        },
                        MessageType::Response => {
                            // Check if we got response with required fields
                            match DiscoveryPeer::from_message(&message) {
                                Some(interested_peer) => {
                                    // Make sure this is not our response
                                    if interested_peer.token != token_clone {
                                        Some(interested_peer)
                                    } else {
                                        None
                                    }
                                },
                                None => None,
                            }
                        }
                    }
                });

            Ok(peer_stream)
        })
    }
}
