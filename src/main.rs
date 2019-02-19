extern crate base64;
extern crate blake2_rfc;
extern crate ed25519_dalek;
extern crate getopts;
extern crate hex;
extern crate rand;
extern crate sha2;

pub mod crypto;

const DAT_URL_PROTOCOL: &str = "dat://";

fn main() {
    // Parse command-line arguments
    let args: Vec<String> = std::env::args().collect();

    let mut opts = getopts::Options::new();
    opts.optopt("c", "clone", "clone data from this URL", "<link>");

    // Generate public and secret keypair
    let keypair = crypto::generate_keypair();

    // Create or clone hypercore depending on given arguments
    let matches = opts.parse(&args[1..]).unwrap();
    let is_cloning = matches.opt_present("clone");

    // Prepare dat:// URL with public key
    let decoded_key;

    let public_key: &[u8] = if is_cloning {
        let clone_public_key = matches.opt_str("clone").unwrap()
            .replace(DAT_URL_PROTOCOL, "");

        decoded_key = hex::decode(clone_public_key).unwrap();
        &decoded_key
    } else {
        keypair.public.as_bytes()
    };

    println!("{}{}", DAT_URL_PROTOCOL, hex::encode(public_key));

    // Build a discovery key (hashed public key and name)
    let discovery_key = crypto::generate_discovery_key(public_key);

    // Generate an individual token to identify ourselves
    let token = crypto::generate_random_token();

    println!("Discovery Key: {:?}\nToken: {}", discovery_key.as_bytes(), token);
}
