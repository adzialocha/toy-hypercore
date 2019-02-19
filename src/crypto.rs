use blake2_rfc::blake2b::{blake2b, Blake2bResult};
use ed25519_dalek::Keypair;
use rand::Rng;
use rand::rngs::OsRng;
use sha2::{Sha256, Sha512, Digest};

const DISCOVERY_KEY_NAME: &[u8] = b"hypercore";

pub fn generate_keypair() -> Keypair {
    let mut csprng: OsRng = OsRng::new().unwrap();

    Keypair::generate::<Sha512, _>(&mut csprng)
}

pub fn generate_discovery_key(public_key: &[u8]) -> Blake2bResult {
    blake2b(32, public_key, DISCOVERY_KEY_NAME)
}

pub fn generate_random_token() -> String {
    let rnd = format!("{:?}", rand::thread_rng().gen::<f64>());

    base64::encode(&Sha256::digest(rnd.as_bytes()))
}
