use askar_crypto::{alg::p256::P256KeyPair, repr::KeyPublicBytes};
use secure_env::{KeyOps, SecureEnvironment, SecureEnvironmentOps};
use uuid::Uuid;

#[no_mangle]
pub extern "C" fn main_rs() {
    let id = Uuid::new_v4();
    let msg = b"Hello World!";

    {
        let key = SecureEnvironment::generate_keypair(id).unwrap();
        let public_key = key.get_public_key().unwrap();
        let sig = key.sign(msg).unwrap();
        let verify_key = P256KeyPair::from_public_bytes(&public_key).unwrap();
        let is_signature_valid = verify_key.verify_signature(msg, &sig);
        println!("is generated key signature valid: {is_signature_valid:?}");
    }

    {
        let key = SecureEnvironment::get_keypair_by_id(id).unwrap();
        let public_key = key.get_public_key().unwrap();
        let sig = key.sign(msg).unwrap();
        let verify_key = P256KeyPair::from_public_bytes(&public_key).unwrap();
        let is_signature_valid = verify_key.verify_signature(msg, &sig);
        println!("is retrieved key signature valid: {is_signature_valid:?}");
    }
}
