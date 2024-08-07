use askar_crypto::{alg::p256::P256KeyPair, repr::KeyPublicBytes};
use secure_env::{KeyOps, SecureEnvironment, SecureEnvironmentOps};
use std::{
    panic::catch_unwind,
    process::exit,
    ptr::{addr_of, null},
};
use uuid::Uuid;

macro_rules! run_tests {
    ($($test:ident),*) => {
        $(
            let result = catch_unwind(|| {
                $test();
            });
            let test_name = stringify!($test);
            match result {
                Ok(_) => {
                    println!("{test_name} passed!");
                }
                Err(e) => {
                    eprintln!("{test_name} failed!");
                    eprintln!("{e:?}");
                    exit(1)
                }
            }
        )*
    }
}

pub fn run_tests() {
    run_tests!(
        test_generate_keypair,
        test_get_keypair_by_id,
        test_get_public_key,
        test_generate_and_sign,
        test_generate_and_sign_and_verify_with_askar,

        test_get_by_id_and_get_public_key,
        test_get_by_id_and_sign,
        test_get_by_id_and_sign_and_verify_with_askar
    );
}

fn test_generate_keypair() {
    let id = Uuid::new_v4();
    let key = SecureEnvironment::generate_keypair(id, false).unwrap();

    assert!((addr_of!(key) != null()));
}

fn test_get_keypair_by_id() {
    let id = Uuid::new_v4();

    SecureEnvironment::generate_keypair(id, false).unwrap();
    let key = SecureEnvironment::get_keypair_by_id(id).unwrap();

    assert!((addr_of!(key) != null()));
}

fn test_get_public_key() {
    let id = Uuid::new_v4();
    let key = SecureEnvironment::generate_keypair(id, false).unwrap();

    let public_key = key.get_public_key().unwrap();

    assert_eq!(public_key.len(), 33);
}

fn test_get_by_id_and_get_public_key() {
    let id = Uuid::new_v4();

    SecureEnvironment::generate_keypair(id, false).unwrap();
    let key = SecureEnvironment::get_keypair_by_id(id).unwrap();

    let public_key = key.get_public_key().unwrap();

    assert!(p256::PublicKey::from_sec1_bytes(&public_key).is_ok());
    assert_eq!(public_key.len(), 33);
}

fn test_generate_and_sign() {
    let id = Uuid::new_v4();
    let key = SecureEnvironment::generate_keypair(id,false).unwrap();
    let msg  = b"Hello World!";

    let signature = key.sign(msg).unwrap();

    assert!(p256::ecdsa::Signature::from_slice(&signature).is_ok());
    assert_eq!(signature.len(), 64);
}

fn test_get_by_id_and_sign() {
    let id = Uuid::new_v4();
    SecureEnvironment::generate_keypair(id,false).unwrap();
    let key = SecureEnvironment::get_keypair_by_id(id).unwrap();
    let msg  = b"Hello World!";

    let signature = key.sign(msg).unwrap();


    assert_eq!(signature.len(), 64);
}

fn test_generate_and_sign_and_verify_with_askar() {
    let id = Uuid::new_v4();
    let key = SecureEnvironment::generate_keypair(id,false).unwrap();
    let public_key = key.get_public_key().unwrap();
    let msg  = b"Hello World!";

    let signature = key.sign(msg).unwrap();

    let keypair = P256KeyPair::from_public_bytes(&public_key).unwrap();

    let is_valid = keypair.verify_signature(msg, &signature);

    assert!(is_valid);

}

fn test_get_by_id_and_sign_and_verify_with_askar() {
    let id = Uuid::new_v4();
    SecureEnvironment::generate_keypair(id,false).unwrap();
    let key = SecureEnvironment::get_keypair_by_id(id).unwrap();
    let public_key = key.get_public_key().unwrap();
    let msg  = b"Hello World!";

    let signature = key.sign(msg).unwrap();

    let keypair = P256KeyPair::from_public_bytes(&public_key).unwrap();

    let is_valid = keypair.verify_signature(msg, &signature);

    assert!(is_valid);

}
