pub mod error;

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod ios;

// #[cfg(target_os = "android")]
mod android;
pub use android::*;

// #[cfg(test)]
// mod test {
//     use crate::common_hsm::CommonHsm;
//     use crate::ios::Ios;
//     use askar_crypto::{
//         alg::p256::P256KeyPair,
//         repr::{KeyPublicBytes, KeySecretBytes, ToPublicBytes},
//     };
//     use sha2::{Digest, Sha256};
//
//     #[test]
//     fn askar_verify_ios_sig() {
//         let ios = Ios::new(true);
//         let msg = b"hello world!";
//
//         let signature_from_ios = ios.sign(msg);
//
//         let public_key = ios.to_public_key();
//         let verify_key = P256KeyPair::from_public_bytes(&public_key).unwrap();
//
//         let is_signature_valid = verify_key.verify_signature(msg, &signature_from_ios);
//
//         assert!(is_signature_valid);
//     }
//
//     #[test]
//     fn askar_identical_signature() {
//         let ios = Ios::new(false);
//         let msg = b"hello world";
//         let sk = ios.to_private_key();
//
//         let mut h = Sha256::new();
//         h.update(msg);
//         let d = h.finalize();
//
//         let sk = P256KeyPair::from_secret_bytes(&sk).unwrap();
//
//         let askar_signature = sk.sign(&d).unwrap().to_vec();
//         let ios_signature = ios.sign(&d);
//
//         assert_eq!(askar_signature, ios_signature);
//     }
//
//     #[test]
//     fn askar_identical_public_key() {
//         let ios = Ios::new(false);
//         let sk = ios.to_private_key();
//
//         let askar_pk = P256KeyPair::from_secret_bytes(&sk)
//             .unwrap()
//             .to_public_bytes()
//             .unwrap()
//             .to_vec();
//         let ios_pk = ios.to_public_key();
//
//         assert_eq!(askar_pk, ios_pk);
//     }
// }
