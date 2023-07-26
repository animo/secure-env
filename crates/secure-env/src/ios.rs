use p256::{ecdsa::Signature, elliptic_curve::group::GroupEncoding, PublicKey};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};

use crate::common_hsm::CommonHsm;

#[derive(Debug)]
pub struct Key(SecKey);

impl Key {
    pub fn new() -> Self {
        let mut opts = GenerateKeyOptions::default();
        opts.set_key_type(KeyType::ec());
        opts.set_token(Token::SecureEnclave);
        opts.set_label("some-app");
        let key = SecKey::generate(opts.to_dictionary()).unwrap();
        Self(key)
    }

    fn to_sec1_bytes(&self) -> Vec<u8> {
        self.0
            .public_key()
            .unwrap()
            .external_representation()
            .unwrap()
            .to_vec()
    }

    pub fn to_private_key(&self) -> Vec<u8> {
        self.0
            .external_representation()
            .unwrap()
            .to_vec()
            .drain(1 + 32 + 32..)
            .collect()
    }
}

impl CommonHsm for Key {
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let der_sig = self
            .0
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, message)
            .unwrap();

        let sig = Signature::from_der(&der_sig).unwrap();
        sig.to_vec()
    }

    fn to_public_key(&self) -> Vec<u8> {
        let pk = PublicKey::from_sec1_bytes(&self.to_sec1_bytes()).unwrap();
        pk.as_affine().to_bytes().to_vec()
    }
}
