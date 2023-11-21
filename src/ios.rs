use crate::{
    error::{Error, Result},
    senv,
};
use p256::{ecdsa::Signature, elliptic_curve::group::GroupEncoding, PublicKey};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};

#[derive(Debug)]
pub struct Key(SecKey);

impl Key {
    pub fn new() -> Result<Self> {
        let mut opts = GenerateKeyOptions::default();
        opts.set_key_type(KeyType::ec());
        opts.set_token(Token::SecureEnclave);
        opts.set_label("some-app");
        let key = SecKey::generate(opts.to_dictionary()).map_err(|_| Error::UnableToGenerateKey)?;
        Ok(Self(key))
    }
}

impl senv::Key for Key {
    fn to_public_key(&self) -> Result<Vec<u8>> {
        let public_key = self.0.public_key().ok_or(Error::UnableToExtractPublicKey)?;
        let sec1_bytes = public_key
            .external_representation()
            .ok_or(Error::UnableToExtractPublicKey)?
            .to_vec();

        let pk =
            PublicKey::from_sec1_bytes(&sec1_bytes).map_err(|_| Error::UnableToExtractPublicKey)?;

        Ok(pk.as_affine().to_bytes().to_vec())
    }
}

impl senv::KeySign for Key {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let der_sig = self
            .0
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, message)
            .map_err(|_| Error::UnableToCreateSignature)?;

        let sig = Signature::from_der(&der_sig).map_err(|_| Error::UnableToCreateSignature)?;

        Ok(sig.to_vec())
    }
}

#[cfg(test)]
mod ios_test {
    use super::*;
    use crate::senv::{Key as _, KeySign};

    #[test]
    fn create_key() {
        assert!(Key::new().is_ok());
    }

    #[test]
    fn get_public_bytes() {
        let key = Key::new().unwrap();

        let public_bytes = key.to_public_key().unwrap();

        assert_eq!(public_bytes.len(), 33);
    }

    #[test]
    fn sign_message() {
        let key = Key::new().unwrap();
        let msg = b"hello world!";
        let sig = key.sign(msg).unwrap();

        assert_eq!(sig.len(), 64);
    }
}
