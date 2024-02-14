use crate::{
    error::{SecureEnvError, SecureEnvResult},
    KeyOps, SecureEnvironmentOps,
};
use p256::elliptic_curve::group::GroupEncoding;
use security_framework::key::{GenerateKeyOptions, KeyType, SecKey, Token};

/// Unit struct that can be used to create and get keypairs by id
///
/// # Examples
///
/// ```
/// use secure_env::{SecureEnvironment, SecureEnvironmentOps};
///
/// let _key = SecureEnvironment::generate_keypair("my-unique-id").unwrap();
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Copy)]
pub struct SecureEnvironment;

impl SecureEnvironmentOps<Key> for SecureEnvironment {
    fn generate_keypair(id: impl Into<String>) -> SecureEnvResult<Key> {
        // Create a dictionary with the following options:
        let mut opts = GenerateKeyOptions::default();

        // Set the key type to `ec` (Elliptic Curve)
        let opts = opts.set_key_type(KeyType::ec());

        // Set the a token of `SecureEnclave`.
        // Meaning Apple will store the key in a secure element
        let opts = opts.set_token(Token::SecureEnclave);

        // Give the key a label so we can retrieve it later
        // with the `SecureEnvironment::get_keypair_by_id` method
        let opts = opts.set_label(id);
        let dict = opts.to_dictionary();

        // Generate a key using the dictionary
        // This also passes along any information the OS provides when an error occurs
        let key = SecKey::generate(dict)
            .map_err(|e| SecureEnvError::UnableToGenerateKey(Some(e.to_string())))?;

        Ok(Key(key))
    }

    fn get_keypair_by_id(id: impl Into<String>) -> SecureEnvResult<Key> {
        let id = id.into();
        todo!()
    }
}

/// Key structure which allows for signing and retrieval of the public key
///
/// # Examples
///
/// ```
/// use secure_env::{SecureEnvironment, SecureEnvironmentOps, Key, KeyOps};
///
/// let key = SecureEnvironment::generate_keypair("documentation-public-key-token").unwrap();
/// let public_key_bytes = key.get_public_key().unwrap();
/// ```
///
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Key(SecKey);

impl KeyOps for Key {
    fn get_public_key(&self) -> SecureEnvResult<Vec<u8>> {
        // Retrieve the internal representation of the public key of the `SecKey`
        let public_key = self
            .0
            .public_key()
            .ok_or(SecureEnvError::UnableToGetPublicKey(Some(
                "No public key reference found on the internal `SecKey`".to_owned(),
            )))?;

        // Convert the public key reference to the `sec1` format in bytes
        let sec1_bytes = public_key
            .external_representation()
            .ok_or(SecureEnvError::UnableToGetPublicKey(Some(
                "Could not create an external representation for the public key on the `SecKey`"
                    .to_owned(),
            )))?
            .to_vec();

        // Instantiate a P256 public key from the `sec1` bytes
        let public_key = p256::PublicKey::from_sec1_bytes(&sec1_bytes)
            .map_err(|e| SecureEnvError::UnableToGetPublicKey(Some(e.to_string())))?;

        // Get the affine point of the public key and convert this into a byte representation
        let public_key = public_key.as_affine().to_bytes().to_vec();

        Ok(public_key)
    }

    fn sign(&self, msg: &[u8]) -> SecureEnvResult<Vec<u8>> {
        todo!()
    }
}

#[cfg(all(test, any(target_os = "macos", target_os = "ios")))]
mod test {
    use std::ptr::addr_of;

    use super::*;

    #[test]
    fn generate_key_pair() {
        let key = SecureEnvironment::generate_keypair("my-test-key").unwrap();
        assert!(!addr_of!(key).is_null());
    }

    #[test]
    fn get_public_key() {
        let key = SecureEnvironment::generate_keypair("my-test-public-key").unwrap();
        let public_key_bytes = key.get_public_key().unwrap();

        assert_eq!(public_key_bytes.len(), 33);
    }
}
