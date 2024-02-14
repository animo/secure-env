use crate::{
    error::{SecureEnvError, SecureEnvResult},
    KeyOps, SecureEnvironmentOps,
};
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Key(SecKey);

impl KeyOps for Key {
    fn get_public_key(&self) -> SecureEnvResult<Vec<u8>> {
        todo!()
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
}
