use crate::{
    error::{SecureEnvError, SecureEnvResult},
    KeyOps, SecureEnvironmentOps,
};
use p256::{ecdsa::Signature, elliptic_curve::group::GroupEncoding};
use security_framework::{
    access_control::{ProtectionMode, SecAccessControl},
    item::{ItemClass, ItemSearchOptions, KeyClass, Location, SearchResult},
    key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token},
    passwords_options::AccessControlOptions,
};

/// Unit struct that can be used to create and get keypairs by id
///
/// # Examples
///
/// ## Generate a keypair
///
/// ```
/// use secure_env::{SecureEnvironment, SecureEnvironmentOps};
///
/// let key = SecureEnvironment::generate_keypair("my-unique-id").unwrap();
/// ```
///
/// ## Get a keypair from the keychain
///
/// ```
/// use secure_env::{SecureEnvironment, SecureEnvironmentOps};
///
/// {
///     SecureEnvironment::generate_keypair("my-unique-id").unwrap();
/// }
///
/// let key = SecureEnvironment::get_keypair_by_id("my-unique-id").unwrap();
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Copy)]
pub struct SecureEnvironment;

impl SecureEnvironmentOps<Key> for SecureEnvironment {
    fn generate_keypair(id: impl Into<String>, backed_by_biometrics: bool) -> SecureEnvResult<Key> {
        // Create a dictionary with the following options:
        let mut opts = GenerateKeyOptions::default();

        // Set the key type to `ec` (Elliptic Curve)
        let opts = opts.set_key_type(KeyType::ec());

        // Set the a token of `SecureEnclave`.
        // Meaning Apple will store the key in a secure element
        let opts = opts.set_token(Token::SecureEnclave);

        let opts = if backed_by_biometrics {
            // Set the access control so that biometrics via LocalAuthentication.framework is required
            let access_control = SecAccessControl::create_with_protection(
                Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
                AccessControlOptions::BIOMETRY_CURRENT_SET.bits(),
            )
            .map_err(|_| {
                SecureEnvError::UnableToGenerateKey(
                    "Unable to create access control flags".to_owned(),
                )
            })?;

            opts.set_access_control(access_control)
        } else {
            opts
        };

        // Store the key in the keychain
        let opts = opts.set_location(Location::DataProtectionKeychain);

        // Give the key a label so we can retrieve it later
        // with the `SecureEnvironment::get_keypair_by_id` method
        let opts = opts.set_label(id);

        let dict = opts.to_dictionary();

        // Generate a key using the dictionary
        // This also passes along any information the OS provides when an error occurs
        let key = SecKey::generate(dict)
            .map_err(|e| SecureEnvError::UnableToGenerateKey(e.to_string()))?;

        Ok(Key(key))
    }

    fn get_keypair_by_id(id: impl Into<String>) -> SecureEnvResult<Key> {
        let id = id.into();

        let search_result = ItemSearchOptions::new()
            // Search by the provided label
            .label(&id)
            // Load the reference, not the actual data
            .load_refs(true)
            // Looking for a `Key` instance
            .class(ItemClass::key())
            // We want access to the private key
            .key_class(KeyClass::private())
            // Limit to 1 output key
            .limit(1)
            // Search the keychain
            .search()
            .map_err(|_| {
                SecureEnvError::UnableToGetKeyPairById(format!(
                    "Key reference with id: '{id}' not found."
                ))
            })?;

        let result = search_result
            .first()
            .ok_or(SecureEnvError::UnableToGetKeyPairById(format!(
                "Key reference with id: '{id}' not found."
            )))?;

        match result {
            SearchResult::Ref(r) => match r {
                security_framework::item::Reference::Key(k) => Ok(Key(k.to_owned())),
                _ => Err(SecureEnvError::UnableToGetKeyPairById(
                    "Found Reference, but not of key instance".to_owned(),
                )),
            },
            _ => Err(SecureEnvError::UnableToGetKeyPairById(
                "Did not find search reference".to_owned(),
            )),
        }
    }
}

/// Key structure which allows for signing and retrieval of the public key
///
/// # Examples
///
/// ## Get the public Key
///
/// ```
/// use secure_env::{SecureEnvironment, SecureEnvironmentOps, Key, KeyOps};
///
/// let key = SecureEnvironment::generate_keypair("documentation-public-key-token").unwrap();
/// let public_key_bytes = key.get_public_key().unwrap();
///
/// assert_eq!(public_key_bytes.len(), 33);
/// ```
///
/// ## Sign a message
///
/// ```
/// use secure_env::{SecureEnvironment, SecureEnvironmentOps, Key, KeyOps};
///
/// let key = SecureEnvironment::generate_keypair("documentation-sign-key-token").unwrap();
/// let signature = key.sign(b"Hello World").unwrap();
///
/// assert_eq!(signature.len(), 64);
/// ```
///
/// ## Verify the signed message with `askar_crypto`
///
/// ```
/// use secure_env::{SecureEnvironment, SecureEnvironmentOps, Key, KeyOps};
/// use askar_crypto::{alg::p256::P256KeyPair, repr::KeyPublicBytes};
///
/// let msg = b"Hello World!";
/// let key = SecureEnvironment::generate_keypair("my-test-sign-key").unwrap();
///
/// let public_key = key.get_public_key().unwrap();
/// let signature = key.sign(b"Hello World!").unwrap();
///
/// let verify_key = P256KeyPair::from_public_bytes(&public_key).unwrap();
/// let is_signature_valid = verify_key.verify_signature(msg, &signature);
///
/// assert!(is_signature_valid);
/// ```
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Key(SecKey);

impl KeyOps for Key {
    fn get_public_key(&self) -> SecureEnvResult<Vec<u8>> {
        // Retrieve the internal representation of the public key of the `SecKey`
        let public_key = self
            .0
            .public_key()
            .ok_or(SecureEnvError::UnableToGetPublicKey(
                "No public key reference found on the internal `SecKey`".to_owned(),
            ))?;

        // Convert the public key reference to the `sec1` format in bytes
        let sec1_bytes = public_key
            .external_representation()
            .ok_or(SecureEnvError::UnableToGetPublicKey(
                "Could not create an external representation for the public key on the `SecKey`"
                    .to_owned(),
            ))?
            .to_vec();

        // Instantiate a P256 public key from the `sec1` bytes
        let public_key = p256::PublicKey::from_sec1_bytes(&sec1_bytes)
            .map_err(|e| SecureEnvError::UnableToGetPublicKey(e.to_string()))?;

        // Get the affine point of the public key and convert this into a byte representation
        let public_key = public_key.as_affine().to_bytes().to_vec();

        Ok(public_key)
    }

    /**
     *
     * Signing is an operation that requires authentication. Make sure to manually authenticate
     * before calling this operation
     *
     */
    fn sign(&self, msg: &[u8]) -> SecureEnvResult<Vec<u8>> {
        // Sign the message with the `der` format
        let der_sig = self
            .0
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, msg)
            .map_err(|e| SecureEnvError::UnableToCreateSignature(e.to_string()))?;

        // Convert the `ASN.1 der` format signature
        let signature = Signature::from_der(&der_sig)
            .map_err(|e| SecureEnvError::UnableToCreateSignature(e.to_string()))?;

        // Convert the signature to a byte representation
        let signature = signature.to_vec();

        Ok(signature)
    }
}
