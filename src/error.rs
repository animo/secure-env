#[derive(Debug, thiserror::Error)]
pub enum SecureEnvError {
    #[error("Unable to generate key. Additional Info: {0:#?}")]
    UnableToGenerateKey(Option<String>),

    #[error("Unable to get keypair by id. Additional Info: {0:#?}")]
    UnableToGetKeyPairById(Option<String>),

    #[error("Unable to create signature. Additional info: {0:#?}")]
    UnableToCreateSignature(Option<String>),

    #[error("Unable to get public key. Additional info: {0:#?}")]
    UnableToGetPublicKey(Option<String>),

    // #[cfg(target_os = "android")]
    #[error("Unable to attach JVM to thread. Additional info: {0}")]
    UnableToAttachJVMToThread(jni::errors::Error),

    // #[cfg(target_os = "android")]
    #[error("Unable to create java value. Additional info: {0}")]
    UnableToCreateJavaValue(jni::errors::Error),

    // TODO: check if we can also use this error on iOS.
    // Otherwise add a cfg target to android only
    #[error("Device does not support hardware backed keys. Additional info: {0:#?}")]
    HardwareBackedKeysAreNotSupported(Option<String>),
}

pub type SecureEnvResult<T> = std::result::Result<T, SecureEnvError>;
