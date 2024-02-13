#[derive(Debug, thiserror::Error)]
pub enum SecureEnvError {
    #[error("JNI Error")]
    JniError(#[from] jni::errors::Error),
    #[error("Unable to generate key")]
    UnableToGenerateKey,
    #[error("Unable to extract public key")]
    UnableToExtractPublicKey,
    #[error("Unable to create signature")]
    UnableToCreateSignature,
    #[error("Unable to attach JVM to thread")]
    UnableToAttachJVMToThread,
    #[error("Unable to create java value")]
    UnableToCreateJavaValue,
}

pub type SecureEnvResult<T> = std::result::Result<T, SecureEnvError>;
