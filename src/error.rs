#[derive(Debug)]
pub enum Error {
    UnableToGenerateKey,
    UnableToExtractPublicKey,
    UnableToCreateSignature,
    UnableToAttachJVMToThread,
    UnableToCreateJavaValue,
    UnableToAcquireJNIEnvLock,
}

pub type Result<T> = std::result::Result<T, Error>;
