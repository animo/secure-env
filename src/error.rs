#[derive(Debug)]
pub enum Error {
    UnableToGenerateKey,
    UnableToExtractPublicKey,
    UnableToCreateSignature,
}

pub type Result<T> = std::result::Result<T, Error>;
