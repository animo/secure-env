use crate::error::Result;

pub trait Key {
    fn to_public_key(&self) -> Result<Vec<u8>>;
}

pub trait KeySign {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;
}
