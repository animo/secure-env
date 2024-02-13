use crate::error::SecureEnvResult;

pub trait KeyOps {
    fn get_public_key(&self) -> SecureEnvResult<Vec<u8>>;

    fn sign(&self, msg: &[u8]) -> SecureEnvResult<Vec<u8>>;
}
