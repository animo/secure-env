pub trait CommonHsm {
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
    fn to_public_key(&self) -> Vec<u8>;
}
