use crate::{error::SecureEnvResult, key::KeyOps};

pub trait SecureEnvironmentOps<K: KeyOps> {
    fn generate_keypair(id: impl Into<String>, backed_by_biometrics: bool) -> SecureEnvResult<K>;

    fn get_keypair_by_id(id: impl Into<String>) -> SecureEnvResult<K>;
}
