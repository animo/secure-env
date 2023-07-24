use jni::{
    objects::JValue,
    sys::{self, jint},
    InitArgsBuilder, JNIVersion, JavaVM,
};

use crate::common_hsm::CommonHsm;

#[derive(Debug)]
pub struct Android(JavaVM);

impl CommonHsm for Android {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        todo!()
    }

    fn to_public_key(&self) -> Vec<u8> {
        todo!()
    }
}

impl Android {
    pub fn new(vm: JavaVM) -> Self {
        Self(vm)
    }
}
