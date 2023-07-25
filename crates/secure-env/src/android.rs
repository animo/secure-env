use jni::{
    objects::{JClass, JString, JValue},
    signature::ReturnType,
    sys::{self, jint},
    AttachGuard, InitArgsBuilder, JNIVersion, JavaVM,
};

use crate::common_hsm::CommonHsm;

#[derive(Debug)]
pub struct Android;

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
        let mut env = vm.attach_current_thread().unwrap();
        let b = env.new_string("EC").unwrap();
        let p = JValue::Object(&b);
        let cls = env.find_class("java/security/KeyPairGenerator").unwrap();
        let res = env
            .call_static_method(
                cls,
                "getInstance",
                "(Ljava/lang/String;)Ljava/security/KeyPairGenerator;",
                &[p],
            )
            .unwrap();
        let res = res.l().unwrap();

        let res = env
            .call_method(
                &res,
                "generateKeyPair",
                "()Ljava/security/KeyPair;",
                &[]
            )
            .unwrap();
        let res = res.l().unwrap();

        let res = env
            .call_method(
                &res,
                "getPublic",
                "()Ljava/security/PublicKey;",
                &[]
            )
            .unwrap();
        let res = res.l().unwrap();

        let res = env
            .call_method(
                &res,
                "getAlgorithm",
                "()Ljava/lang/String;",
                &[]
            )
            .unwrap();
        let res = JString::from(res.l().unwrap());
        let res = env.get_string(&res).unwrap();
        let res = res.to_str().unwrap();

        println!("{res:?}");

        Self
    }
}

// println!("key_pair_generator: {key_pair_generator:?}");
//let method = env
//    .get_static_method_id(
//        "java/security/KeyPairGenerator",
//        "getInstance",
//        "(Ljava/lang/String;)Ljava/security/KeyPairGenerator",
//    )
//    .unwrap();
// println!("method: {method:?}");
