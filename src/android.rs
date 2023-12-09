use crate::error::{Error, Result};
use jni::objects::{JObject, JValueGen};
use jni::JNIEnv;

lazy_static::lazy_static! {
    pub static ref JAVA_VM: jni::JavaVM =
        unsafe { jni::JavaVM::from_raw(ndk_context::android_context().vm().cast()) }.unwrap();
}

#[derive(Debug)]
pub struct SecureEnvironment(JNIEnv<'static>, JObject<'static>);

impl SecureEnvironment {
    pub fn new() -> Result<Self> {
        let mut env = JAVA_VM.attach_current_thread_as_daemon()?;
        let algorithm = env.new_string("EC")?;
        let provider = env.new_string("AndroidKeyStore")?;
        let args = [(&algorithm).into(), (&provider).into()];

        let key_pair_generator = env.call_static_method(
            "java/security/KeyPairGenerator",
            "getInstance",
            "(Ljava/lang/String;Ljava/lang/String;)Ljava/security/KeyPairGenerator;",
            &args,
        )?;

        let kpg_instance = key_pair_generator.l()?;

        Ok(Self(env, kpg_instance))
    }

    pub fn generate_key(&mut self) -> Result<Key> {
        let result =
            self.0
                .call_method(&self.1, "generateKeyPair", "()Ljava/security/KeyPair;", &[])?;
        Ok(Key(result))
    }
}

#[derive(Debug)]
pub struct Key<'a>(JValueGen<JObject<'a>>);
