use std::sync::{Arc, Mutex};

use crate::error::{Error, Result};
use jni::{
    objects::{JObject, JValue},
    AttachGuard, JNIEnv,
};

lazy_static::lazy_static! {
    pub static ref JAVA_VM: jni::JavaVM =
        unsafe { jni::JavaVM::from_raw(ndk_context::android_context().vm().cast()) }.unwrap();
}

enum JavaClass {
    KeyPairGeneratorGetInstance,
    KeyPairGeneratorGenerateKeyPair,
}

fn call_jni_static<'a>(
    env: &'a mut JNIEnv<'a>,
    token: JavaClass,
    args: &'a [JValue<'a, 'a>],
) -> Result<JObject<'a>> {
    let (c, f, s) = token.into();
    let result = env.call_static_method(c, f, s, args).unwrap();
    let result = result.l().unwrap();

    Ok(result)
}

fn call_jni<'a>(
    env: &'a mut JNIEnv<'a>,
    token: JavaClass,
    class: JObject<'a>,
    args: &'a [JValue<'a, 'a>],
) -> Result<JObject<'a>> {
    let (_, f, s) = token.into();
    let result = env.call_method(class, f, s, args).unwrap();
    let result = result.l().unwrap();

    Ok(result)
}

impl Into<(String, String, String)> for JavaClass {
    fn into(self) -> (String, String, String) {
        let items = match self {
            JavaClass::KeyPairGeneratorGetInstance => (
                "java/security/KeyPairGenerator",
                "getInstance",
                "(Ljava/lang/String;)Ljava/security/KeyPairGenerator;",
            ),
            JavaClass::KeyPairGeneratorGenerateKeyPair => (
                "java/security/KeyPairGenerator",
                "generateKeyPair",
                "()Ljava/security/KeyPair;",
            ),
        };

        (items.0.to_owned(), items.1.to_owned(), items.2.to_owned())
    }
}

#[derive(Debug)]
pub struct Key(Arc<Mutex<JNIEnv<'static>>>);

impl Key {
    pub fn new() -> Result<Self> {
        let env = JAVA_VM
            .attach_current_thread_as_daemon()
            .map_err(|_| Error::UnableToAttachJVMToThread)?;
        Ok(Self(Arc::new(Mutex::new(env))))
    }

    pub fn generate(&mut self) -> Result<()> {
        let algorithm = self
            .0
            .lock()
            .map_err(|_| Error::UnableToAcquireJNIEnvLock)?
            .new_string("EC")
            .map_err(|_| Error::UnableToCreateJavaValue)?;
        let algorithm = JValue::Object(&algorithm);

        let provider = self
            .0
            .lock()
            .map_err(|_| Error::UnableToAcquireJNIEnvLock)?
            .new_string("AndroidKeyStore")
            .map_err(|_| Error::UnableToCreateJavaValue)?;
        let provider = JValue::Object(&provider);

        // let args = [algorithm, provider];
        // let key_pair_generator = call_jni_static(
        //     &mut env.lock().unwrap(),
        //     JavaClass::KeyPairGeneratorGetInstance,
        //     &args,
        // )?;
        // let result = call_jni(
        //     &mut env.lock().unwrap(),
        //     JavaClass::KeyPairGeneratorGenerateKeyPair,
        //     key_pair_generator,
        //     &[],
        // )?;

        Ok(())
    }

    pub fn to_public_bytes(&self) -> Vec<u8> {
        vec![]
    }
}
