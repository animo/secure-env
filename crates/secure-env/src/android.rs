use jni::objects::JValue;

lazy_static::lazy_static! {
    pub static ref JAVA_VM: jni::JavaVM =
        unsafe { jni::JavaVM::from_raw(ndk_context::android_context().vm().cast()) }.unwrap();
}

enum JavaClass {
    KeyPairGeneratorGetInstance,
    KeyPairGeneratorGenerateKeyPair,
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
pub struct Key;

impl Key {
    pub fn generate() -> Self {
        let mut env = JAVA_VM.attach_current_thread().unwrap();
        let b = env.new_string("EC").unwrap();
        let p = JValue::Object(&b);

        // TODO: macro potential
        let (c, f, s) = JavaClass::KeyPairGeneratorGetInstance.into();
        let result = env.call_static_method(c, f, s, &[p]).unwrap();
        let result = result.l().unwrap();

        let (_, f, s) = JavaClass::KeyPairGeneratorGenerateKeyPair.into();
        let result = env.call_method(result, f, s, &[]).unwrap();
        let result = result.l().unwrap();
        println!("Created key!");

        Self
    }

    pub fn to_public_bytes(&self) -> Vec<u8> {
        vec![]
    }
}
