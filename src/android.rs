use crate::error::Result;
use jni::objects::{JByteArray, JObject, JValue};
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

        // ====

        let purpose_sign = env
            .get_static_field(
                "android/security/keystore/KeyProperties",
                "PURPOSE_SIGN",
                "I",
            )?
            .i()?;

        let builder = env.new_object(
            "android/security/keystore/KeyGenParameterSpec$Builder",
            "(Ljava/lang/String;I)V",
            &[
                (&env.new_string("hi").unwrap()).into(),
                JValue::from(purpose_sign),
            ],
        )?;

        let kp_cls = env.find_class("android/security/keystore/KeyProperties")?;

        let digest_sha256 = env
            .get_static_field(kp_cls, "DIGEST_SHA256", "Ljava/lang/String;")?
            .l()?;

        let class = env.find_class("java/lang/String")?;
        let args = env.new_object_array(1, class, &digest_sha256)?;

        let builder = env
            .call_method(
                &builder,
                "setDigests",
                "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                &[(&args).into()],
            )?
            .l()?;

        let builder = env
            .call_method(
                &builder,
                "setKeySize",
                "(I)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                &[JValue::from(256)],
            )?
            .l()?;

        // let builder = env
        //     .call_method(
        //         &builder,
        //         "setIsStrongBoxBacked",
        //         "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        //         &[JValue::Bool(1)],
        //     )?
        //     .l()?;

        let builder = env
            .call_method(
                &builder,
                "setUserPresenceRequired",
                "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                &[JValue::Bool(1)],
            )?
            .l()?;

        let params = env
            .call_method(
                &builder,
                "build",
                "()Landroid/security/keystore/KeyGenParameterSpec;",
                &[],
            )?
            .l()?;

        // ====

        env.call_method(
            &kpg_instance,
            "initialize",
            "(Ljava/security/spec/AlgorithmParameterSpec;)V",
            &[(&params).into()],
        )?;

        Ok(Self(env, kpg_instance))
    }

    pub fn generate_key(&mut self) -> Result<Key> {
        let result = self
            .0
            .call_method(&self.1, "generateKeyPair", "()Ljava/security/KeyPair;", &[])?
            .l()?;
        Ok(Key(result))
    }
}

#[derive(Debug)]
pub struct Key<'a>(JObject<'a>);

impl<'a> Key<'a> {
    pub fn get_public_key(&self) -> Result<Vec<u8>> {
        let mut env = JAVA_VM.attach_current_thread_as_daemon()?;
        let pk = env
            .call_method(&self.0, "getPublic", "()Ljava/security/PublicKey;", &[])?
            .l()?;

        let pk = env
            .call_method(&pk, "getEncoded", "()[B", &[])?
            .l()?;

        let pk: JByteArray = pk.try_into().unwrap();

        let pk = env.convert_byte_array(&pk)?;

        Ok(pk)
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let mut env = JAVA_VM.attach_current_thread_as_daemon()?;
        let algorithm = env.new_string("SHA256withECDSA")?;

        let signature_instance = env
            .call_static_method(
                "java/security/Signature",
                "getInstance",
                "(Ljava/lang/String;)Ljava/security/Signature;",
                &[(&algorithm).into()],
            )?
            .l()?;

        let pk = env
            .call_method(&self.0, "getPrivate", "()Ljava/security/PrivateKey;", &[])?
            .l()?;

        env.call_method(
            &signature_instance,
            "initSign",
            "(Ljava/security/PrivateKey;)V",
            &[(&pk).into()],
        )?;

        let b_arr = env.byte_array_from_slice(msg)?;

        env.call_method(&signature_instance, "update", "([B)V", &[(&b_arr).into()])?;

        let signature = env
            .call_method(&signature_instance, "sign", "()[B", &[])?
            .l()?;

        let signature: JByteArray = signature.try_into().unwrap();

        let signature = env.convert_byte_array(&signature)?;

        Ok(signature)
    }
}
