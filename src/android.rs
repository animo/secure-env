use crate::{error::SecureEnvResult, key::KeyOps, secure_environment::SecureEnvironmentOps};
use jni::objects::{JByteArray, JObject, JValue};

lazy_static::lazy_static! {
    pub static ref JAVA_VM: jni::JavaVM =
        unsafe { jni::JavaVM::from_raw(ndk_context::android_context().vm().cast()) }.unwrap();
}

#[derive(Debug)]
pub struct SecureEnvironment;

impl SecureEnvironmentOps<Key> for SecureEnvironment {
    fn generate_keypair(id: impl Into<String>) -> SecureEnvResult<Key> {
        let mut env = JAVA_VM.attach_current_thread_as_daemon()?;

        let id = id.into();
        let id = env.new_string(id)?;

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
            &[(&id).into(), JValue::from(purpose_sign)],
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

        // TOGGLED OF FOR DEV
        // emulators do not have strongbox support
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

        env.call_method(
            &kpg_instance,
            "initialize",
            "(Ljava/security/spec/AlgorithmParameterSpec;)V",
            &[(&params).into()],
        )?;

        let result = env
            .call_method(
                &kpg_instance,
                "generateKeyPair",
                "()Ljava/security/KeyPair;",
                &[],
            )?
            .l()?;

        Ok(Key(result))
    }

    fn get_keypair_by_id(id: impl Into<String>) -> SecureEnvResult<Key> {
        let mut env = JAVA_VM.attach_current_thread_as_daemon()?;
        let provider = env.new_string("AndroidKeyStore")?;
        let id = id.into();
        let id = env.new_string(id)?;

        let keystore_instance = env
            .call_static_method(
                "java/security/KeyStore",
                "getInstance",
                "(Ljava/lang/String;)Ljava/security/KeyStore;",
                &[(&provider).into()],
            )?
            .l()?;

        env.call_method(
            &keystore_instance,
            "load",
            "(Ljava/security/KeyStore$LoadStoreParameter;)V",
            &[(&JObject::null()).into()],
        )?;

        let entry = env
            .call_method(
                &keystore_instance,
                "getEntry",
                "(Ljava/lang/String;Ljava/security/KeyStore$ProtectionParameter;)Ljava/security/KeyStore$Entry;",
                &[(&id).into(), (&JObject::null()).into()]
            )?
            .l()?;

        let private_key = env
            .call_method(&entry, "getPrivateKey", "()Ljava/security/PrivateKey;", &[])?
            .l()?;

        let certificate = env
            .call_method(
                &entry,
                "getCertificate",
                "()Ljava/security/cert/Certificate;",
                &[],
            )?
            .l()?;

        let public_key = env
            .call_method(
                &certificate,
                "getPublicKey",
                "()Ljava/security/PublicKey;",
                &[],
            )?
            .l()?;

        let key_pair_class = env.find_class("java/security/KeyPair")?;

        let key_pair = env.new_object(
            &key_pair_class,
            "(Ljava/security/PublicKey;Ljava/security/PrivateKey;)V",
            &[(&public_key).into(), (&private_key).into()],
        )?;

        Ok(Key(key_pair))
    }
}

#[derive(Debug)]
pub struct Key(JObject<'static>);

impl KeyOps for Key {
    fn get_public_key(&self) -> SecureEnvResult<Vec<u8>> {
        let mut env = JAVA_VM.attach_current_thread_as_daemon()?;
        let pk = env
            .call_method(&self.0, "getPublic", "()Ljava/security/PublicKey;", &[])?
            .l()?;

        let pk = env.call_method(&pk, "getEncoded", "()[B", &[])?.l()?;

        let pk: JByteArray = pk.try_into().unwrap();

        let pk = env.convert_byte_array(&pk)?;

        Ok(pk)
    }

    fn sign(&self, msg: &[u8]) -> SecureEnvResult<Vec<u8>> {
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
