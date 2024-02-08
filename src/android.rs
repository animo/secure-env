use crate::{error::SecureEnvResult, key::KeyOps, secure_environment::SecureEnvironmentOps};
use jni::objects::{JByteArray, JObject, JValue};

use crate::jni::*;

lazy_static::lazy_static! {
    pub static ref JAVA_VM: jni::JavaVM =
        unsafe { jni::JavaVM::from_raw(ndk_context::android_context().vm().cast()) }.unwrap();
}

#[derive(Debug)]
pub struct SecureEnvironment;

// TODO: create a simple method to call a method
impl SecureEnvironmentOps<Key> for SecureEnvironment {
    fn generate_keypair(id: impl Into<String>) -> SecureEnvResult<Key> {
        let mut env = JAVA_VM.attach_current_thread_as_daemon()?;

        let id = id.into();
        let id = env.new_string(id)?;

        let purpose_sign = env
            .get_static_field(
                KEY_PROPERTIES_CLS,
                KEY_PROPERTIES_PURPOSE_SIGN,
                KEY_PROPERTIES_PURPOSE_SIGN_SIG,
            )?
            .i()?;

        let builder = env.new_object(
            KEY_GEN_PARAMETER_SPEC_BUILDER_CLS,
            KEY_GEN_PARAMETER_SPEC_BUILDER_CTOR_SIG,
            &[(&id).into(), JValue::from(purpose_sign)],
        )?;

        let kp_cls = env.find_class(KEY_PROPERTIES_CLS)?;

        let digest_sha256 = env
            .get_static_field(
                kp_cls,
                KEY_PROPERTIES_DIGEST_SHA256,
                KEY_PROPERTIES_DIGEST_SHA256_SIG,
            )?
            .l()?;

        let class = env.find_class(STRING)?;
        let args = env.new_object_array(1, class, &digest_sha256)?;

        let builder = env
            .call_method(
                &builder,
                KEY_GEN_PARAMETER_SPEC_BUILDER_SET_DIGESTS,
                KEY_GEN_PARAMETER_SPEC_BUILDER_SET_DIGESTS_SIG,
                &[(&args).into()],
            )?
            .l()?;

        let builder = env
            .call_method(
                &builder,
                KEY_GEN_PARAMETER_SPEC_BUILDER_SET_KEY_SIZE,
                KEY_GEN_PARAMETER_SPEC_BUILDER_SET_KEY_SIZE_SIG,
                &[JValue::from(256)],
            )?
            .l()?;

        // TOGGLED OF FOR DEV
        // emulators do not have strongbox support
        // let builder = env
        //     .call_method(
        //         &builder,
        //         KEY_GEN_PARAMETER_SPEC_BUILDER_SET_IS_STRONG_BOX_BACKED,
        //         KEY_GEN_PARAMETER_SPEC_BUILDER_SET_IS_STRONG_BOX_BACKED_SIG,
        //         &[JValue::Bool(1)],
        //     )?
        //     .l()?;

        let builder = env
            .call_method(
                &builder,
                KEY_GEN_PARAMETER_SPEC_BUILDER_SET_USER_PRESENCE_REQUIRED,
                KEY_GEN_PARAMETER_SPEC_BUILDER_SET_USER_PRESENCE_REQUIRED_SIG,
                &[JValue::Bool(1)],
            )?
            .l()?;

        let params = env
            .call_method(
                &builder,
                KEY_GEN_PARAMETER_SPEC_BUILDER_BUILD,
                KEY_GEN_PARAMETER_SPEC_BUILDER_BUILD_SIG,
                &[],
            )?
            .l()?;

        let algorithm = env.new_string(EC_ALGORITHM)?;
        let provider = env.new_string(ANDROID_KEY_STORE_PROVIDER)?;
        let args = [(&algorithm).into(), (&provider).into()];

        let key_pair_generator = env.call_static_method(
            KEY_PAIR_GENERATOR_CLS,
            KEY_PAIR_GENERATOR_GET_INSTANCE,
            KEY_PAIR_GENERATOR_GET_INSTANCE_SIG,
            &args,
        )?;

        let kpg_instance = key_pair_generator.l()?;

        env.call_method(
            &kpg_instance,
            KEY_PAIR_GENERATOR_INITIALIZE,
            KEY_PAIR_GENERATOR_INITIALIZE_SIG,
            &[(&params).into()],
        )?;

        let result = env
            .call_method(
                &kpg_instance,
                KEY_PAIR_GENERATOR_GENERATE_KEY_PAIR,
                KEY_PAIR_GENERATOR_GENERATE_KEY_PAIR_SIG,
                &[],
            )?
            .l()?;

        Ok(Key(result))
    }

    fn get_keypair_by_id(id: impl Into<String>) -> SecureEnvResult<Key> {
        let mut env = JAVA_VM.attach_current_thread_as_daemon()?;
        let provider = env.new_string(ANDROID_KEY_STORE_PROVIDER)?;
        let id = id.into();
        let id = env.new_string(id)?;

        let keystore_instance = env
            .call_static_method(
                KEY_STORE_CLS,
                KEY_STORE_GET_INSTANCE,
                KEY_STORE_GET_INSTANCE_SIG,
                &[(&provider).into()],
            )?
            .l()?;

        env.call_method(
            &keystore_instance,
            KEY_STORE_LOAD,
            KEY_STORE_LOAD_SIG,
            &[(&JObject::null()).into()],
        )?;

        let entry = env
            .call_method(
                &keystore_instance,
                KEY_STORE_GET_ENTRY,
                KEY_STORE_GET_ENTRY_SIG,
                &[(&id).into(), (&JObject::null()).into()],
            )?
            .l()?;

        let private_key = env
            .call_method(
                &entry,
                KEY_STORE_ENTRY_GET_PRIVATE_KEY,
                KEY_STORE_ENTRY_GET_PRIVATE_KEY_SIG,
                &[],
            )?
            .l()?;

        let certificate = env
            .call_method(
                &entry,
                KEY_STORE_ENTRY_GET_CERTIFICATE,
                KEY_STORE_ENTRY_GET_CERTIFICATE_SIG,
                &[],
            )?
            .l()?;

        let public_key = env
            .call_method(
                &certificate,
                CERTIFICATE_GET_PUBLIC_KEY,
                CERTIFICATE_GET_PUBLIC_KEY_SIG,
                &[],
            )?
            .l()?;

        let key_pair_class = env.find_class(KEY_PAIR_CLS)?;

        let key_pair = env.new_object(
            &key_pair_class,
            KEY_PAIR_CTOR_SIG,
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
        let public_key = env
            .call_method(&self.0, KEY_PAIR_GET_PUBLIC, KEY_PAIR_GET_PUBLIC_SIG, &[])?
            .l()?;

        let public_key = env
            .call_method(
                &public_key,
                PUBLIC_KEY_GET_ENCODED,
                PUBLIC_KEY_GET_ENCODED_SIG,
                &[],
            )?
            .l()?;

        let public_key: JByteArray = public_key.try_into().unwrap();

        let public_key = env.convert_byte_array(&public_key)?;

        Ok(public_key)
    }

    fn sign(&self, msg: &[u8]) -> SecureEnvResult<Vec<u8>> {
        let mut env = JAVA_VM.attach_current_thread_as_daemon()?;
        let algorithm = env.new_string(SHA256_WITH_ECDSA_ALGO)?;

        let signature_instance = env
            .call_static_method(
                SIGNATURE_CLS,
                SIGNATURE_GET_INSTANCE,
                SIGNATURE_GET_INSTANCE_SIG,
                &[(&algorithm).into()],
            )?
            .l()?;

        let private_key = env
            .call_method(
                &self.0,
                KEY_PAIR_GET_PRIVATE,
                KEY_PAIR_GET_PRIVATE_SIG,
                &[],
            )?
            .l()?;

        env.call_method(
            &signature_instance,
            SIGNATURE_INIT_SIGN,
            SIGNATURE_INIT_SIGN_SIG,
            &[(&private_key).into()],
        )?;

        let b_arr = env.byte_array_from_slice(msg)?;

        env.call_method(
            &signature_instance,
            SIGNATURE_UPDATE,
            SIGNATURE_UPDATE_SIG,
            &[(&b_arr).into()],
        )?;

        let signature = env
            .call_method(&signature_instance, SIGNATURE_SIGN, SIGNATURE_SIGN_SIG, &[])?
            .l()?;

        let signature: JByteArray = signature.try_into().unwrap();

        let signature = env.convert_byte_array(&signature)?;

        Ok(signature)
    }
}
