use crate::{
    error::{SecureEnvError, SecureEnvResult},
    jni_tokens::*,
    key::KeyOps,
    secure_environment::SecureEnvironmentOps,
};
use jni::objects::{JByteArray, JObject, JValue};

lazy_static::lazy_static! {
    pub static ref JAVA_VM: jni::JavaVM =
        unsafe { jni::JavaVM::from_raw(ndk_context::android_context().vm().cast()) }.unwrap();
}

macro_rules! jni_call_method {
    ($env:expr, $cls:expr, $method:ident, $args:expr, $ret_typ:ident, $err:ident) => {
        $env.call_method($cls, $method, concat_idents!($method, _SIG), $args)
            .map_err(|e| $crate::error::SecureEnvError::$err(Some(e.to_string())))?
            .$ret_typ()
            .map_err(|e| $crate::error::SecureEnvError::$err(Some(e.to_string())))
    };

    ($env:expr, $cls:expr, $method:ident, $ret_typ:ident, $err:ident) => {
        jni_call_method!($env, $cls, $method, &[], $ret_typ, $err)
    };
}

macro_rules! jni_call_static_method {
    ($env:expr, $cls:ident, $method:ident, $args:expr, $ret_typ:ident, $err:ident) => {
        $env.call_static_method(
            concat_idents!($cls, _CLS),
            $method,
            concat_idents!($method, _SIG),
            $args,
        )
        .and_then(|v| v.$ret_typ())
        .map_err(|e| $crate::error::SecureEnvError::$err(Some(e.to_string())))
    };

    ($env:expr, $cls:expr, $method:ident, $ret_typ:ident, $err:ident) => {
        jni_call_static_method!($env, $cls, $method, &[], $ret_typ, $err)
    };
}

macro_rules! jni_get_static_field {
    ($env:expr, $cls:expr, $method:ident, $ret_typ:ident, $err:ident) => {
        $env.get_static_field($cls, $method, concat_idents!($method, _SIG))
            .and_then(|v| v.$ret_typ())
            .map_err(|e| $crate::error::SecureEnvError::$err(Some(e.to_string())))
    };
}

macro_rules! jni_new_object {
    ($env:expr, $cls:ident, $args:expr, $err:ident) => {
        $env.new_object(
            concat_idents!($cls, _CLS),
            concat_idents!($cls, _CTOR_SIG),
            $args,
        )
        .map_err(|e| $crate::error::SecureEnvError::$err(Some(e.to_string())))
    };
}

macro_rules! jni_find_class {
    ($env:expr, $cls:ident, $err:ident) => {
        $env.find_class(concat_idents!($cls, _CLS))
            .map_err(|e| $crate::error::SecureEnvError::$err(Some(e.to_string())))
    };
}

#[derive(Debug)]
pub struct SecureEnvironment;

impl SecureEnvironmentOps<Key> for SecureEnvironment {
    fn generate_keypair(id: impl Into<String>) -> SecureEnvResult<Key> {
        let mut env = JAVA_VM
            .attach_current_thread_as_daemon()
            .map_err(SecureEnvError::UnableToAttachJVMToThread)?;

        let id = id.into();

        let id = env
            .new_string(id)
            .map_err(SecureEnvError::UnableToCreateJavaValue)?;

        let purpose_sign = jni_get_static_field!(
            env,
            KEY_PROPERTIES_CLS,
            KEY_PROPERTIES_PURPOSE_SIGN,
            i,
            UnableToGenerateKey
        )?;

        let builder = jni_new_object!(
            env,
            KEY_GEN_PARAMETER_SPEC_BUILDER,
            &[(&id).into(), JValue::from(purpose_sign)],
            UnableToGenerateKey
        )?;

        let kp_cls = jni_find_class!(env, KEY_PROPERTIES, UnableToGenerateKey)?;

        let digest_sha256 = jni_get_static_field!(
            env,
            kp_cls,
            KEY_PROPERTIES_DIGEST_SHA256,
            l,
            UnableToGenerateKey
        )?;

        let string_cls = jni_find_class!(env, STRING, UnableToGenerateKey)?;

        let args = env
            .new_object_array(1, string_cls, &digest_sha256)
            .map_err(SecureEnvError::UnableToCreateJavaValue)?;

        let builder = jni_call_method!(
            env,
            builder,
            KEY_GEN_PARAMETER_SPEC_BUILDER_SET_DIGESTS,
            &[(&args).into()],
            l,
            UnableToGenerateKey
        )?;

        let builder = jni_call_method!(
            env,
            builder,
            KEY_GEN_PARAMETER_SPEC_BUILDER_SET_KEY_SIZE,
            &[JValue::from(256)],
            l,
            UnableToGenerateKey
        )?;

        // TOGGLED FOR DEV
        // emulators do not have strongbox support
        // let builder = jni_call_method!(
        //     env,
        //     builder,
        //     KEY_GEN_PARAMETER_SPEC_BUILDER_SET_IS_STRONG_BOX_BACKED,
        //     &[JValue::Bool(1)],
        //     l,
        //     UnableToGenerateKey
        // )?;

        let builder = jni_call_method!(
            env,
            &builder,
            KEY_GEN_PARAMETER_SPEC_BUILDER_SET_USER_PRESENCE_REQUIRED,
            &[JValue::Bool(1)],
            l,
            UnableToGenerateKey
        )?;

        let algorithm = env
            .new_string(EC_ALGORITHM)
            .map_err(SecureEnvError::UnableToCreateJavaValue)?;

        let provider = env
            .new_string(ANDROID_KEY_STORE_PROVIDER)
            .map_err(SecureEnvError::UnableToCreateJavaValue)?;

        let key_pair_generator = jni_call_static_method!(
            env,
            KEY_PAIR_GENERATOR,
            KEY_PAIR_GENERATOR_GET_INSTANCE,
            &[(&algorithm).into(), (&provider).into()],
            l,
            UnableToGenerateKey
        )?;

        let params = jni_call_method!(
            env,
            &builder,
            KEY_GEN_PARAMETER_SPEC_BUILDER_BUILD,
            l,
            UnableToGenerateKey
        )?;

        jni_call_method!(
            env,
            &key_pair_generator,
            KEY_PAIR_GENERATOR_INITIALIZE,
            &[(&params).into()],
            v,
            UnableToGenerateKey
        )?;

        let key = jni_call_method!(
            env,
            &key_pair_generator,
            KEY_PAIR_GENERATOR_GENERATE_KEY_PAIR,
            l,
            UnableToGenerateKey
        )?;

        Ok(Key(key))
    }

    fn get_keypair_by_id(id: impl Into<String>) -> SecureEnvResult<Key> {
        let mut env = JAVA_VM
            .attach_current_thread_as_daemon()
            .map_err(SecureEnvError::UnableToAttachJVMToThread)?;

        let provider = env
            .new_string(ANDROID_KEY_STORE_PROVIDER)
            .map_err(SecureEnvError::UnableToCreateJavaValue)?;

        let id = id.into();
        let id = env
            .new_string(id)
            .map_err(SecureEnvError::UnableToCreateJavaValue)?;

        let key_store = jni_call_static_method!(
            env,
            KEY_STORE,
            KEY_STORE_GET_INSTANCE,
            &[(&provider).into()],
            l,
            UnableToGetKeyPairById
        )?;

        jni_call_method!(
            env,
            &key_store,
            KEY_STORE_LOAD,
            &[(&JObject::null()).into()],
            v,
            UnableToGetKeyPairById
        )?;

        let entry = jni_call_method!(
            env,
            &key_store,
            KEY_STORE_GET_ENTRY,
            &[(&id).into(), (&JObject::null()).into()],
            l,
            UnableToGetKeyPairById
        )?;

        let private_key = jni_call_method!(
            env,
            &entry,
            KEY_STORE_ENTRY_GET_PRIVATE_KEY,
            l,
            UnableToGetKeyPairById
        )?;

        let certificate = jni_call_method!(
            env,
            &entry,
            KEY_STORE_ENTRY_GET_CERTIFICATE,
            l,
            UnableToGetKeyPairById
        )?;

        let public_key = jni_call_method!(
            env,
            &certificate,
            CERTIFICATE_GET_PUBLIC_KEY,
            l,
            UnableToGetKeyPairById
        )?;

        let key_pair_cls = jni_find_class!(env, KEY_PAIR, UnableToGetKeyPairById)?;

        let key_pair = jni_new_object!(
            env,
            KEY_PAIR,
            &[(&public_key).into(), (&private_key).into()],
            UnableToGetKeyPairById
        )?;

        Ok(Key(key_pair))
    }
}

#[derive(Debug)]
pub struct Key(JObject<'static>);

impl KeyOps for Key {
    fn get_public_key(&self) -> SecureEnvResult<Vec<u8>> {
        let mut env = JAVA_VM
            .attach_current_thread_as_daemon()
            .map_err(SecureEnvError::UnableToAttachJVMToThread)?;

        let public_key =
            jni_call_method!(env, &self.0, KEY_PAIR_GET_PUBLIC, l, UnableToGetPublicKey)?;

        let public_key = jni_call_method!(
            env,
            &public_key,
            PUBLIC_KEY_GET_ENCODED,
            l,
            UnableToGetPublicKey
        )?;

        // `try_into` returns `Infallible` so we can unwrap safely
        let public_key: JByteArray = public_key.try_into().unwrap();

        let public_key = env
            .convert_byte_array(&public_key)
            .map_err(SecureEnvError::UnableToCreateJavaValue)?;

        Ok(public_key)
    }

    fn sign(&self, msg: &[u8]) -> SecureEnvResult<Vec<u8>> {
        let mut env = JAVA_VM
            .attach_current_thread_as_daemon()
            .map_err(SecureEnvError::UnableToAttachJVMToThread)?;

        let algorithm = env
            .new_string(SHA256_WITH_ECDSA_ALGO)
            .map_err(SecureEnvError::UnableToCreateJavaValue)?;

        let private_key = jni_call_method!(
            env,
            &self.0,
            KEY_PAIR_GET_PRIVATE,
            l,
            UnableToCreateSignature
        )?;

        let signature_instance = jni_call_static_method!(
            env,
            SIGNATURE,
            SIGNATURE_GET_INSTANCE,
            &[(&algorithm).into()],
            l,
            UnableToCreateSignature
        )?;

        jni_call_method!(
            env,
            &signature_instance,
            SIGNATURE_INIT_SIGN,
            &[(&private_key).into()],
            v,
            UnableToCreateSignature
        )?;

        let b_arr = env
            .byte_array_from_slice(msg)
            .map_err(SecureEnvError::UnableToCreateJavaValue)?;

        jni_call_method!(
            env,
            &signature_instance,
            SIGNATURE_UPDATE,
            &[(&b_arr).into()],
            v,
            UnableToCreateSignature
        )?;

        let signature = jni_call_method!(
            env,
            &signature_instance,
            SIGNATURE_SIGN,
            l,
            UnableToCreateSignature
        )?;

        // `try_into` returns `Infallible` so we can unwrap safely
        let signature: JByteArray = signature.try_into().unwrap();

        let signature = env
            .convert_byte_array(&signature)
            .map_err(SecureEnvError::UnableToCreateJavaValue)?;

        Ok(signature)
    }
}
