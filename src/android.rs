use crate::{
    error::{SecureEnvError, SecureEnvResult},
    jni_tokens::*,
    KeyOps, SecureEnvironmentOps,
};
use jni::objects::{JByteArray, JObject, JString, JValue};
use p256::{ecdsa::Signature, elliptic_curve::sec1::ToEncodedPoint};
use paste::paste;
use x509_parser::{prelude::FromDer, x509::SubjectPublicKeyInfo};

lazy_static::lazy_static! {
    pub static ref JAVA_VM: jni::JavaVM =
        unsafe { jni::JavaVM::from_raw(ndk_context::android_context().vm().cast()) }.unwrap();
}

macro_rules! jni_handle_error {
    ($env:expr, $err:ident) => {
        if $env
            .exception_check()
            .map_err(|e| $crate::error::SecureEnvError::$err(Some(e.to_string())))?
        {
            let throwable = $env
                .exception_occurred()
                .map_err(|e| $crate::error::SecureEnvError::$err(Some(e.to_string())))?;
            $env.exception_clear()
                .map_err(|e| $crate::error::SecureEnvError::$err(Some(e.to_string())))?;

            let message = $env
                .call_method(
                    &throwable,
                    EXCEPTION_TO_STRING,
                    EXCEPTION_TO_STRING_SIG,
                    &[],
                )
                .and_then(|v| v.l())
                .unwrap();

            let msg_rust: String = $env
                .get_string(&message.into())
                .map_err($crate::error::SecureEnvError::UnableToCreateJavaValue)?
                .into();

            return Err($crate::error::SecureEnvError::$err(Some(msg_rust)));
        }
    };
}

macro_rules! jni_call_method {
    ($env:expr, $cls:expr, $method:ident, $args:expr, $ret_typ:ident, $err:ident) => {
        paste! {
        $env.call_method($cls, $method, [<$method _SIG>], $args)
            .map_err(|e| $crate::error::SecureEnvError::$err(Some(e.to_string())))
            .and_then(|v| {
                jni_handle_error!($env, $err);

                v.$ret_typ()
                    .map_err(|e| $crate::error::SecureEnvError::$err(Some(e.to_string())))
            })
        }
    };

    ($env:expr, $cls:expr, $method:ident, $ret_typ:ident, $err:ident) => {
        jni_call_method!($env, $cls, $method, &[], $ret_typ, $err)
    };
}

macro_rules! jni_call_static_method {
    ($env:expr, $cls:ident, $method:ident, $args:expr, $ret_typ:ident, $err:ident) => {
        paste! {{
        let res = $env
            .call_static_method(
                [<$cls _CLS>],
                $method,
                [<$method _SIG>],
                $args,
            )
            .map_err(|e| $crate::error::SecureEnvError::$err(Some(e.to_string())))
            .and_then(|v| {
                jni_handle_error!($env, $err);

                v.$ret_typ()
                    .map_err(|e| $crate::error::SecureEnvError::$err(Some(e.to_string())))
            });

        jni_handle_error!($env, $err);

        res
        }}
    };

    ($env:expr, $cls:ident, $method:ident, $ret_typ:ident, $err:ident) => {
        jni_call_static_method!($env, $cls, $method, &[], $ret_typ, $err)
    };
}

macro_rules! jni_get_static_field {
    ($env:expr, $cls:expr, $method:ident, $ret_typ:ident, $err:ident) => {
        paste! {{
        let field = $env
            .get_static_field($cls, $method, [<$method _SIG>])
            .map_err(|e| $crate::error::SecureEnvError::$err(Some(e.to_string())))
            .and_then(|v| {
                jni_handle_error!($env, $err);

                v.$ret_typ()
                    .map_err(|e| $crate::error::SecureEnvError::$err(Some(e.to_string())))
            });

        jni_handle_error!($env, $err);

        field
        }}
    };
}

macro_rules! jni_new_object {
    ($env:expr, $cls:ident, $args:expr, $err:ident) => {
        paste! {{
        let obj = $env
            .new_object(
                [<$cls _CLS>],
                [<$cls _CTOR_SIG>],
                $args,
            )
            .map_err(|e| $crate::error::SecureEnvError::$err(Some(e.to_string())));

        jni_handle_error!($env, $err);

        obj
        }}
    };
}

macro_rules! jni_find_class {
    ($env:expr, $cls:ident, $err:ident) => {
        paste! {{
        let cls = $env
            .find_class([<$cls _CLS>])
            .map_err(|e| $crate::error::SecureEnvError::$err(Some(e.to_string())));

        jni_handle_error!($env, $err);

        cls
        }}
    };
}

#[derive(Debug)]
pub struct SecureEnvironment;

impl SecureEnvironmentOps<Key> for SecureEnvironment {
    fn generate_keypair(id: impl Into<String>) -> SecureEnvResult<Key> {
        let mut env = JAVA_VM
            .attach_current_thread_as_daemon()
            .map_err(SecureEnvError::UnableToAttachJVMToThread)?;

        let ctx = ndk_context::android_context().context() as jni::sys::jobject;
        if ctx.is_null() {
            return Err(SecureEnvError::UnableToGenerateKey(Some(
                "Could not acquire context. Null, or unaligned pointer, was found".to_owned(),
            )));
        }
        let ctx = unsafe { JObject::from_raw(ctx) };

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

        let package_manager = jni_call_method!(
            env,
            ctx,
            CONTEXT_GET_PACKAGE_MANAGER,
            l,
            UnableToGenerateKey
        )?;

        let hardware_keystore_token = env
            .new_string("android.hardware.hardware_keystore")
            .map_err(SecureEnvError::UnableToCreateJavaValue)?;

        // This has not been documented anywhere that I could find.
        // After some debugging with emulators and multiple real device
        // (some with a Secure Element (Pixel 6a) and some without (OnePlus Nord))
        // 300 seems to be the correct cut-off.
        let required_hardware_keystore_version = 300;

        let has_strongbox_support = jni_call_method!(
            env,
            &package_manager,
            PACKAGE_MANAGER_HAS_SYSTEM_FEATURE,
            &[
                (&hardware_keystore_token).into(),
                required_hardware_keystore_version.into()
            ],
            z,
            UnableToGenerateKey
        )?;

        let builder = if has_strongbox_support {
            jni_call_method!(
                env,
                &builder,
                KEY_GEN_PARAMETER_SPEC_BUILDER_SET_IS_STRONG_BOX_BACKED,
                &[JValue::Bool(1)],
                l,
                UnableToGenerateKey
            )?
        } else {
            // 41: Hardware enforcement of device-unlocked keys
            // TODO: check the exact meaning behind this
            //       Maybe there is number that corrolates to TEE?
            //       This seems to work best with testing
            let required_device_unlocked_keystore_version = 41;

            let has_device_unlocked_keystore_support = jni_call_method!(
                env,
                &package_manager,
                PACKAGE_MANAGER_HAS_SYSTEM_FEATURE,
                &[
                    (&hardware_keystore_token).into(),
                    required_device_unlocked_keystore_version.into()
                ],
                z,
                UnableToGenerateKey
            )?;

            if !has_device_unlocked_keystore_support {
                return Err(SecureEnvError::UnableToGenerateKey(Some(
                    "Unable to generate keypair. Device has insufficient keystore support"
                        .to_owned(),
                )));
            }

            builder
        };

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

        let p = jni_call_method!(env, &self.0, KEY_PAIR_GET_PUBLIC, l, UnableToGetPublicKey)?;

        let public_key =
            jni_call_method!(env, &p, PUBLIC_KEY_GET_ENCODED, l, UnableToGetPublicKey)?;

        let format =
            jni_call_method!(env, &p, PUBLIC_KEY_GET_FORMAT, l, UnableToGetPublicKey).unwrap();

        let s = JString::from(format);
        let f = env.get_string(&s).unwrap();
        let s = f.to_str().unwrap();

        if s != "X.509" {
            return Err(SecureEnvError::UnableToGetPublicKey(Some(format!(
                "Unexpected key format. Expected 'X.509', received: '{s}'"
            ))));
        }

        let public_key: JByteArray = public_key.into();

        let public_key = env
            .convert_byte_array(public_key)
            .map_err(SecureEnvError::UnableToCreateJavaValue)?;

        let spki = SubjectPublicKeyInfo::from_der(&public_key).unwrap();
        let public_key = spki.1.subject_public_key.data.to_vec();

        let public_key = p256::PublicKey::from_sec1_bytes(&public_key)
            .map_err(|e| SecureEnvError::UnableToGetPublicKey(Some(e.to_string())))?;

        let point = public_key.to_encoded_point(true);

        let public_key = point.to_bytes().to_vec();

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

        let signature: JByteArray = signature.into();

        let signature = env
            .convert_byte_array(signature)
            .map_err(SecureEnvError::UnableToCreateJavaValue)?;

        let signature = Signature::from_der(&signature).unwrap();
        let r = signature.r();
        let s = signature.s();
        let compact_signature = [r.to_bytes(), s.to_bytes()].concat();

        Ok(compact_signature)
    }
}
