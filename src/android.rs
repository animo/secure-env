use crate::{
    error::{SecureEnvError, SecureEnvResult},
    jni_tokens::*,
    KeyOps, SecureEnvironmentOps,
};
use jni::{
    objects::{JByteArray, JClass, JObject, JString, JValue},
    sys::{jint, jobject, JNI_VERSION_1_6},
    JNIEnv, JavaVM,
};
use lazy_static::lazy_static;
use libc::c_void;
use p256::{ecdsa::Signature, elliptic_curve::sec1::ToEncodedPoint};
use paste::paste;
use std::sync::{Arc, Mutex};
use x509_parser::{prelude::FromDer, x509::SubjectPublicKeyInfo};

pub struct AndroidContext(*mut c_void);

unsafe impl Send for AndroidContext {}
unsafe impl Sync for AndroidContext {}

lazy_static! {
    static ref JAVA_VM: Arc<Mutex<Option<jni::JavaVM>>> = Arc::new(Mutex::new(None));
}

// Entry point that can be used to set the pointer to the jvm. It has to be called manually from a
// Java environment,
#[no_mangle]
pub extern "system" fn Java_id_animo_SecureEnvironment_set_1env<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
) {
    let vm = env.get_java_vm().unwrap();
    *JAVA_VM.lock().unwrap() = Some(vm);
}

macro_rules! jni_handle_error {
    ($env:expr, $err:ident, $e:expr) => {
        match (|| -> $crate::error::SecureEnvResult<()> {
            if $env
                .exception_check()
                .map_err(|e| $crate::error::SecureEnvError::$err(e.to_string()))?
            {
                let throwable = $env
                    .exception_occurred()
                    .map_err(|e| $crate::error::SecureEnvError::$err(e.to_string()))?;
                $env.exception_clear()
                    .map_err(|e| $crate::error::SecureEnvError::$err(e.to_string()))?;

                let message = $env
                    .call_method(
                        &throwable,
                        EXCEPTION_TO_STRING,
                        EXCEPTION_TO_STRING_SIG,
                        &[],
                    )
                    .and_then(|v| v.l())
                    .map_err(|e| {
                        $crate::error::SecureEnvError::UnableToCreateJavaValue(e.to_string())
                    })?;

                let msg_rust: String = $env
                    .get_string(&message.into())
                    .map_err(|e| {
                        $crate::error::SecureEnvError::UnableToCreateJavaValue(e.to_string())
                    })?
                    .into();

                return Err($crate::error::SecureEnvError::$err(msg_rust));
            } else {
                return Err($crate::error::SecureEnvError::$err($e.to_string()));
            }
        })() {
            Ok(_) => $crate::error::SecureEnvError::$err($e.to_string()),
            Err(e) => e,
        }
    };
}

macro_rules! jni_call_method {
    ($env:expr, $cls:expr, $method:ident, $args:expr, $ret_typ:ident, $err:ident) => {
        paste! {
        $env.call_method($cls, $method, [<$method _SIG>], $args)
            .and_then(|v| v.$ret_typ())
            .map_err(|e| jni_handle_error!($env, $err, e))
        }
    };

    ($env:expr, $cls:expr, $method:ident, $ret_typ:ident, $err:ident) => {
        jni_call_method!($env, $cls, $method, &[], $ret_typ, $err)
    };
}

macro_rules! jni_call_static_method {
    ($env:expr, $cls:ident, $method:ident, $args:expr, $ret_typ:ident, $err:ident) => {
        paste! {{
            $env.call_static_method([<$cls _CLS>], $method, [<$method _SIG>], $args)
                .and_then(|v| v.$ret_typ())
                .map_err(|e| jni_handle_error!($env, $err, e))
        }}
    };

    ($env:expr, $cls:ident, $method:ident, $ret_typ:ident, $err:ident) => {
        jni_call_static_method!($env, $cls, $method, &[], $ret_typ, $err)
    };
}

macro_rules! jni_get_static_field {
    ($env:expr, $cls:expr, $method:ident, $ret_typ:ident, $err:ident) => {
        paste! {{
            $env.get_static_field($cls, $method, [<$method _SIG>])
                .and_then(|v| v.$ret_typ())
                .map_err(|e| jni_handle_error!($env, $err, e))
        }}
    };
}

macro_rules! jni_new_object {
    ($env:expr, $cls:ident, $args:expr, $err:ident) => {
        paste! {{
            $env.new_object([<$cls _CLS>], [<$cls _CTOR_SIG>], $args)
                .map_err(|e| jni_handle_error!($env, $err, e))
        }}
    };
}

macro_rules! jni_find_class {
    ($env:expr, $cls:ident, $err:ident) => {
        paste! {{
            $env.find_class([<$cls _CLS>])
                .map_err(|e| jni_handle_error!($env, $err, e))
        }}
    };
}

#[derive(Debug)]
pub struct SecureEnvironment;

impl SecureEnvironmentOps<Key> for SecureEnvironment {
    fn generate_keypair(id: impl Into<String>) -> SecureEnvResult<Key> {
        let jvm = JAVA_VM.lock().map_err(|_| {
            SecureEnvError::UnableToAttachJVMToThread("Could not acquire lock on JVM".to_owned())
        })?;

        let jvm = jvm
            .as_ref()
            .ok_or(SecureEnvError::UnableToAttachJVMToThread(
                "JVM has not been set".to_owned(),
            ))?;

        let mut env = jvm
            .attach_current_thread_as_daemon()
            .map_err(|e| SecureEnvError::UnableToAttachJVMToThread(e.to_string()))?;

        let id = id.into();

        let id = env
            .new_string(id)
            .map_err(|e| SecureEnvError::UnableToCreateJavaValue(e.to_string()))?;

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
            .map_err(|e| SecureEnvError::UnableToCreateJavaValue(e.to_string()))?;

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

        let current_activity_thread = jni_call_static_method!(
            env,
            ACTIVITY_THREAD,
            ACTIVITY_THREAD_GET_CURRENT_ACTIVITY_THREAD,
            l,
            UnableToGenerateKey
        )?;
        let ctx = jni_call_method!(
            env,
            current_activity_thread,
            ACTIVITY_THREAD_GET_APPLICATION,
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
            .map_err(|e| SecureEnvError::UnableToCreateJavaValue(e.to_string()))?;

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
                return Err(SecureEnvError::UnableToGenerateKey(
                    "Unable to generate keypair. Device has insufficient keystore support"
                        .to_owned(),
                ));
            }

            builder
        };

        let algorithm = env
            .new_string(EC_ALGORITHM)
            .map_err(|e| SecureEnvError::UnableToCreateJavaValue(e.to_string()))?;

        let provider = env
            .new_string(ANDROID_KEY_STORE_PROVIDER)
            .map_err(|e| SecureEnvError::UnableToCreateJavaValue(e.to_string()))?;

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

        Ok(Key(Arc::new(Mutex::new(*key))))
    }

    fn get_keypair_by_id(id: impl Into<String>) -> SecureEnvResult<Key> {
        let jvm = JAVA_VM.lock().map_err(|_| {
            SecureEnvError::UnableToAttachJVMToThread("Could not acquire lock on JVM".to_owned())
        })?;

        let jvm = jvm
            .as_ref()
            .ok_or(SecureEnvError::UnableToAttachJVMToThread(
                "JVM has not been set".to_owned(),
            ))?;

        let mut env = jvm
            .attach_current_thread_as_daemon()
            .map_err(|e| SecureEnvError::UnableToAttachJVMToThread(e.to_string()))?;

        let provider = env
            .new_string(ANDROID_KEY_STORE_PROVIDER)
            .map_err(|e| SecureEnvError::UnableToCreateJavaValue(e.to_string()))?;

        let id = id.into();
        let id = env
            .new_string(id)
            .map_err(|e| SecureEnvError::UnableToCreateJavaValue(e.to_string()))?;

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

        Ok(Key(Arc::new(Mutex::new(*key_pair))))
    }
}

#[derive(Debug)]
pub struct Key(Arc<Mutex<jobject>>);

unsafe impl Send for Key {}
unsafe impl Sync for Key {}

impl Key {
    unsafe fn get_object(&self) -> JObject {
        let raw = self.0.lock().unwrap();
        JObject::from_raw(*raw)
    }
}

impl KeyOps for Key {
    fn get_public_key(&self) -> SecureEnvResult<Vec<u8>> {
        let jvm = JAVA_VM.lock().map_err(|_| {
            SecureEnvError::UnableToAttachJVMToThread("Could not acquire lock on JVM".to_owned())
        })?;

        let jvm = jvm
            .as_ref()
            .ok_or(SecureEnvError::UnableToAttachJVMToThread(
                "JVM has not been set".to_owned(),
            ))?;

        let mut env = jvm
            .attach_current_thread_as_daemon()
            .map_err(|e| SecureEnvError::UnableToAttachJVMToThread(e.to_string()))?;

        let key = unsafe { self.get_object() };

        let public_key = jni_call_method!(env, &key, KEY_PAIR_GET_PUBLIC, l, UnableToGetPublicKey)?;

        let public_key_encoded = jni_call_method!(
            env,
            &public_key,
            PUBLIC_KEY_GET_ENCODED,
            l,
            UnableToGetPublicKey
        )?;

        let format = jni_call_method!(
            env,
            &public_key,
            PUBLIC_KEY_GET_FORMAT,
            l,
            UnableToGetPublicKey
        )?;

        let format = JString::from(format);
        let format = env
            .get_string(&format)
            .map_err(|e| SecureEnvError::UnableToCreateJavaValue(e.to_string()))?;
        let format = format
            .to_str()
            .map_err(|e| SecureEnvError::UnableToGetPublicKey(e.to_string()))?;

        if format != "X.509" {
            return Err(SecureEnvError::UnableToGetPublicKey(format!(
                "Unexpected key format. Expected 'X.509', received: '{format}'"
            )));
        }

        let public_key: JByteArray = public_key_encoded.into();

        let public_key = env
            .convert_byte_array(public_key)
            .map_err(|e| SecureEnvError::UnableToCreateJavaValue(e.to_string()))?;

        let spki = SubjectPublicKeyInfo::from_der(&public_key)
            .map_err(|e| SecureEnvError::UnableToGetPublicKey(e.to_string()))?;

        let spki_data = spki.1.subject_public_key.data;

        let public_key = p256::PublicKey::from_sec1_bytes(&spki_data)
            .map_err(|e| SecureEnvError::UnableToGetPublicKey(e.to_string()))?;

        let encoded_point = public_key.to_encoded_point(true);

        let public_key = encoded_point.to_bytes().to_vec();

        Ok(public_key)
    }

    fn sign(&self, msg: &[u8]) -> SecureEnvResult<Vec<u8>> {
        let jvm = JAVA_VM.lock().map_err(|_| {
            SecureEnvError::UnableToAttachJVMToThread("Could not acquire lock on JVM".to_owned())
        })?;

        let jvm = jvm
            .as_ref()
            .ok_or(SecureEnvError::UnableToAttachJVMToThread(
                "JVM has not been set".to_owned(),
            ))?;

        let mut env = jvm
            .attach_current_thread_as_daemon()
            .map_err(|e| SecureEnvError::UnableToAttachJVMToThread(e.to_string()))?;

        let key = unsafe { self.get_object() };

        let algorithm = env
            .new_string(SHA256_WITH_ECDSA_ALGO)
            .map_err(|e| SecureEnvError::UnableToCreateJavaValue(e.to_string()))?;

        let private_key =
            jni_call_method!(env, &key, KEY_PAIR_GET_PRIVATE, l, UnableToCreateSignature)?;

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
            .map_err(|e| SecureEnvError::UnableToCreateJavaValue(e.to_string()))?;

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
            .map_err(|e| SecureEnvError::UnableToCreateJavaValue(e.to_string()))?;

        let signature = Signature::from_der(&signature)
            .map_err(|e| SecureEnvError::UnableToCreateSignature(e.to_string()))?;

        let r = signature.r();
        let s = signature.s();
        let compact_signature = [r.to_bytes(), s.to_bytes()].concat();

        Ok(compact_signature)
    }
}
