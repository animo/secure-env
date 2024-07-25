pub static STRING_CLS: &str = "java/lang/String";

pub static EXCEPTION_TO_STRING: &str = "toString";
pub static EXCEPTION_TO_STRING_SIG: &str = "()Ljava/lang/String;";

pub static EC_ALGORITHM: &str = "EC";
pub static ANDROID_KEY_STORE_PROVIDER: &str = "AndroidKeyStore";
pub static SHA256_WITH_ECDSA_ALGO: &str = "SHA256withECDSA";

// Context

pub static CONTEXT_GET_PACKAGE_MANAGER: &str = "getPackageManager";
pub static CONTEXT_GET_PACKAGE_MANAGER_SIG: &str = "()Landroid/content/pm/PackageManager;";

// Package manager

pub static PACKAGE_MANAGER_HAS_SYSTEM_FEATURE: &str = "hasSystemFeature";
pub static PACKAGE_MANAGER_HAS_SYSTEM_FEATURE_SIG: &str = "(Ljava/lang/String;I)Z";

// Key Properties

pub static KEY_PROPERTIES_CLS: &str = "android/security/keystore/KeyProperties";

pub static KEY_PROPERTIES_AUTH_BIOMETRIC_STRONG: &str = "AUTH_BIOMETRIC_STRONG";
pub static KEY_PROPERTIES_AUTH_BIOMETRIC_STRONG_SIG: &str = "I";

pub static KEY_PROPERTIES_PURPOSE_SIGN: &str = "PURPOSE_SIGN";
pub static KEY_PROPERTIES_PURPOSE_SIGN_SIG: &str = "I";

pub static KEY_PROPERTIES_DIGEST_SHA256: &str = "DIGEST_SHA256";
pub static KEY_PROPERTIES_DIGEST_SHA256_SIG: &str = "Ljava/lang/String;";

// Key Gen Parameter Spec Builder

pub static KEY_GEN_PARAMETER_SPEC_BUILDER_CLS: &str =
    "android/security/keystore/KeyGenParameterSpec$Builder";

pub static KEY_GEN_PARAMETER_SPEC_BUILDER_CTOR_SIG: &str = "(Ljava/lang/String;I)V";

pub static KEY_GEN_PARAMETER_SPEC_BUILDER_SET_DIGESTS: &str = "setDigests";
pub static KEY_GEN_PARAMETER_SPEC_BUILDER_SET_DIGESTS_SIG: &str =
    "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;";

pub static KEY_GEN_PARAMETER_SPEC_BUILDER_SET_KEY_SIZE: &str = "setKeySize";
pub static KEY_GEN_PARAMETER_SPEC_BUILDER_SET_KEY_SIZE_SIG: &str =
    "(I)Landroid/security/keystore/KeyGenParameterSpec$Builder;";

pub static KEY_GEN_PARAMETER_SPEC_BUILDER_SET_USER_AUTHENTICATION_REQUIRED: &str =
    "setUserAuthenticationRequired";
pub static KEY_GEN_PARAMETER_SPEC_BUILDER_SET_USER_AUTHENTICATION_REQUIRED_SIG: &str =
    "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;";

pub static KEY_GEN_PARAMETER_SPEC_BUILDER_SET_INVALIDATED_BY_BIOMETRIC_ENROLLMENT: &str =
    "setInvalidatedByBiometricEnrollment";
pub static KEY_GEN_PARAMETER_SPEC_BUILDER_SET_INVALIDATED_BY_BIOMETRIC_ENROLLMENT_SIG: &str =
    "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;";

pub static KEY_GEN_PARAMETER_SPEC_BUILDER_SET_USER_AUTHENTICATION_PARAMETERS: &str =
    "setUserAuthenticationParameters";
pub static KEY_GEN_PARAMETER_SPEC_BUILDER_SET_USER_AUTHENTICATION_PARAMETERS_SIG: &str =
    "(II)Landroid/security/keystore/KeyGenParameterSpec$Builder;";

pub static KEY_GEN_PARAMETER_SPEC_BUILDER_SET_IS_STRONG_BOX_BACKED: &str = "setIsStrongBoxBacked";
pub static KEY_GEN_PARAMETER_SPEC_BUILDER_SET_IS_STRONG_BOX_BACKED_SIG: &str =
    "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;";

pub static KEY_GEN_PARAMETER_SPEC_BUILDER_BUILD: &str = "build";
pub static KEY_GEN_PARAMETER_SPEC_BUILDER_BUILD_SIG: &str =
    "()Landroid/security/keystore/KeyGenParameterSpec;";

// Key Pair Generator

pub static KEY_PAIR_GENERATOR_CLS: &str = "java/security/KeyPairGenerator";

pub static KEY_PAIR_GENERATOR_GET_INSTANCE: &str = "getInstance";
pub static KEY_PAIR_GENERATOR_GET_INSTANCE_SIG: &str =
    "(Ljava/lang/String;Ljava/lang/String;)Ljava/security/KeyPairGenerator;";

pub static KEY_PAIR_GENERATOR_INITIALIZE: &str = "initialize";
pub static KEY_PAIR_GENERATOR_INITIALIZE_SIG: &str =
    "(Ljava/security/spec/AlgorithmParameterSpec;)V";

pub static KEY_PAIR_GENERATOR_GENERATE_KEY_PAIR: &str = "generateKeyPair";
pub static KEY_PAIR_GENERATOR_GENERATE_KEY_PAIR_SIG: &str = "()Ljava/security/KeyPair;";

// Key Store

pub static KEY_STORE_CLS: &str = "java/security/KeyStore";

pub static KEY_STORE_GET_INSTANCE: &str = "getInstance";
pub static KEY_STORE_GET_INSTANCE_SIG: &str = "(Ljava/lang/String;)Ljava/security/KeyStore;";

pub static KEY_STORE_LOAD: &str = "load";
pub static KEY_STORE_LOAD_SIG: &str = "(Ljava/security/KeyStore$LoadStoreParameter;)V";

pub static KEY_STORE_GET_ENTRY: &str = "getEntry";
pub static KEY_STORE_GET_ENTRY_SIG: &str = "(Ljava/lang/String;Ljava/security/KeyStore$ProtectionParameter;)Ljava/security/KeyStore$Entry;";

// Key Store Entry

pub static KEY_STORE_ENTRY_GET_PRIVATE_KEY: &str = "getPrivateKey";
pub static KEY_STORE_ENTRY_GET_PRIVATE_KEY_SIG: &str = "()Ljava/security/PrivateKey;";

pub static KEY_STORE_ENTRY_GET_CERTIFICATE: &str = "getCertificate";
pub static KEY_STORE_ENTRY_GET_CERTIFICATE_SIG: &str = "()Ljava/security/cert/Certificate;";

// Certificate

pub static CERTIFICATE_GET_PUBLIC_KEY: &str = "getPublicKey";
pub static CERTIFICATE_GET_PUBLIC_KEY_SIG: &str = "()Ljava/security/PublicKey;";

// Key Pair

pub static KEY_PAIR_CLS: &str = "java/security/KeyPair";
pub static KEY_PAIR_CTOR_SIG: &str = "(Ljava/security/PublicKey;Ljava/security/PrivateKey;)V";

pub static KEY_PAIR_GET_PUBLIC: &str = "getPublic";
pub static KEY_PAIR_GET_PUBLIC_SIG: &str = "()Ljava/security/PublicKey;";

pub static KEY_PAIR_GET_PRIVATE: &str = "getPrivate";
pub static KEY_PAIR_GET_PRIVATE_SIG: &str = "()Ljava/security/PrivateKey;";

// Public Key

pub static PUBLIC_KEY_GET_ENCODED: &str = "getEncoded";
pub static PUBLIC_KEY_GET_ENCODED_SIG: &str = "()[B";

pub static PUBLIC_KEY_GET_FORMAT: &str = "getFormat";
pub static PUBLIC_KEY_GET_FORMAT_SIG: &str = "()Ljava/lang/String;";

// Signature

pub static SIGNATURE_CLS: &str = "java/security/Signature";

pub static SIGNATURE_GET_INSTANCE: &str = "getInstance";
pub static SIGNATURE_GET_INSTANCE_SIG: &str = "(Ljava/lang/String;)Ljava/security/Signature;";

pub static SIGNATURE_INIT_SIGN: &str = "initSign";
pub static SIGNATURE_INIT_SIGN_SIG: &str = "(Ljava/security/PrivateKey;)V";

pub static SIGNATURE_UPDATE: &str = "update";
pub static SIGNATURE_UPDATE_SIG: &str = "([B)V";

pub static SIGNATURE_SIGN: &str = "sign";
pub static SIGNATURE_SIGN_SIG: &str = "()[B";

pub static ACTIVITY_THREAD_CLS: &str = "android/app/ActivityThread";

pub static ACTIVITY_THREAD_GET_CURRENT_ACTIVITY_THREAD: &str = "currentActivityThread";
pub static ACTIVITY_THREAD_GET_CURRENT_ACTIVITY_THREAD_SIG: &str = "()Landroid/app/ActivityThread;";

pub static ACTIVITY_THREAD_GET_APPLICATION: &str = "getApplication";
pub static ACTIVITY_THREAD_GET_APPLICATION_SIG: &str = "()Landroid/app/Application;";
