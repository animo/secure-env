#![feature(concat_idents, pointer_is_aligned)]

#[cfg(not(any(target_os = "android", target_os = "ios")))]
compile_error!("Only Android and iOS are supported targets");

pub mod error;

mod key;
pub use key::*;

mod secure_environment;
pub use secure_environment::*;

#[cfg(target_os = "ios")]
mod ios;
#[cfg(target_os = "ios")]
pub use ios::*;

#[cfg(target_os = "android")]
mod android;
#[cfg(target_os = "android")]
pub use android::*;

#[cfg(target_os = "android")]
mod jni_tokens;
