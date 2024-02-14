#![feature(concat_idents)]

pub mod error;

mod key;
pub use key::*;

mod secure_environment;
pub use secure_environment::*;

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod ios;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub use ios::*;

#[cfg(target_os = "android")]
mod android;
#[cfg(target_os = "android")]
pub use android::*;

#[cfg(target_os = "android")]
mod jni_tokens;
