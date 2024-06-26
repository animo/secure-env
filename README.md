# Secure Element Library for Android and iOS

`secure-env` is a library that allows for key generation and signature creation using the mobile secure element.

## Supported targets

-   `aarch64-apple-ios`
-   `aarch64-apple-ios-sim`
-   `x86_64-apple-ios`
-   `aarch64-linux-android`
-   `armv7-linux-androideabi`
-   `i686-linux-android`
-   `x86_64-linux-android`

## iOS

iOS bindings are done via [security-framework](https://github.com/kornelski/rust-security-framework). This is a safe wrapper around [Apple's security.framework](https://developer.apple.com/documentation/security).

## Android

Android bindings are done via [jni-rs](https://github.com/jni-rs/jni-rs). It was discussed to use do this via IPC (Binder) or HIDL, but jni was chosen for its similicity and available documentation.

Beneath these bindings it fully relies on `KeyStore`. During key generation, based on the support version, `setIsStrongBoxBacked` is set to make sure the key is store in hardware. If this is not supported we fall back to a lower level of security `setUserPresenceRequired`.

> NOTE: there still needs to be some additional research done into the exact garantuees that `setUserPresenceRequired` provides. If it means TEE, it is all good.

### Additional setup

Due to time constraints, currently some additional setup is required for Android to fully work. This has to do with accessing the JVM pointer from Rust. If something like [android_activity](https://github.com/rust-mobile/android-activity) is used, take a look at the [android example](./examples/android/src/lib.rs). If this library is used from a React Native context, or native Android app, include the following in your project:

```java
package id.animo;

public class SecureEnvironment {
    static {
        System.loadLibrary("secure_env");
    }


    public static native void set_env();
}

```

Afterwards, you can call `SecureEnvironment.set_env` before making any calls to the library. Afterwards everything should be set up properly.

## Features

|                   | ios | android |
| ----------------- | --- | ------- |
| generate keypair  | ✅  | ✅      |
| get keypair by id | ✅  | ✅      |
| get public key    | ✅  | ✅      |
| sign              | ✅  | ✅      |

## Usage

Add the dependency

```console
cargo add secure-env
```

```rust
// src/main.rs
use secure_env::{SecureEnvironment, SecureEnvironmentOps, Key, KeyOps};

fn main() {
    let key = SecureEnvironment::generate_keypair("my-key-id").unwrap();
    let key_from_id = SecureEnvironment::get_keypair_by_id("my-key-id").unwrap();

    let msg = b"Hello World!";

    let public_key = key.get_public_key().unwrap();
    let signature = key.sign(msg).unwrap();

    assert!(public_key.len(), 33);
    assert!(signature.len(), 64);
}
```
