use android_activity::AndroidApp;
use secure_env::{key::KeyOps, secure_environment::SecureEnvironmentOps, SecureEnvironment};

#[no_mangle]
fn android_main(_app: AndroidApp) {
    let k = SecureEnvironment::generate_keypair("some-id").unwrap();
    let n_k = SecureEnvironment::get_keypair_by_id("some-id").unwrap();

    let k = k.get_public_key().unwrap();
    let n_k = n_k.get_public_key().unwrap();

    assert_eq!(k, n_k);
    println!("Created and got key and they are equal");
}
