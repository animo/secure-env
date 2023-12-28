use android_activity::AndroidApp;
use secure_env::{Key, SecureEnvironment};

#[no_mangle]
fn android_main(_app: AndroidApp) {
    let senv = SecureEnvironment::new().unwrap();
    let k = senv.generate_key("some-id").unwrap();
    let n_k = senv.get_by_id("some-id").unwrap();

    let k = k.get_public_key().unwrap();
    let n_k = n_k.get_public_key().unwrap();
    assert_eq!(k, n_k);

    // let key = k.get_public_key().unwrap();

    // println!("key: {key:?}");

    // let signature = k.sign(b"message!").unwrap();
    // println!("signature: {signature:?}");
}
