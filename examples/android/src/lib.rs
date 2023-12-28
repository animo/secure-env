use android_activity::AndroidApp;
use secure_env::SecureEnvironment;

#[no_mangle]
fn android_main(_app: AndroidApp) {
    let mut senv = SecureEnvironment::new().unwrap();
    let k = senv.generate_key().unwrap();

    let key = k.get_public_key().unwrap();

    println!("key: {key:?}");

    let signature = k.sign(b"message!").unwrap();
    println!("signature: {signature:?}");
}
