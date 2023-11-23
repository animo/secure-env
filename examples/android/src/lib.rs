use android_activity::AndroidApp;

use secure_env::android::Key;

#[no_mangle]
fn android_main(_app: AndroidApp) {
    let k = Key::new();
    println!("KEY INSTANCE: {k:?}");
}
