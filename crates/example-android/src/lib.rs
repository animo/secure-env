use android_activity::AndroidApp;

#[no_mangle]
fn android_main(_app: AndroidApp) -> Result<(), Box<dyn std::error::Error>> {
    let key = secureenv::android::Key::generate();
    println!("secure environment: {key:#?}",);

    Ok(())
}
