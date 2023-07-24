use android_activity::AndroidApp;
use jni::objects::JObject;

#[no_mangle]
fn android_main(_app: AndroidApp) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ndk_context::android_context();
    let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }?;

    let senv = secureenv::android::Android::new(vm);
    println!("secure environment: {senv:#?}");

    Ok(())
}
