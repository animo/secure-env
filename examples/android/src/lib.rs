use android_activity::AndroidApp;
use mobile_tests::run_tests;

use jni::{JavaVM, JNIEnv, objects::JClass, sys::jobject};

extern "system" {
    fn Java_id_animo_SecureEnvironment_set_1env<'local>(env: JNIEnv<'local>, _class: JClass<'local>);
}

#[no_mangle]
fn android_main(app: AndroidApp) {
    // Since we cannot use the jvm pointer set by `android_activity` we manually call the exposed
    // method with a null pointer for a class (as it is not used anyways) and the jni env we
    // receive from the `app`.
    let jvm = unsafe { JavaVM::from_raw(app.vm_as_ptr() as *mut _) }.unwrap();
    let env = unsafe { JNIEnv::from_raw(jvm.attach_current_thread().unwrap().get_raw()) }.unwrap();
    let clazz = unsafe { JClass::from_raw(std::ptr::null::<jobject>() as *mut _) };
    unsafe { Java_id_animo_SecureEnvironment_set_1env(env, clazz) };

    run_tests();
}
