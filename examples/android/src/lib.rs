use android_activity::AndroidApp;
use mobile_tests::run_tests;

#[no_mangle]
fn android_main(_app: AndroidApp) {
    run_tests();
}
