use mobile_tests::run_tests;

#[no_mangle]
pub extern "C" fn main_rs() {
    run_tests();
}
