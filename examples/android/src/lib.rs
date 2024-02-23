use android_activity::AndroidApp;
use secure_env::{
    error::SecureEnvResult, key::KeyOps, secure_environment::SecureEnvironmentOps,
    SecureEnvironment,
};

fn main() -> SecureEnvResult<()> {
    let k = SecureEnvironment::generate_keypair("some-id")?;
    let n_k = SecureEnvironment::get_keypair_by_id("some-id")?;

    let k = k.get_public_key()?;
    let n_k = n_k.get_public_key()?;

    assert_eq!(k, n_k);
    println!("Created and got key and they are equal");

    Ok(())
}

#[no_mangle]
fn android_main(_app: AndroidApp) {
    match main() {
        Ok(_) => println!("Success!"),
        Err(e) => eprintln!("Error!: {e:?}"),
    }
}
