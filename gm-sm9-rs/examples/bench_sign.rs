use gm_sm9_rs::{SignMasterKey, Signer, Verifier};
use rand::rng;
use std::time::Instant;

fn main() {
    let mut rng = rng();

    println!("Generating master key...");
    let start = Instant::now();
    let master = SignMasterKey::generate(&mut rng).unwrap();
    println!("Master key gen: {:?}", start.elapsed());

    let identity = b"test@example.com";

    println!("Extracting user key...");
    let start = Instant::now();
    let user_key = master.extract_key(identity).unwrap();
    println!("Extract key: {:?}", start.elapsed());

    let signer = Signer::new(user_key);
    let message = b"test message";

    println!("Signing...");
    let start = Instant::now();
    let signature = signer.sign(message, &mut rng).unwrap();
    println!("Sign: {:?}", start.elapsed());

    let verifier = Verifier::new(identity, &master.ppubs);

    println!("Verifying...");
    let start = Instant::now();
    let valid = verifier.verify(message, &signature).unwrap();
    println!("Verify: {:?}", start.elapsed());

    assert!(valid);
    println!("Success!");
}
