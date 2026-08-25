// Find a byte in a stateless sig whose corruption still verifies.
extern crate shrincs;
use shrincs::{shrincs as s_api, SHRINCS_L, constants::Params};

fn main() {
    let mut seed = [0u8; 48];
    for i in 0..48 { seed[i] = (i as u8).wrapping_mul(3).wrapping_add(5); }
    let mut pk = s_api::PublicKey::default();
    let mut sk = s_api::SecretKey::default();
    let mut st = s_api::State::default();
    s_api::restore::<SHRINCS_L>(&seed, &mut pk, &mut sk, &mut st);
    let msg = vec![0x42u8; 32];
    let sig = s_api::sign_stateless::<SHRINCS_L>(&msg, &sk).unwrap();
    println!("SL_SIZE={}", SHRINCS_L::SL_SIZE);
    // corrupt each byte and see which still verify
    for off in 0..sig.len() {
        let mut bad = sig.clone();
        bad[off] ^= 0x01;
        if s_api::verify::<SHRINCS_L>(&msg, &bad, &pk) {
            println!("UNDETECTED corruption at byte {}", off);
        }
    }
    println!("done");
}
