//! Port of the C++ GTest suite (`tests/tests.cpp`).
//!
//! Exercises each building block (WOTS, XMSS, UXMSS, PORS) and the top-level
//! stateful/stateless sign-verify round trips, for all three parameter sets.

// The library crate (`shrincs_rs`) and the `shrincs` module share a name; bind
// the crate root explicitly so `shrincs::…` paths in this file refer to the
// library root.
extern crate shrincs_rs as shrincs;

use shrincs::{
    SHRINCS_B, SHRINCS_B32, SHRINCS_L,
    address::{self, Adrs},
    constants::Params,
    hash::Sha256Ctx,
    pors_fp, shrincs as shrincs_api, uxmss, wots_c, xmss,
};

/// Build the shared base hash context from an all-zero `pk_seed` plus 48 zero
/// bytes — exactly as the C++ tests do.
fn test_hash_ctx() -> Sha256Ctx {
    let adrs = [0u8; 32];
    Sha256Ctx::new()
        .add_to_ctx(&[0u8; 16])
        .add_to_ctx(&adrs)
        .add_to_ctx(&adrs[..16])
}

const ZERO_SEED: [u8; 16] = [0u8; 16];

#[test]
fn wots_sign_verify_all_variants() {
    wots_sign_verify::<SHRINCS_L>();
    wots_sign_verify::<SHRINCS_B>();
    wots_sign_verify::<SHRINCS_B32>();
}

fn wots_sign_verify<P: Params>() {
    let message = vec![0u8; 32];
    let hash_ctx = test_hash_ctx();
    let mut adrs: Adrs = [0u8; 32];

    let signature = wots_c::wots_sign::<P>(
        &message, &ZERO_SEED, &ZERO_SEED, &ZERO_SEED, &ZERO_SEED, &hash_ctx, &mut adrs, 10, true,
        false,
    )
    .unwrap();
    let pkey = wots_c::wots_pk_from_sig::<P>(
        &signature, &message, &ZERO_SEED, &hash_ctx, &mut adrs, 10, true, false,
    )
    .unwrap();
    let ex_pkey = wots_c::wots_pk_gen::<P>(&ZERO_SEED, &hash_ctx, &mut adrs, 10, true);

    assert_eq!(pkey, ex_pkey);
}

#[test]
fn xmss_sign_verify_all_variants() {
    xmss_sign_verify::<SHRINCS_L>();
    xmss_sign_verify::<SHRINCS_B>();
    xmss_sign_verify::<SHRINCS_B32>();
}

fn xmss_sign_verify<P: Params>() {
    let message = vec![0u8; 32];
    let hash_ctx = test_hash_ctx();
    let mut adrs: Adrs = [0u8; 32];

    let signature = xmss::xmss_sign::<P>(
        &message,
        &ZERO_SEED,
        &ZERO_SEED,
        &ZERO_SEED,
        &ZERO_SEED,
        &hash_ctx,
        &mut adrs,
        P::H_PRIME as u32,
        2,
    )
    .unwrap();
    let pkey = xmss::xmss_pk_from_sig::<P>(
        &signature[..P::WOTS_SIGN_LEN],
        &signature[P::WOTS_SIGN_LEN..],
        &message,
        &ZERO_SEED,
        &hash_ctx,
        &mut adrs,
        P::H_PRIME as u32,
        2,
    )
    .unwrap();
    let root = xmss::xmss_root::<P>(&ZERO_SEED, &hash_ctx, &mut adrs, P::H_PRIME as u32);

    assert_eq!(pkey, root);
}

#[test]
fn uxmss_sign_verify_all_variants() {
    uxmss_sign_verify::<SHRINCS_L>();
    uxmss_sign_verify::<SHRINCS_B>();
    uxmss_sign_verify::<SHRINCS_B32>();
}

fn uxmss_sign_verify<P: Params>() {
    let message = vec![0u8; 32];
    let hash_ctx = test_hash_ctx();
    let mut adrs: Adrs = [0u8; 32];

    let signature = uxmss::uxmss_sign::<P>(
        &message, &ZERO_SEED, &ZERO_SEED, &ZERO_SEED, &ZERO_SEED, &hash_ctx, &mut adrs, 2,
    )
    .unwrap();
    let pkey = uxmss::uxmss_pk_from_sig::<P>(
        &signature[..P::WOTS_SIGN_LEN],
        &signature[P::WOTS_SIGN_LEN..],
        &message,
        &ZERO_SEED,
        &hash_ctx,
        &mut adrs,
        2,
    )
    .unwrap();
    let root = uxmss::uxmss_root::<P>(&ZERO_SEED, &hash_ctx, &mut adrs);

    assert_eq!(pkey, root);
}

#[test]
fn pors_extract_bits() {
    let message = [0xFFu8; 16];

    // 22 ones -> 4194303
    assert_eq!(pors_fp::extract_bits(&message, 34, 22), 4194303);
    assert_eq!(pors_fp::extract_bits(&message, 35, 22), 4194303);
}

#[test]
fn stateful_sign_verify_all_variants() {
    stateful_sign_verify::<SHRINCS_L>();
    stateful_sign_verify::<SHRINCS_B>();
    stateful_sign_verify::<SHRINCS_B32>();
}

fn stateful_sign_verify<P: Params>() {
    let mut pk = shrincs_api::PublicKey::default();
    let mut sk = shrincs_api::SecretKey::default();
    let mut state = shrincs_api::State::default();

    shrincs_api::key_gen::<P>(&mut pk, &mut sk, &mut state).unwrap();

    let message = vec![0u8; 32];

    // q = 1
    let sig = shrincs_api::sign_stateful::<P>(&message, &mut sk, &mut state).unwrap();
    assert!(shrincs_api::verify::<P>(&message, &sig, &pk));

    // q = 10
    state.q = 10;
    let sig = shrincs_api::sign_stateful::<P>(&message, &mut sk, &mut state).unwrap();
    assert!(shrincs_api::verify::<P>(&message, &sig, &pk));

    // q = 100
    state.q = 100;
    let sig = shrincs_api::sign_stateful::<P>(&message, &mut sk, &mut state).unwrap();
    assert!(shrincs_api::verify::<P>(&message, &sig, &pk));

    // q = HSF - 1 (also validates the q > 100 path non-trivially)
    state.q = P::HSF as u32 - 2;
    let sig = shrincs_api::sign_stateful::<P>(&message, &mut sk, &mut state).unwrap();
    assert!(shrincs_api::verify::<P>(&message, &sig, &pk));

    // q = HSF (last normal leaf)
    state.q = P::HSF as u32 - 1;
    let sig = shrincs_api::sign_stateful::<P>(&message, &mut sk, &mut state).unwrap();
    assert!(shrincs_api::verify::<P>(&message, &sig, &pk));

    // q = HSF + 1 (extra leaf) — still valid
    state.q = P::HSF as u32;
    let sig = shrincs_api::sign_stateful::<P>(&message, &mut sk, &mut state).unwrap();
    assert!(shrincs_api::verify::<P>(&message, &sig, &pk));

    // q = HSF + 2 must fail
    state.q = P::HSF as u32 + 1;
    assert!(shrincs_api::sign_stateful::<P>(&message, &mut sk, &mut state).is_err());
}

#[test]
fn stateless_sign_verify_all_variants() {
    stateless_sign_verify::<SHRINCS_L>();
    stateless_sign_verify::<SHRINCS_B>();
    stateless_sign_verify::<SHRINCS_B32>();
}

fn stateless_sign_verify<P: Params>() {
    let mut pk = shrincs_api::PublicKey::default();
    let mut sk = shrincs_api::SecretKey::default();
    let mut state = shrincs_api::State::default();

    shrincs_api::key_gen::<P>(&mut pk, &mut sk, &mut state).unwrap();

    let message = vec![0u8; 32];

    let sig = shrincs_api::sign_stateless::<P>(&message, &sk).unwrap();
    assert_eq!(sig.len(), P::SL_SIZE);
    assert!(shrincs_api::verify::<P>(&message, &sig, &pk));
}

#[test]
fn stateless_prepare_sign_verify_all_variants() {
    stateless_prepare_sign_verify::<SHRINCS_L>();
    stateless_prepare_sign_verify::<SHRINCS_B>();
    stateless_prepare_sign_verify::<SHRINCS_B32>();
}

/// The prepared (cached) stateless signing path must produce a signature
/// byte-identical to the unprepared one and still verify, and the serialized
/// cache must stay under the 10 KiB budget.
fn stateless_prepare_sign_verify<P: Params>() {
    let mut pk = shrincs_api::PublicKey::default();
    let mut sk = shrincs_api::SecretKey::default();
    let mut state = shrincs_api::State::default();

    shrincs_api::key_gen::<P>(&mut pk, &mut sk, &mut state).unwrap();

    let message = vec![0u8; 32];

    let prepared = shrincs_api::sign_stateless_prepare::<P>(&sk);
    let bytes = prepared.to_bytes();
    assert!(
        bytes.len() < 10_000,
        "cache too large: {} bytes",
        bytes.len()
    );

    // Round-trip through the serialized form (as a file backing would).
    let loaded = shrincs_api::PreparedStatelessKey::<P>::from_bytes(&bytes)
        .expect("serialized prepared key must round-trip");

    // Corrupted/truncated input must be rejected.
    let mut bad = bytes.clone();
    bad[0] ^= 0xFF;
    assert!(shrincs_api::PreparedStatelessKey::<P>::from_bytes(&bad).is_none());
    assert!(
        shrincs_api::PreparedStatelessKey::<P>::from_bytes(&bytes[..bytes.len() - 1]).is_none()
    );

    let sig = shrincs_api::sign_stateless::<P>(&message, &sk).unwrap();
    let sig_prepared =
        shrincs_api::sign_stateless_with_prepare::<P>(&message, &sk, &loaded).unwrap();

    assert_eq!(
        sig, sig_prepared,
        "prepared and unprepared signatures must match"
    );
    assert!(shrincs_api::verify::<P>(&message, &sig_prepared, &pk));
}

/// Sanity: the address setters place fields at the documented offsets.
#[test]
fn address_setters() {
    let mut a: Adrs = [0u8; 32];
    address::set_layer_address(&mut a, 0x0102_0304);
    assert_eq!(&a[0..4], &[0x01, 0x02, 0x03, 0x04]);

    address::set_tree_address(&mut a, 0x0102_0304, 0x0102_0304_0506_0708);
    assert_eq!(&a[4..8], &[0x01, 0x02, 0x03, 0x04]);
    assert_eq!(&a[8..16], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

    address::set_type_and_clear(&mut a, 0xAABB_CCDD);
    assert_eq!(&a[16..20], &[0xAA, 0xBB, 0xCC, 0xDD]);
    assert_eq!(&a[20..32], &[0u8; 12]);
}
