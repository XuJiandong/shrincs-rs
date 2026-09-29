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

/// The self-contained WOTS+C API must sign and verify a message, and reject a
/// wrong message, a wrong key and a tampered signature.
#[test]
fn wots_standalone_sign_verify_all_variants() {
    wots_standalone_sign_verify::<SHRINCS_L>();
    wots_standalone_sign_verify::<SHRINCS_B>();
    wots_standalone_sign_verify::<SHRINCS_B32>();
}

fn wots_standalone_sign_verify<P: Params>() {
    let sk = wots_c::wots_key_from_seed::<P>(&[0x42u8; 48]);
    let message = b"shrincs wots+c standalone message";

    let sig = wots_c::wots_sign_message::<P>(message, &sk).unwrap();
    assert_eq!(sig.len(), P::WOTS_SIGN_LEN);
    assert!(wots_c::wots_verify_message::<P>(message, &sig, &sk.pk));

    // Wrong message.
    assert!(!wots_c::wots_verify_message::<P>(
        b"a different message",
        &sig,
        &sk.pk
    ));

    // Wrong key (entirely different seed).
    let other = wots_c::wots_key_from_seed::<P>(&[0x43u8; 48]);
    assert_ne!(other.pk, sk.pk);
    assert!(!wots_c::wots_verify_message::<P>(message, &sig, &other.pk));

    // Public key binding: altering only `pk_seed` or only `root` must fail.
    let mut bad_seed = sk.pk;
    bad_seed.pk_seed[0] ^= 0x01;
    assert!(!wots_c::wots_verify_message::<P>(message, &sig, &bad_seed));
    let mut bad_root = sk.pk;
    bad_root.root[0] ^= 0x01;
    assert!(!wots_c::wots_verify_message::<P>(message, &sig, &bad_root));

    // Tampered signature: flip one bit in `r`, in `ctr`, in the first chain and
    // in the last chain. Each must be rejected (and must not panic).
    let raw = sig.to_bytes();
    for pos in [0, P::R_LEN, P::R_LEN + 3, P::R_LEN + 4, raw.len() - 1] {
        let mut tampered_raw = raw.clone();
        tampered_raw[pos] ^= 0x01;
        let tampered = wots_c::WotsSignature::from_bytes::<P>(&tampered_raw)
            .expect("tampering must preserve the signature length");
        assert!(
            !wots_c::wots_verify_message::<P>(message, &tampered, &sk.pk),
            "tampered signature accepted at byte {pos}"
        );
    }
}

/// A randomly generated key pair must sign and verify, and its serialized
/// forms must round-trip into a key/public key that still verify.
#[test]
fn wots_standalone_key_gen_sign_verify_all_variants() {
    wots_standalone_key_gen_sign_verify::<SHRINCS_L>();
    wots_standalone_key_gen_sign_verify::<SHRINCS_B>();
    wots_standalone_key_gen_sign_verify::<SHRINCS_B32>();
}

fn wots_standalone_key_gen_sign_verify<P: Params>() {
    let sk = wots_c::wots_key_gen::<P>().unwrap();
    let message = b"random key message";

    let sig = wots_c::wots_sign_message::<P>(message, &sk).unwrap();
    assert!(wots_c::wots_verify_message::<P>(message, &sig, &sk.pk));
    assert!(!wots_c::wots_verify_message::<P>(
        b"other message",
        &sig,
        &sk.pk
    ));

    // Two independent generations yield different keys.
    let sk2 = wots_c::wots_key_gen::<P>().unwrap();
    assert!(sk2 != sk);
    assert!(!wots_c::wots_verify_message::<P>(message, &sig, &sk2.pk));

    // Deserialized keys and signatures still work.
    let sk_rt = wots_c::WotsSecretKey::from_bytes(&sk.to_bytes()).unwrap();
    let pk_rt = wots_c::WotsPublicKey::from_bytes(&sk.pk.to_bytes()).unwrap();
    let sig_rt = wots_c::WotsSignature::from_bytes::<P>(&sig.to_bytes()).unwrap();
    assert!(wots_c::wots_verify_message::<P>(message, &sig_rt, &pk_rt));
    assert_eq!(
        wots_c::wots_sign_message::<P>(message, &sk_rt).unwrap(),
        sig
    );
}

/// The standalone key derivation must use the documented fixed context
/// (stateless domain, key-pair address 0, all-zero address), and the standalone
/// verifier must accept a signature produced by the low-level primitive under
/// that same context.
#[test]
fn wots_standalone_matches_low_level_all_variants() {
    wots_standalone_matches_low_level::<SHRINCS_L>();
    wots_standalone_matches_low_level::<SHRINCS_B>();
    wots_standalone_matches_low_level::<SHRINCS_B32>();
}

fn wots_standalone_matches_low_level<P: Params>() {
    let message = vec![0u8; 32];
    let hash_ctx = test_hash_ctx();
    let mut adrs: Adrs = [0u8; 32];

    // `pk_seed == 0` makes `wots_key_from_seed`'s context equal `test_hash_ctx`.
    let sk = wots_c::wots_key_from_seed::<P>(&[0u8; 48]);
    let expected_root = wots_c::wots_pk_gen::<P>(&ZERO_SEED, &hash_ctx, &mut adrs, 0, false);
    assert_eq!(sk.pk.root, expected_root);

    // A low-level signature under the standalone context verifies as standalone.
    let raw = wots_c::wots_sign::<P>(
        &message,
        &ZERO_SEED,
        &ZERO_SEED,
        &ZERO_SEED,
        &sk.pk.root,
        &hash_ctx,
        &mut adrs,
        0,
        false,
        false,
    )
    .unwrap();
    let sig = wots_c::WotsSignature::from_bytes::<P>(&raw).unwrap();
    assert!(wots_c::wots_verify_message::<P>(&message, &sig, &sk.pk));
}

/// Key/signature serialization round-trips, and malformed lengths are rejected.
#[test]
fn wots_standalone_serialization() {
    // `wots_key_gen` must be the exact inverse of `wots_key_from_seed` on the
    // serialized 48-byte seed.
    let sk = wots_c::wots_key_gen::<SHRINCS_B>().unwrap();
    let bytes = sk.to_bytes();
    assert_eq!(bytes.len(), wots_c::WotsSecretKey::SERIALIZED_LEN);
    let seed: [u8; 48] = bytes[..48].try_into().unwrap();
    // (`WotsSecretKey` deliberately has no `Debug`, hence `assert!`.)
    assert!(wots_c::wots_key_from_seed::<SHRINCS_B>(&seed) == sk);
    assert_eq!(sk.to_bytes(), bytes);
    assert_eq!(sk.public_key(), &sk.pk);

    // Secret key round-trip.
    let sk_rt = wots_c::WotsSecretKey::from_bytes(&bytes).expect("valid length");
    assert!(sk_rt == sk);
    assert_eq!(sk_rt.to_bytes(), bytes);

    // Public key round-trip.
    let pk_bytes = sk.pk.to_bytes();
    assert_eq!(pk_bytes.len(), wots_c::WotsPublicKey::SERIALIZED_LEN);
    assert_eq!(wots_c::WotsPublicKey::from_bytes(&pk_bytes), Some(sk.pk));

    // Malformed lengths are rejected.
    assert!(wots_c::WotsSecretKey::from_bytes(&bytes[..bytes.len() - 1]).is_none());
    assert!(wots_c::WotsPublicKey::from_bytes(&pk_bytes[..16]).is_none());

    // Signature round-trip and length validation (no signing needed).
    let raw = vec![0u8; SHRINCS_B::WOTS_SIGN_LEN];
    let sig = wots_c::WotsSignature::from_bytes::<SHRINCS_B>(&raw).unwrap();
    assert_eq!(sig.len(), raw.len());
    assert!(!sig.is_empty());
    assert_eq!(sig.as_bytes(), &raw[..]);
    assert_eq!(sig.to_bytes(), raw);
    assert!(wots_c::WotsSignature::from_bytes::<SHRINCS_B>(&raw[..raw.len() - 1]).is_none());
    assert!(wots_c::WotsSignature::from_bytes::<SHRINCS_B>(&[]).is_none());
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
