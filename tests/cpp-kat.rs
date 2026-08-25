#![cfg(feature = "kat-tests")]

//! Verify the Known-Answer-Test `.rsp` files emitted by the C++ reference
//! generators (`kat/kat_gen_pass.cpp` / `kat/kat_gen_fail.cpp`, run through
//! `make kat`, which writes them into `tests/`).
//!
//! Verification only — no signing. For every record the key pair is
//! re-derived from the record's `seed` via [`shrincs::restore`] (which must
//! reproduce the printed `pk` byte-for-byte), and the signature is checked
//! with [`shrincs::verify`], which dispatches on signature length exactly like
//! the C++ `shrincs_verify(msg, sig, sig_len, pk)`.
//!
//! The FAIL files contain two kinds of records:
//!   * corruption records — the corrupted bytes live in an extra field
//!     (`msg corrupted`, `pk corrupted`, `sig corrupted`,
//!     `sig corrupted (truncated to MAX_SF_SIZE)`); the original data is in
//!     the canonical fields and must still verify, while the corrupted input
//!     must produce the recorded `result` (normally `Fail`).
//!   * throw records (`sig = N/A`) — the failure only occurs inside signing
//!     (invalid state / exhausted counter), so they cannot be reproduced
//!     without signing and are skipped.
//!
//! Run `make kat` first to (re)generate the files, then:
//!   cargo test --release --features kat-tests --test cpp-kat

use shrincs::constants::Params;
use shrincs::{restore, verify, PublicKey, SecretKey, State, SHRINCS_B, SHRINCS_L};

const B_PASS: &str = include_str!("SHRINCS-B_pass.rsp");
const B_FAIL: &str = include_str!("SHRINCS-B_fail.rsp");
const L_PASS: &str = include_str!("SHRINCS-L_pass.rsp");
const L_FAIL: &str = include_str!("SHRINCS-L_fail.rsp");

/// One record from a `.rsp` file.
struct Record {
    label: String,
    /// 48-byte seed (`sk_seed ‖ sk_prf ‖ pk_seed`).
    seed: [u8; 48],
    msg: Vec<u8>,
    /// Printed public key: `pk_seed ‖ pk_root` (32 bytes).
    pk: [u8; 32],
    /// Signature; `None` for throw records (`sig = N/A`).
    sig: Option<Vec<u8>>,
    /// Extra corrupted-data field (name, bytes), if any.
    corrupted: Option<(String, Vec<u8>)>,
    /// `result = Pass` → true, `result = Fail` → false.
    expected: bool,
}

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex field: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex field"))
        .collect()
}

fn hex_arr<const N: usize>(s: &str) -> [u8; N] {
    let v = hex(s);
    assert_eq!(v.len(), N, "hex field has wrong length: {s}");
    v.try_into().unwrap()
}

fn get<'a>(fields: &'a [(String, String)], key: &str) -> &'a str {
    fields
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
        .unwrap_or_else(|| panic!("record missing field `{key}`"))
}

/// Canonical field names; anything else in a record is the corrupted-data
/// field (or `corrupted = N/A` on throw records).
const KNOWN_FIELDS: [&str; 10] = [
    "count", "label", "seed", "mlen", "msg", "pk", "sk", "sig", "siglen", "result",
];

fn parse_records(text: &str) -> Vec<Record> {
    text.split("\n\n")
        .filter(|block| {
            let b = block.trim();
            !b.is_empty() && !b.starts_with('#')
        })
        .map(|block| {
            let mut fields: Vec<(String, String)> = Vec::new();
            for line in block.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let (k, v) = line.split_once('=').expect("record line without '='");
                fields.push((k.trim().to_string(), v.trim().to_string()));
            }

            let mlen: usize = get(&fields, "mlen").parse().expect("bad mlen");
            let msg = hex(get(&fields, "msg"));
            assert_eq!(msg.len(), mlen, "msg length != mlen");
            let sig = match get(&fields, "sig") {
                "N/A" => None,
                s => Some(hex(s)),
            };
            if let Some(sig) = &sig {
                let siglen: usize = get(&fields, "siglen").parse().expect("bad siglen");
                assert_eq!(sig.len(), siglen, "sig length != siglen");
            }

            let corrupted = match fields
                .iter()
                .find(|(k, _)| !KNOWN_FIELDS.contains(&k.as_str()))
            {
                Some((k, v)) if v != "N/A" => Some((k.clone(), hex(v))),
                _ => None,
            };

            Record {
                label: get(&fields, "label").to_string(),
                seed: hex_arr::<48>(get(&fields, "seed")),
                msg,
                pk: hex_arr::<32>(get(&fields, "pk")),
                sig,
                corrupted,
                expected: match get(&fields, "result") {
                    "Pass" => true,
                    "Fail" => false,
                    other => panic!("bad result field: {other}"),
                },
            }
        })
        .collect()
}

fn run_suite<P: Params>(text: &str, variant: &str) {
    let records = parse_records(text);

    // The generator writes a `# Total records: N` footer; the parser must
    // have seen exactly that many records.
    let total: usize = text
        .lines()
        .find_map(|l| l.strip_prefix("# Total records:"))
        .expect("missing total-records footer")
        .trim()
        .parse()
        .expect("bad total-records footer");
    assert_eq!(records.len(), total, "{variant}: parser lost records");

    let mut verified = 0usize;
    let mut skipped = 0usize;

    for rec in &records {
        // Re-derive the key pair from the seed (no signing).
        let mut pk = PublicKey::default();
        let mut sk = SecretKey::default();
        let mut st = State::default();
        restore::<P>(&rec.seed, &mut pk, &mut sk, &mut st);

        // `restore` must reproduce the printed pk byte-for-byte.
        let mut pk_printed = [0u8; 32];
        pk_printed[..16].copy_from_slice(&pk.seed);
        pk_printed[16..].copy_from_slice(&pk.root);
        assert_eq!(
            pk_printed, rec.pk,
            "{variant}: restore pk != printed pk: {}",
            rec.label
        );

        let Some(sig) = &rec.sig else {
            // Throw record: the failure occurs inside signing (invalid
            // state / exhausted counter) — not reproducible without signing.
            skipped += 1;
            continue;
        };

        match &rec.corrupted {
            // PASS record: all data is original and must verify.
            None => {
                assert_eq!(
                    verify::<P>(&rec.msg, sig, &pk),
                    rec.expected,
                    "{variant}: plain record: {}",
                    rec.label
                );
            }
            Some((name, bad)) => match name.as_str() {
                // Original message must verify; corrupted message must
                // produce the recorded result.
                "msg corrupted" => {
                    assert_eq!(bad.len(), rec.msg.len(), "{variant}: bad msg length");
                    assert!(
                        verify::<P>(&rec.msg, sig, &pk),
                        "{variant}: original msg failed: {}",
                        rec.label
                    );
                    assert_eq!(
                        verify::<P>(bad, sig, &pk),
                        rec.expected,
                        "{variant}: wrong-msg: {}",
                        rec.label
                    );
                }
                // Original key must verify; the other key's pk must not.
                "pk corrupted" => {
                    assert_eq!(bad.len(), 32, "{variant}: bad pk length");
                    assert!(
                        verify::<P>(&rec.msg, sig, &pk),
                        "{variant}: original pk failed: {}",
                        rec.label
                    );
                    let mut bad_pk = PublicKey::default();
                    bad_pk.seed.copy_from_slice(&bad[..16]);
                    bad_pk.root.copy_from_slice(&bad[16..]);
                    assert_eq!(
                        verify::<P>(&rec.msg, sig, &bad_pk),
                        rec.expected,
                        "{variant}: wrong-pk: {}",
                        rec.label
                    );
                }
                // `sig` holds the original signature (must verify); the
                // corrupted bytes are the verify input.
                "sig corrupted" => {
                    assert!(
                        verify::<P>(&rec.msg, sig, &pk),
                        "{variant}: original sig failed: {}",
                        rec.label
                    );
                    assert_eq!(
                        verify::<P>(&rec.msg, bad, &pk),
                        rec.expected,
                        "{variant}: corrupted-sig: {}",
                        rec.label
                    );
                }
                // The stateless signature truncated to MAX_SF_SIZE bytes and
                // verified as if it were stateful — the C++ generator calls
                // shrincs_verify(msg, sig, MAX_SF_SIZE, pk).
                "sig corrupted (truncated to MAX_SF_SIZE)" => {
                    assert_eq!(bad.len(), P::MAX_SF_SIZE, "{variant}: truncated sig length");
                    assert!(
                        verify::<P>(&rec.msg, sig, &pk),
                        "{variant}: full stateless sig failed: {}",
                        rec.label
                    );
                    assert_eq!(
                        verify::<P>(&rec.msg, bad, &pk),
                        rec.expected,
                        "{variant}: truncated cross-type: {}",
                        rec.label
                    );
                }
                other => panic!("{variant}: unknown corrupted field `{other}`"),
            },
        }
        verified += 1;
    }

    eprintln!(
        "{variant}: {verified} record(s) verified, {skipped} throw record(s) skipped (of {total})"
    );
    assert!(verified > 0, "{variant}: no verifiable records");
}

#[test]
fn cpp_kat_pass_b() {
    run_suite::<SHRINCS_B>(B_PASS, "B-pass");
}

#[test]
fn cpp_kat_pass_l() {
    run_suite::<SHRINCS_L>(L_PASS, "L-pass");
}

#[test]
fn cpp_kat_fail_b() {
    run_suite::<SHRINCS_B>(B_FAIL, "B-fail");
}

#[test]
fn cpp_kat_fail_l() {
    run_suite::<SHRINCS_L>(L_FAIL, "L-fail");
}
