#![cfg_attr(not(any(feature = "library", test)), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(any(feature = "library", test))]
extern crate alloc;

#[cfg(not(any(feature = "library", test)))]
ckb_std::entry!(program_entry);
#[cfg(not(any(feature = "library", test)))]
// By default, the following heap configuration is used:
// * 16KB fixed heap
// * 1.2MB(rounded up to be 16-byte aligned) dynamic heap
// * Minimal memory block in dynamic heap is 64 bytes
// For more details, please refer to ckb-std's default_alloc macro
// and the buddy-alloc alloc implementation.
ckb_std::default_alloc!(16384, 1258306, 64);

use alloc::vec::Vec;

use ckb_std::log;
// The library crate (`shrincs_rs`) and the `shrincs` module share a name; bind
// the crate root explicitly so `shrincs::…` paths refer to the library root.
extern crate shrincs_rs as shrincs;
use shrincs::constants::Params;
use shrincs::shrincs as shrincs_api;
use shrincs::{PublicKey, SHRINCS_B};

// The parameter set hardened into this binary. `verify` dispatches on
// signature length internally, so a single parameter set covers both the
// stateful (short) and stateless (long) signature families.
type CurrentParams = SHRINCS_B;

/// Decode a hex nibble.
fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decode an even-length hex string (without a `0x` prefix) into bytes.
fn decode_hex(s: &[u8]) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.chunks(2) {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

/// Build a [`PublicKey`] from a 32-byte buffer: `seed (16) ‖ root (16)`.
fn parse_pk(bytes: &[u8]) -> Option<PublicKey> {
    if bytes.len() != 32 {
        return None;
    }
    let mut seed = [0u8; 16];
    let mut root = [0u8; 16];
    seed.copy_from_slice(&bytes[..16]);
    root.copy_from_slice(&bytes[16..32]);
    Some(PublicKey { seed, root })
}

pub fn program_entry() -> i8 {
    // Enable logging via ckb-std's `log` feature. Log lines can be seen when
    // running under ckb-debugger. Ignore the (benign) duplicate-init error.
    let _ = ckb_std::logger::init();

    let args = ckb_std::env::argv();
    log::info!("test-shrincs: argc = {}", args.len());

    // The data fields are <message> <signature> <pubkey>, hex-encoded.
    //
    // Layout depends on how argv is set up:
    // * `ckb-debugger --bin test-shrincs <msg> <sig> <pk>` passes the three
    //   values directly, so they start at argv[0] (argc == 3).
    // * Some launchers prepend the program name, so the three values sit at
    //   argv[1..4] (argc == 4).
    // Accept both; preferring argv[1..4] when the program name is present.
    let data = if args.len() >= 4 {
        &args[1..4]
    } else if args.len() == 3 {
        &args[0..3]
    } else {
        log::error!("expected 3 hex args: <message> <signature> <pubkey>");
        return 2;
    };

    let message = match decode_hex(data[0].to_bytes()) {
        Some(m) => m,
        None => {
            log::error!("bad hex in <message>");
            return 3;
        }
    };
    let sig = match decode_hex(data[1].to_bytes()) {
        Some(s) => s,
        None => {
            log::error!("bad hex in <signature>");
            return 4;
        }
    };
    let pk_bytes = match decode_hex(data[2].to_bytes()) {
        Some(p) => p,
        None => {
            log::error!("bad hex in <pubkey>");
            return 5;
        }
    };

    let pk = match parse_pk(&pk_bytes) {
        Some(p) => p,
        None => {
            log::error!("pubkey must be 32 bytes (seed‖root)");
            return 7;
        }
    };

    // The family is dispatched automatically: `verify` treats signatures up to
    // MAX_SF_SIZE bytes as stateful and longer ones as stateless.
    let stateful = sig.len() <= CurrentParams::MAX_SF_SIZE;
    log::info!(
        "message.len = {}, signature.len = {}, family = {}",
        message.len(),
        sig.len(),
        if stateful { "stateful" } else { "stateless" }
    );

    let ok = shrincs_api::verify::<CurrentParams>(&message, &sig, &pk);
    log::info!("verification result = {}", ok);

    if ok {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_hex_round_trip() {
        assert_eq!(decode_hex(b""), Some(vec![]));
        assert_eq!(decode_hex(b"00ff10"), Some(vec![0x00, 0xff, 0x10]));
        assert_eq!(decode_hex(b"0A"), Some(vec![0x0a]));
    }

    #[test]
    fn decode_hex_rejects_invalid() {
        // Odd length.
        assert_eq!(decode_hex(b"abc"), None);
        // Non-hex characters.
        assert_eq!(decode_hex(b"0g"), None);
        assert_eq!(decode_hex(b"zz"), None);
    }

    #[test]
    fn parse_pk_matches_expected_layout() {
        let bytes: Vec<u8> = (0..32u8).collect();
        let pk = parse_pk(&bytes).unwrap();
        assert_eq!(pk.seed, [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        assert_eq!(
            pk.root,
            [16u8, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]
        );
    }

    #[test]
    fn parse_pk_rejects_bad_lengths() {
        assert!(parse_pk(&[]).is_none());
        assert!(parse_pk(&[0u8; 16]).is_none());
        assert!(parse_pk(&[0u8; 33]).is_none());
    }
}
