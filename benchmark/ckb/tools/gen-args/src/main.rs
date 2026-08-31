//! SHRINCS test-vector generator for the CKB on-chain benchmark.
//!
//! Produces the three hex arguments consumed by
//! `contracts/test-shrincs` (via `ckb-debugger --bin test-shrincs ...`):
//!
//!   <message> <signature> <pubkey>
//!
//! For a chosen parameter set it can emit either a **stateful** signature
//! (short, `sl`-based, with a state counter `q`) or a **stateless** signature
//! (long, `sf`-based). Key material is deterministic: `shrincs::restore` is
//! seeded from a fixed 48-byte master seed, so outputs are reproducible.
//!
//! Usage:
//!   gen-shrincs-args --param B --stateful --q 1 [--seed <48-byte hex>] [--msg-hex <hex>]
//!   gen-shrincs-args --param B --stateless [--seed <48-byte hex>] [--msg-hex <hex>]
//!
//! Output is a single line of three space-separated hex fields, which can be
//! passed directly to ckb-debugger:
//!   gen-shrincs-args --stateful | xargs ckb-debugger --bin build/release/test-shrincs

// The library crate (`shrincs_rs`) and the `shrincs` module share a name; bind
// the crate root explicitly so `shrincs::…` paths refer to the library root.
extern crate shrincs_rs as shrincs;
use shrincs::shrincs as shrincs_api;
use shrincs::{PublicKey, SecretKey, State, SHRINCS_B, SHRINCS_B32, SHRINCS_L};

/// SHRINCS parameter sets and their generator implementations.
#[derive(Clone, Copy)]
enum Param {
    B,
    B32,
    L,
}

// A fixed 48-byte master seed, so outputs are deterministic across runs.
const DEFAULT_SEED: &[u8; 48] = b"shrincs-benchmark-seed-0000000000000000000000000";

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks(2) {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn encode_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn parse_seed(hex: &str) -> [u8; 48] {
    let bytes = decode_hex(hex).expect("invalid seed hex");
    assert_eq!(bytes.len(), 48, "seed must be 48 bytes (96 hex chars)");
    let mut seed = [0u8; 48];
    seed.copy_from_slice(&bytes);
    seed
}

/// Restore a key pair for the chosen parameter set and emit its three args.
fn emit<P: shrincs::constants::Params>(
    seed: &[u8; 48],
    msg: &[u8],
    stateful: bool,
    q: u32,
) {
    let mut pk = PublicKey::default();
    let mut sk = SecretKey::default();
    let mut state = State::default();
    shrincs_api::restore::<P>(seed, &mut pk, &mut sk, &mut state);
    state.valid = true;

    let sig = if stateful {
        // Advance the counter first so the produced signature matches the
        // requested q (the auth path length encodes q).
        state.q = q - 1;
        shrincs_api::sign_stateful::<P>(msg, &mut sk, &mut state).expect("stateful sign")
    } else {
        shrincs_api::sign_stateless::<P>(msg, &sk).expect("stateless sign")
    };

    // Public key serialized as seed ‖ root (32 bytes).
    let mut pk_bytes = [0u8; 32];
    pk_bytes[..16].copy_from_slice(&pk.seed);
    pk_bytes[16..].copy_from_slice(&pk.root);

    println!(
        "{} {} {}",
        encode_hex(msg),
        encode_hex(&sig),
        encode_hex(&pk_bytes),
    );
}

fn main() {
    let args = std::env::args().skip(1);
    let mut param = Param::B;
    let mut stateful = true;
    let mut q: u32 = 1;
    let mut seed = DEFAULT_SEED.clone();
    let mut msg: Vec<u8> = b"hello shrincs benchmark".to_vec();

    let mut it = args.peekable();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--param" => {
                param = match it.next().expect("--param needs a value").as_str() {
                    "B" => Param::B,
                    "B32" => Param::B32,
                    "L" => Param::L,
                    other => panic!("unknown param set: {other} (expected B, B32, or L)"),
                }
            }
            "--stateful" => stateful = true,
            "--stateless" => stateful = false,
            "--q" => q = it.next().expect("--q needs a value").parse().expect("invalid q"),
            "--seed" => seed = parse_seed(&it.next().expect("--seed needs a value")),
            "--msg-hex" => {
                msg = decode_hex(&it.next().expect("--msg-hex needs a value"))
                    .expect("invalid --msg-hex")
            }
            other => {
                eprintln!("unknown option: {other}");
                std::process::exit(2);
            }
        }
        let _ = it.peek();
    }

    match param {
        Param::B => emit::<SHRINCS_B>(&seed, &msg, stateful, q),
        Param::B32 => emit::<SHRINCS_B32>(&seed, &msg, stateful, q),
        Param::L => emit::<SHRINCS_L>(&seed, &msg, stateful, q),
    }
}
