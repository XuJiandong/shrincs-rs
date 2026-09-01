# SHRINCS (Rust)

Rust implementation of the [SHRINCS](https://github.com/BlockstreamResearch/shrincs-specification)
post-quantum signature scheme, ported from the
[C++ implementation](https://github.com/BlockstreamResearch/shrincs).

> ⚠️ **This project is a work in progress and is provided as-is for research,
> learning, and experimentation.** It is not production-ready and has not
> undergone a formal security audit.

### Parameter sets

Three parameter sets coexist as distinct marker types implementing
[`Params`](shrincs::constants::Params):

* [`SHRINCS_L`](shrincs::SHRINCS_L)
* [`SHRINCS_B`](shrincs::SHRINCS_B)
* [`SHRINCS_B32`](shrincs::SHRINCS_B32)

[`SHRINCS_B`](shrincs::SHRINCS_B) is the recommended default: it has the
smallest signature size of the three parameter sets.

### `no_std` verification / `std` signing

The crate is `#![no_std]` with an optional `std` feature (on by default):

* **Verification** (`shrincs::verify`, `verify_stateful`, `verify_stateless`
  and their dependency graph) compiles and runs under `no_std` (with `alloc`).
* **Signing** (`key_gen`, `sign_stateful`, `sign_stateless`, key derivation
  `restore`) requires `std` for OS randomness and multi-threaded digest
  grinding.

## Usage

```rust
use shrincs::{shrincs, Params, SHRINCS_B};

let mut pk = shrincs::PublicKey::default();
let mut sk = shrincs::SecretKey::default();
let mut state = shrincs::State::default();

// Generate keys (std)
shrincs::key_gen::<SHRINCS_B>(&mut pk, &mut sk, &mut state).unwrap();

let msg = b"hello world";

// Stateful signature
let sig = shrincs::sign_stateful::<SHRINCS_B>(msg, &mut sk, &mut state).unwrap();
assert!(shrincs::verify::<SHRINCS_B>(msg, &sig, &pk));

// Stateless signature
let sig = shrincs::sign_stateless::<SHRINCS_B>(msg, &sk).unwrap();
assert!(shrincs::verify::<SHRINCS_B>(msg, &sig, &pk));

// Restore from a 48-byte seed
let seed = [0x42u8; 48];
shrincs::restore::<SHRINCS_B>(&seed, &mut pk, &mut sk, &mut state);
```

## Fast stateless signing (`prepare`)

A plain [`sign_stateless`](shrincs::sign_stateless) call is quite slow. If you
sign many messages with the same key pair, precompute that work once and reuse
it to speed things up:

```rust
use shrincs::{Params, SHRINCS_B};

let mut pk = shrincs::PublicKey::default();
let mut sk = shrincs::SecretKey::default();
let mut state = shrincs::State::default();
shrincs::key_gen::<SHRINCS_B>(&mut pk, &mut sk, &mut state).unwrap();

// Build once per key pair (deterministic; depends only on the seeds in `sk`).
let prepared = shrincs::sign_stateless_prepare::<SHRINCS_B>(&sk);

// Optionally serialize/persist it, then load it back later.
let bytes = prepared.to_bytes(); // 8,708 bytes for all parameter sets
let loaded = shrincs::PreparedStatelessKey::<SHRINCS_B>::from_bytes(&bytes).unwrap();

// Reuse the prepared cache across any number of messages.
let msg = b"hello world";
let sig = shrincs::sign_stateless_with_prepare::<SHRINCS_B>(msg, &sk, &loaded).unwrap();
assert!(shrincs::verify::<SHRINCS_B>(msg, &sig, &pk));
```

Notes:

* [`sign_stateless_with_prepare`](shrincs::sign_stateless_with_prepare)
  produces a signature **byte-identical** to [`sign_stateless`](shrincs::sign_stateless)
  for the same message and key — it only skips the message-independent tree
  reconstruction.
* The cache is message-independent and tied to the key pair: rebuild it after
  any key change. A cache from a different key pair yields a wrong result, not
  an error — pass it the matching `sk`.

## SHA-256

SHA-256 is provided exclusively by
[`ckb-opt-sha256`](https://crates.io/crates/ckb-opt-sha256) (the optimized
SHA-256 implementation for CKB-VM). 

## Testing

```bash
cargo test --release        # unit tests + tests/ (KAT suites excluded by default)
cargo build --no-default-features --target riscv64imac-unknown-none-elf  # no_std on a bare-metal target
```

The KAT suites (`tests/kat.rs`) are **not** run by default: they are gated
behind the `kat-tests` cargo feature and must be enabled explicitly:

```bash
cargo test --release --features kat-tests  # KAT pass/fail suites (all 3 parameter sets)
```

> ⚠️ **Warning: the KAT suites are very slow.** They sign and verify hundreds
> of messages across all three parameter sets, so a full run can take a very long time (a
> `--release` build is strongly recommended; debug builds are far worse).
> Only enable `kat-tests` when you specifically want the full known-answer
> validation.

## License

MIT (as the upstream C++ implementation).
