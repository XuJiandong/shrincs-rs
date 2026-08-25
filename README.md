# SHRINCS (Rust)

Rust implementation of the [SHRINCS](https://github.com/BlockstreamResearch/shrincs-specification)
post-quantum signature scheme, ported from the
[C++ implementation](https://github.com/BlockstreamResearch/shrincs).

> ⚠️ **This project is a work in progress and is provided as-is for research,
> learning, and experimentation.** It is not production-ready and has not
> undergone a formal security audit.

## Design

The crate mirrors the C++ module layout, with one Rust module per C++ file:

| C++ file            | Rust module       |
|---------------------|-------------------|
| `constants.h`       | `shrincs::constants` |
| `address.h/.cpp`    | `shrincs::address`   |
| `hash.h/.cpp`       | `shrincs::hash`      |
| `wots_c.h/.cpp`     | `shrincs::wots_c`    |
| `xmss.h/.cpp`       | `shrincs::xmss`      |
| `uxmss.h/.cpp`      | `shrincs::uxmss`     |
| `pors_fp.h/.cpp`    | `shrincs::pors_fp`   |
| `shrincs.h/.cpp`    | `shrincs::shrincs`   |
| `rng.c/.h` (kat)    | `shrincs::rng`       |

### Parameter sets

Three parameter sets coexist as distinct marker types implementing
[`Params`](shrincs::constants::Params):

* [`SHRINCS_L`](shrincs::SHRINCS_L)
* [`SHRINCS_B`](shrincs::SHRINCS_B)
* [`SHRINCS_B32`](shrincs::SHRINCS_B32)

Every parameter (`W`, `L`, `SWN`, `HSF`, `HSL`, `D`, `T`, `B`, `K`, `M_MAX`,
`H_PRIME`, and the derived signature sizes) is documented in
`src/constants.rs`.

### `no_std` verification / `std` signing

The crate is `#![no_std]` with an optional `std` feature (on by default):

* **Verification** (`shrincs::verify`, `verify_stateful`, `verify_stateless`
  and their dependency graph) compiles and runs under `no_std` (with `alloc`).
* **Signing** (`key_gen`, `sign_stateful`, `sign_stateless`, key derivation
  `restore`) requires `std` for OS randomness and multi-threaded digest
  grinding.

```toml
shrincs = { path = ".", default-features = false } # verification only
```

## Usage

```rust
use shrincs::{shrincs, Params, SHRINCS_L};

let mut pk = shrincs::PublicKey::default();
let mut sk = shrincs::SecretKey::default();
let mut state = shrincs::State::default();

// Generate keys (std)
shrincs::key_gen::<SHRINCS_L>(&mut pk, &mut sk, &mut state).unwrap();

let msg = b"hello world";

// Stateful signature
let sig = shrincs::sign_stateful::<SHRINCS_L>(msg, &mut sk, &mut state).unwrap();
assert!(shrincs::verify::<SHRINCS_L>(msg, &sig, &pk));

// Stateless signature
let sig = shrincs::sign_stateless::<SHRINCS_L>(msg, &sk).unwrap();
assert!(shrincs::verify::<SHRINCS_L>(msg, &sig, &pk));

// Restore from a 48-byte seed (deterministic, for KATs)
let seed = [0x42u8; 48];
shrincs::restore::<SHRINCS_L>(&seed, &mut pk, &mut sk, &mut state);
```

## SHA-256

SHA-256 is provided exclusively by
[`ckb-opt-sha256`](https://crates.io/crates/ckb-opt-sha256) (the optimized
SHA-256 implementation for CKB-VM). The code binds the C `sha256_init` /
`sha256_update` / `sha256_final` symbols shipped by that crate through a
`#[repr(C)]` `Copy` context, reproducing the reference implementation's
"copy a pre-keyed base context, append, finalize" idiom byte-for-byte.

## Testing

```bash
cargo test --release        # unit tests + tests/ + KAT suites (all 3 parameter sets)
cargo build --no-default-features  # no_std verification surface
```

The test suite ports:

* `tests/tests.cpp` → `tests/tests.rs` (WOTS/XMSS/UXMSS round-trips,
  `extract_bits`, stateful & stateless sign/verify).
* `kat/kat_gen_pass.cpp`, `kat/kat_gen_fail.cpp`, `kat/truncation_bug_demo.cpp`,
  and `kat/rng.c` → `tests/kat.rs` + `src/rng.rs` (deterministic AES-256-CTR
  known-answer pass/fail suites).

## License

MIT (as the upstream C++ implementation).
