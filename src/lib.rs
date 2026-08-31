//! # SHRINCS
//!
//! Rust implementation of the [SHRINCS](https://github.com/BlockstreamResearch/shrincs-specification)
//! post-quantum signature scheme, ported from the C++ implementation.
//!
//! The crate is split along an important axis:
//!
//! * **Verification** (everything reachable from [`shrincs::verify`]) is
//!   `no_std`-compatible and performs no heap allocation when built without
//!   the `std` feature.
//! * **Signing** (key generation and signature production) requires `std`
//!   because it uses OS randomness ([`getrandom`]) and multi-threaded digest
//!   grinding.
//!
//! # Parameter sets
//!
//! Three parameter sets are provided as distinct marker types implementing
//! [`Params`]: [`SHRINCS_L`], [`SHRINCS_B`], and [`SHRINCS_B32`]. Because each
//! is a separate type, all three coexist in a single binary and may be used
//! simultaneously. [`SHRINCS_B`] is the recommended default: it has the
//! smallest signature size of the three parameter sets.
//!
//! # Example
//!
//! ```ignore
//! use shrincs::{constants::Params, shrincs, SHRINCS_B};
//!
//! let mut pk = shrincs::PublicKey::default();
//! let mut sk = shrincs::SecretKey::default();
//! let mut state = shrincs::State::default();
//!
//! shrincs::key_gen::<SHRINCS_B>(&mut pk, &mut sk, &mut state).unwrap();
//!
//! let msg = b"hello world";
//! let sig = shrincs::sign_stateful::<SHRINCS_B>(msg, &mut sk, &mut state).unwrap();
//! assert!(shrincs::verify::<SHRINCS_B>(msg, &sig, &pk));
//! ```

#![no_std]
// Many functions mirror the C++ signatures one-for-one, which legitimately
// take several arguments (e.g. all the WOTS/XMSS/UXMSS seed parameters).
#![allow(clippy::too_many_arguments)]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

pub mod address;
pub mod constants;
pub mod hash;
pub mod pors_fp;
pub mod shrincs;
pub mod uxmss;
pub mod wots_c;
pub mod xmss;

#[cfg(feature = "std")]
pub mod rng;

pub use constants::{Params, SHRINCS_B, SHRINCS_B32, SHRINCS_L, address_types};

// Re-export the top-level API at the crate root so callers can write
// `shrincs::key_gen::<SHRINCS_B>(…)` instead of `shrincs::shrincs::key_gen(…)`.
pub use shrincs::{PublicKey, SecretKey, State, verify, verify_stateful, verify_stateless};
#[cfg(feature = "std")]
pub use shrincs::{key_gen, restore, sign_stateful, sign_stateless};
