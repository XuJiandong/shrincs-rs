//! SHRINCS parameters.
//!
//! This module models the three SHRINCS parameter sets as distinct Rust types
//! implementing a common [`Params`] trait. Because each parameter set is a
//! *different type*, `SHRINCS_L`, `SHRINCS_B`, and `SHRINCS_B32` can all be
//! used in the same binary without conflicting — exactly mirroring how the
//! C++ implementation selects a parameter set at compile time with
//! `-DSHRINCS_B` / `-DSHRINCS_L` / `-DSHRINCS_B32`.

// The marker type names intentionally mirror the upstream C++ macro names.
#![allow(non_camel_case_types)]

// SHRINCS targets little-endian platforms only.
#[cfg(target_endian = "big")]
compile_error!("SHRINCS only supports little-endian platforms");

/// Common trait implemented by every SHRINCS parameter set.
///
/// All length / count parameters are expressed as byte counts or element
/// counts and are `usize` so they index Rust slices directly.
pub trait Params {
    /// Security parameter (in **bytes**): the length of every hash digest,
    /// secret-key seed, and public-key seed. Always 16 for SHRINCS.
    const N: usize = 16;

    /// Randomness length (in **bytes**): the length of the per-signature
    /// randomizer `r` embedded in WOTS+C and PORS+FP signatures. Always 32.
    const R_LEN: usize = 32;

    /// Winternitz parameter: the base of the WOTS+C digit decomposition, i.e.
    /// the number of values a single chain covers. `W = 4` for SHRINCS-L and
    /// `W = 256` for SHRINCS-B / SHRINCS-B32.
    const W: usize;

    /// WOTS+C chain count: the number of Winternitz chains. This is derived
    /// so that `L * log2(W)` covers the `SWN` target sum. `L = 64` for
    /// SHRINCS-L and `L = 16` for SHRINCS-B / SHRINCS-B32.
    const L: usize;

    /// Target sum for the WOTS+C checksum: the grinding method iterates until
    /// the sum of all `L` base-`W` digits equals `SWN`. `SWN = 140` for
    /// SHRINCS-L and `SWN = 2040` for SHRINCS-B / SHRINCS-B32.
    const SWN: usize;

    /// Maximum **stateful** (UXMSS) tree height: the number of leaves in the
    /// stateful tree is `HSF + 1` (there is one extra leaf on the deepest
    /// right side). `HSF = 189` (L), `141` (B), `210` (B32).
    const HSF: usize;

    /// Maximum **stateless** hypertree height: the total height across all
    /// `D` layers of the stateless XMSS hypertree used to authenticate the
    /// PORS+FP public key. `HSL = 24` (L/B), `32` (B32).
    const HSL: usize;

    /// Stateless hypertree **layers**: the number of XMSS trees stacked in the
    /// stateless hypertree. `D = 2` (L/B), `4` (B32). Each layer has height
    /// [`Self::H_PRIME`].
    const D: usize;

    /// Number of secret values in the PORS+FP tree: the total number of leaves
    /// (secret values) in the stateless FORS-like tree. `T = 9245141` (L/B),
    /// `109571` (B32).
    const T: usize;

    /// PORS+FP tree **height**: `ceil(log2(T))`. `B = 24` (L/B), `17` (B32).
    const B: usize;

    /// Number of revealed PORS+FP tree leaves: how many distinct indices are
    /// selected from the XOF output and revealed with their authentication
    /// paths. `K = 6` (L/B), `11` (B32).
    const K: usize;

    /// Maximum size of the octopus authentication path: the upper bound on the
    /// number of sibling nodes revealed by the compressed PORS+FP octopus
    /// authentication. `M_MAX = 91` (L/B), `111` (B32).
    const M_MAX: usize;

    /// Grinding margin: a slack added to [`Self::XOF_OFFSET_BITS`] so that the
    /// probability of finding valid indices with a short octopus path is large
    /// enough. `MARGIN = 7` (L/B), `10` (B32).
    const MARGIN: usize;

    /// Height of one stateless layer: `HSL / D`. `H_PRIME = 12` (L/B), `8`
    /// (B32): each XMSS tree layer has `2^H_PRIME` leaves.
    const H_PRIME: usize = Self::HSL / Self::D;

    /// Total length (bytes) of a WOTS+C signature:
    /// `R_LEN` (the randomizer `r`) + 4 (the counter `ctr`) + `L * N` (the
    /// `L` chains, each an `N`-byte node).
    const WOTS_SIGN_LEN: usize = Self::R_LEN + 4 + Self::L * Self::N;

    /// Total length (bytes) of one XMSS signature: a WOTS+C signature plus an
    /// authentication path of `H_PRIME` nodes.
    const XMSS_SIGN_LEN: usize = Self::WOTS_SIGN_LEN + Self::H_PRIME * Self::N;

    /// Total length (bytes) of a PORS+FP signature:
    /// `R_LEN` (`r`) + `K * N` (revealed chain secrets) + `M_MAX * N`
    /// (the fixed-size octopus authentication path, zero-padded to maximum).
    const PORS_SIGN_LEN: usize = Self::R_LEN + (Self::K + Self::M_MAX) * Self::N;

    /// Maximum size (bytes) of a **stateful** signature: the `N`-byte `sl`
    /// prefix plus a full stateful tree signature at height `HSF`.
    const MAX_SF_SIZE: usize = Self::N + Self::WOTS_SIGN_LEN + Self::HSF * Self::N;

    /// Size (bytes) of a **stateless** signature: the `N`-byte `sf` prefix plus
    /// a PORS+FP signature plus `D` XMSS signatures.
    const SL_SIZE: usize = Self::N + Self::PORS_SIGN_LEN + Self::XMSS_SIGN_LEN * Self::D;

    /// Number of index candidates per XOF block: `c = 256 / B`. Each 32-byte
    /// XOF block yields `c` candidate `B`-bit indices.
    const C: usize = 256 / Self::B;

    /// Bit offset within the XOF output where the `HSL`-bit hypertree index is
    /// read. Equivalent to the C++ `xof_offset_bits`.
    const XOF_OFFSET_BITS: usize =
        (((1 << Self::B) * Self::K + Self::T - 1) / Self::T + Self::MARGIN) * Self::B + 16;

    /// Number of 32-byte XOF blocks that must be generated / stored, as
    /// computed by the C++ `xof_block_idx`. Selected indices are always fully
    /// contained within the first `XOF_BLOCK_IDX` blocks.
    const XOF_BLOCK_IDX: usize = (Self::XOF_OFFSET_BITS + 32 + 255) >> 8;
}

/// The SHRINCS-L parameter set (faster, larger signatures).
///
/// | param | value |
/// |-------|-------|
/// | W     | 4     |
/// | L     | 64    |
/// | SWN   | 140   |
/// | HSF   | 189   |
/// | HSL   | 24    |
/// | D     | 2     |
/// | T     | 9245141 |
/// | B     | 24    |
/// | K     | 6     |
/// | M_MAX | 91    |
/// | margin| 7     |
pub struct SHRINCS_L;

/// The SHRINCS-B parameter set (smaller signatures, slower).
///
/// | param | value |
/// |-------|-------|
/// | W     | 256   |
/// | L     | 16    |
/// | SWN   | 2040  |
/// | HSF   | 141   |
/// | HSL   | 24    |
/// | D     | 2     |
/// | T     | 9245141 |
/// | B     | 24    |
/// | K     | 6     |
/// | M_MAX | 91    |
/// | margin| 7     |
pub struct SHRINCS_B;

/// The SHRINCS-B32 parameter set (32-byte digests, 256-bit security).
///
/// | param | value   |
/// |-------|---------|
/// | W     | 256     |
/// | L     | 16      |
/// | SWN   | 2040    |
/// | HSF   | 210     |
/// | HSL   | 32      |
/// | D     | 4       |
/// | T     | 109571  |
/// | B     | 17      |
/// | K     | 11      |
/// | M_MAX | 111     |
/// | margin| 10      |
pub struct SHRINCS_B32;

impl Params for SHRINCS_L {
    const W: usize = 4;
    const L: usize = 64;
    const SWN: usize = 140;
    const HSF: usize = 189;
    const HSL: usize = 24;
    const D: usize = 2;
    const T: usize = 9245141;
    const B: usize = 24;
    const K: usize = 6;
    const M_MAX: usize = 91;
    const MARGIN: usize = 7;
}

impl Params for SHRINCS_B {
    const W: usize = 256;
    const L: usize = 16;
    const SWN: usize = 2040;
    const HSF: usize = 141;
    const HSL: usize = 24;
    const D: usize = 2;
    const T: usize = 9245141;
    const B: usize = 24;
    const K: usize = 6;
    const M_MAX: usize = 91;
    const MARGIN: usize = 7;
}

impl Params for SHRINCS_B32 {
    const W: usize = 256;
    const L: usize = 16;
    const SWN: usize = 2040;
    const HSF: usize = 210;
    const HSL: usize = 32;
    const D: usize = 4;
    const T: usize = 109571;
    const B: usize = 17;
    const K: usize = 11;
    const M_MAX: usize = 111;
    const MARGIN: usize = 10;
}

/// Address-type constants written into the `type` field of an address
/// ([`crate::address::Adrs`]) to domain-separate every hash input.
///
/// The low `0x00`–`0x05` block belongs to the **stateful** (UXMSS) tree, the
/// `0x06`–`0x0A` block to **PORS+FP**, the `0x0B`–`0x10` block to the
/// **stateless** (XMSS) hypertree, and `0x11` (`ROOT`) is the final top-level
/// public-key compression domain.
pub mod address_types {
    /// Stateful WOTS+C chain hash.
    pub const SF_WOTS_HASH: u32 = 0x00;
    /// Stateful WOTS+C public-key compression.
    pub const SF_WOTS_PK: u32 = 0x01;
    /// Stateful UXMSS tree compression.
    pub const SF_TREE: u32 = 0x02;
    /// Stateful WOTS+C digest grinding.
    pub const SF_WOTS_GRIND: u32 = 0x03;
    /// Stateful message-to-digest hashing.
    pub const SF_H_MSG: u32 = 0x04;
    /// Stateful WOTS+C secret-key PRF.
    pub const SF_WOTS_PRF: u32 = 0x05;
    /// PORS+FP leaf hash.
    pub const PORS_HASH: u32 = 0x06;
    /// PORS+FP tree compression.
    pub const PORS_TREE: u32 = 0x07;
    /// PORS+FP public-key compression.
    pub const PORS_PK: u32 = 0x08;
    /// PORS+FP secret-key PRF.
    pub const PORS_PRF: u32 = 0x09;
    /// PORS+FP index XOF.
    pub const PORS_XOF: u32 = 0x0A;
    /// Stateless WOTS+C chain hash.
    pub const SL_WOTS_HASH: u32 = 0x0B;
    /// Stateless WOTS+C public-key compression.
    pub const SL_WOTS_PK: u32 = 0x0C;
    /// Stateless XMSS tree compression.
    pub const SL_TREE: u32 = 0x0D;
    /// Stateless WOTS+C digest grinding.
    pub const SL_WOTS_GRIND: u32 = 0x0E;
    /// Stateless message-to-digest hashing.
    pub const SL_H_MSG: u32 = 0x0F;
    /// Stateless WOTS+C secret-key PRF.
    pub const SL_WOTS_PRF: u32 = 0x10;
    /// Top-level public-key compression.
    pub const ROOT: u32 = 0x11;
}
