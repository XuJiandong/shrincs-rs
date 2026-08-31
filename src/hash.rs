//! SHA-256 primitives built on top of [`ckb_opt_sha256`].
//!
//! The C++ implementation hashes through a *reusable base context*: it
//! pre-keys a `SHA256_CTX` with `pk_seed ‖ 32 zero bytes ‖ 16 zero bytes` (one
//! full 64-byte block) and then, for every subsequent hash, **copies** that
//! context, appends more data, and finalizes the copy — leaving the base
//! context untouched. This copy-and-finalize idiom is essential to matching
//! the reference implementation byte-for-byte.
//!
//! [`ckb_opt_sha256`] exposes an opaque, non-`Clone` [`Sha256`][ckb] whose
//! `finalize()` consumes its receiver, which is intentional but does not by
//! itself support the copy idiom. The crate also compiles its own C
//! `sha256_init` / `sha256_update` / `sha256_final` symbols into the final
//! binary; we bind those same symbols with a `#[repr(C)]` context that mirrors
//! the crate's internal layout and make it `Copy`, giving us exactly the
//! semantics the algorithm needs while still routing 100% of SHA-256 through
//! `ckb-opt-sha256`.
//!
//! [ckb]: ckb_opt_sha256::Sha256

use core::ffi::{c_uchar, c_uint, c_ulonglong};

#[cfg(feature = "std")]
use ckb_opt_sha256 as _;

/// SHA-256 context with the exact `#[repr(C)]` memory layout of the C
/// `SHA256_CTX` compiled by [`ckb_opt_sha256`]'s `build.rs`.
///
/// This is `Copy` so that callers can cheaply snapshot a base context and
/// finalize independent extensions of it, mirroring the C++
/// `sha256_add_to_ctx` / `sha256_finalize` helpers.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sha256Ctx {
    /// Buffered input bytes (un-processed partial block).
    pub data: [c_uchar; 64],
    /// Number of buffered bytes in `data`.
    pub datalen: c_uint,
    /// Total message length in bits, accumulated over full blocks.
    pub bitlen: c_ulonglong,
    /// The running 8-word digest state.
    pub state: [c_uint; 8],
}

// The exact `extern "C"` symbols shipped by `ckb-opt-sha256` (from its
// `src/sha256.c`, linked via its `build.rs`).
unsafe extern "C" {
    fn sha256_init(ctx: *mut Sha256Ctx);
    fn sha256_update(ctx: *mut Sha256Ctx, data: *const c_uchar, len: c_ulonglong);
    fn sha256_final(ctx: *mut Sha256Ctx, hash: *mut c_uchar);
}

impl Default for Sha256Ctx {
    fn default() -> Self {
        let mut ctx = Sha256Ctx {
            data: [0u8; 64],
            datalen: 0,
            bitlen: 0,
            state: [0u32; 8],
        };
        unsafe {
            sha256_init(&mut ctx);
        }
        ctx
    }
}

impl Sha256Ctx {
    /// A freshly initialized SHA-256 context.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Copy `self`, append `data`, and return the extended context.
    ///
    /// This is the faithful port of the C++ `sha256_add_to_ctx`.
    #[inline]
    pub fn add_to_ctx(&self, data: &[u8]) -> Self {
        let mut ctx = *self;
        unsafe {
            sha256_update(&mut ctx, data.as_ptr(), data.len() as c_ulonglong);
        }
        ctx
    }
}

/// Finalize a copy of `base_ctx` and copy the first `n` bytes into `out`.
///
/// The C++ `sha256_finalize` copies `N = 16` bytes; `sha256_finalize_32`
/// copies all 32. `n` must be `<= 32`. Finalizing a copy leaves `base_ctx`
/// usable for further hashing.
#[inline]
fn finalize_into(base_ctx: &Sha256Ctx, out: &mut [u8]) {
    let mut ctx = *base_ctx;
    let mut full = [0u8; 32];
    unsafe {
        sha256_final(&mut ctx, full.as_mut_ptr());
    }
    out.copy_from_slice(&full[..out.len()]);
}

/// Finalize a copy of `base_ctx` and write `N = 16` bytes to `out`.
///
/// Port of C++ `sha256_finalize`. `out` must be at least 16 bytes; only the
/// first 16 are written.
#[inline]
pub fn sha256_finalize(base_ctx: &Sha256Ctx, out: &mut [u8]) {
    assert!(out.len() >= 16);
    finalize_into(base_ctx, &mut out[..16]);
}

/// Finalize a copy of `base_ctx` and write all 32 bytes to `out`.
///
/// Port of C++ `sha256_finalize_32`. `out` must be at least 32 bytes.
#[inline]
pub fn sha256_finalize_32(base_ctx: &Sha256Ctx, out: &mut [u8]) {
    assert!(out.len() >= 32);
    finalize_into(base_ctx, &mut out[..32]);
}

/// Port of the C++ `prf_msg` pseudorandom function.
///
/// Computes `H(sk_prf ‖ pk_seed ‖ opt_rand ‖ [ctr_be] ‖ message ‖ i_be)` for
/// `i = 0, 1, ...` until `mask_len` bytes have been produced, writing at most
/// `mask_len` bytes total into `out`.
///
/// # Panics
/// Panics if `out.len() < mask_len`.
pub fn prf_msg(
    sk_prf: &[u8],
    pk_seed: &[u8],
    opt_rand: &[u8],
    message: &[u8],
    is_ctr: bool,
    ctr: u32,
    mask_len: usize,
    out: &mut [u8],
) {
    assert!(out.len() >= mask_len, "prf_msg output buffer too small");

    let mut ctx = Sha256Ctx::new()
        .add_to_ctx(sk_prf)
        .add_to_ctx(pk_seed)
        .add_to_ctx(opt_rand);
    if is_ctr {
        ctx = ctx.add_to_ctx(&ctr.to_be_bytes());
    }
    ctx = ctx.add_to_ctx(message);

    let mut hash = [0u8; 32];
    let mut produced = 0usize;
    let mut i: u32 = 0;
    while produced < mask_len {
        let ctx_i = ctx.add_to_ctx(&i.to_be_bytes());
        sha256_finalize_32(&ctx_i, &mut hash);
        let take = core::cmp::min(32, mask_len - produced);
        out[produced..produced + take].copy_from_slice(&hash[..take]);
        produced += take;
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The copyable FFI context must agree with the opaque `ckb-opt-sha256`
    /// `sha256` one-shot API on the standard vectors.
    #[test]
    fn matches_ckb_opt_sha256() {
        let cases: &[&[u8]] = &[
            b"",
            b"hello world",
            b"Hello, World!",
            &[0x01u8; 57],
            &[
                0xde, 0x18, 0x89, 0x41, 0xa3, 0x37, 0x5d, 0x3a, 0x8a, 0x06, 0x1e, 0x67, 0x57, 0x6e,
                0x92, 0x6d,
            ],
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ];
        for msg in cases {
            let mut out = [0u8; 32];
            let ctx = Sha256Ctx::new().add_to_ctx(msg);
            sha256_finalize_32(&ctx, &mut out);
            assert_eq!(out, ckb_opt_sha256::sha256(msg), "mismatch for {msg:02x?}");
        }
    }

    /// Copy semantics: extending two independent copies of one base context
    /// must not interfere.
    #[test]
    fn copy_semantics() {
        let base = Sha256Ctx::new().add_to_ctx(&[0x41u8; 64]);
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        sha256_finalize_32(&base.add_to_ctx(b"X"), &mut a);
        sha256_finalize_32(&base.add_to_ctx(b"Y"), &mut b);
        assert_ne!(a, b);

        // The base context must still be usable after both finalizations.
        let mut c = [0u8; 32];
        sha256_finalize_32(&base.add_to_ctx(b"X"), &mut c);
        assert_eq!(a, c);
    }
}
