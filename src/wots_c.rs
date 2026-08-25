//! WOTS+C (Winternitz One-Time Signature with Checksum).
//!
//! This module implements the WOTS+C one-time signature scheme used both by
//! the stateful UXMSS tree and the stateless XMSS hypertree (and internally by
//! each XMSS layer). All functions are generic over [`Params`], reading
//! parameters as runtime values (the universal sizes `N = 16` and `R_LEN = 32`
//! are fixed array types; variant-specific lengths use `Vec`).

use alloc::vec;
use alloc::vec::Vec;

use crate::address::*;
use crate::constants::address_types::*;
use crate::constants::Params;
#[cfg(feature = "std")]
use crate::hash::prf_msg;
use crate::hash::{sha256_finalize, Sha256Ctx};

/// A 16-byte hash node (the universal digest length `N`).
pub type Node = [u8; 16];

/// Error raised when WOTS+C signature/verification operations fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The recomputed WOTS+C message digest did not satisfy the target sum.
    DigestInvalid,
    /// The (theoretically unreachable) grind search failed to find a valid digest.
    GrindFailed,
}

/// Decompose `message` into `L` base-`W` digits, packed MSB-first.
///
/// Faithful port of the C++ `base_w`: consumes `log2(W)` bits at a time
/// (MSB-first within each byte) and emits each digit masked with `W - 1`.
pub fn base_w<P: Params>(message: &[u8], out: &mut [u8]) {
    let w_log = P::W.trailing_zeros() as i32;
    let w_mod = P::W as i32 - 1;

    let mut in_idx = 0usize;
    let mut bits: i32 = 0;
    let mut total: i32 = 0;

    for out_byte in out.iter_mut().take(P::L) {
        if bits == 0 {
            total = message[in_idx] as i32;
            in_idx += 1;
            bits = 8;
        }
        bits -= w_log;
        *out_byte = ((total >> bits) & w_mod) as u8;
    }
}

/// Apply `steps` consecutive chain hashes to `m`, starting at chain `start`.
///
/// Each step hashes `adrs(with hash = index) ‖ node`. Port of C++ `chain`.
pub fn chain<P: Params>(
    m: &Node,
    start: u32,
    steps: u32,
    hash_ctx: &Sha256Ctx,
    adrs: &mut Adrs,
    out: &mut Node,
) {
    out.copy_from_slice(m);
    for i in start..start + steps {
        set_hash_address(adrs, i);
        let ctx = hash_ctx.add_to_ctx(adrs).add_to_ctx(out);
        sha256_finalize(&ctx, out);
    }
}

/// Select the three WOTS+C address types for the stateful (`sf == true`) or
/// stateless (`sf == false`) domain.
#[inline]
fn types(sf: bool) -> (u32, u32, u32) {
    if sf {
        (SF_WOTS_HASH, SF_WOTS_PK, SF_WOTS_PRF)
    } else {
        (SL_WOTS_HASH, SL_WOTS_PK, SL_WOTS_PRF)
    }
}

/// Generate the WOTS+C public key for `keypair`. Signing-only (`std`).
#[cfg(feature = "std")]
pub fn wots_pk_gen<P: Params>(
    sk_seed: &[u8],
    hash_ctx: &Sha256Ctx,
    adrs: &mut Adrs,
    keypair: u32,
    sf: bool,
) -> Node {
    let (wots_hash, wots_pk, wots_prf) = types(sf);
    let steps = (P::W - 1) as u32;

    let mut sk_i = Node::default();
    let mut pk_nodes = Vec::with_capacity(P::L * P::N);

    for i in 0..P::L {
        set_type_and_clear(adrs, wots_prf);
        set_key_pair_address(adrs, keypair);
        set_chain_address(adrs, i as u32);
        let ctx = hash_ctx.add_to_ctx(adrs).add_to_ctx(sk_seed);
        sha256_finalize(&ctx, &mut sk_i);

        set_type_and_clear(adrs, wots_hash);
        set_key_pair_address(adrs, keypair);
        set_chain_address(adrs, i as u32);
        let mut node = Node::default();
        chain::<P>(&sk_i, 0, steps, hash_ctx, adrs, &mut node);
        pk_nodes.extend_from_slice(&node);
    }

    set_type_and_clear(adrs, wots_pk);
    set_key_pair_address(adrs, keypair);
    let ctx = hash_ctx.add_to_ctx(adrs).add_to_ctx(&pk_nodes);
    let mut res = Node::default();
    sha256_finalize(&ctx, &mut res);
    res
}

/// Grind for a valid WOTS+C message digest (multi-threaded, `std` only).
///
/// Returns `(ctr, digits)` where `digits` has `L` bytes. Port of `wots_grind`.
#[cfg(feature = "std")]
pub fn wots_grind<P: Params>(
    message: &[u8],
    hash_ctx: &Sha256Ctx,
    adrs: &mut Adrs,
    keypair: u32,
    sf: bool,
) -> Result<(u32, Vec<u8>), Error> {
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;

    let grind_type = if sf { SF_WOTS_GRIND } else { SL_WOTS_GRIND };

    set_type_and_clear(adrs, grind_type);
    set_key_pair_address(adrs, keypair);
    let ctx = hash_ctx.add_to_ctx(adrs).add_to_ctx(message);

    let current_ctr = Arc::new(AtomicU64::new(0));
    let found = Arc::new(AtomicBool::new(false));
    let result_ctr = Arc::new(AtomicU64::new(0));

    let num_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    let mut threads = Vec::with_capacity(num_threads);
    for _ in 0..num_threads {
        let current_ctr = Arc::clone(&current_ctr);
        let found = Arc::clone(&found);
        let result_ctr = Arc::clone(&result_ctr);
        threads.push(std::thread::spawn(move || {
            let mut res = Node::default();
            let mut tmp_msg = vec![0u8; P::L];
            loop {
                if found.load(Ordering::Relaxed) {
                    break;
                }
                let ctr = current_ctr.fetch_add(1, Ordering::Relaxed);
                if ctr > u32::MAX as u64 {
                    break;
                }
                let ctx_ = ctx.add_to_ctx(&(ctr as u32).to_be_bytes());
                sha256_finalize(&ctx_, &mut res);
                base_w::<P>(&res, &mut tmp_msg);
                let sum: u32 = tmp_msg.iter().map(|&b| b as u32).sum();
                if sum == P::SWN as u32 {
                    if found
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                        .is_ok()
                    {
                        result_ctr.store(ctr, Ordering::Relaxed);
                    }
                    break;
                }
            }
        }));
    }

    for t in threads {
        let _ = t.join();
    }

    if found.load(Ordering::Relaxed) {
        let ctr = result_ctr.load(Ordering::Relaxed) as u32;
        let mut res = Node::default();
        let ctx_ = ctx.add_to_ctx(&ctr.to_be_bytes());
        sha256_finalize(&ctx_, &mut res);
        let mut digits = vec![0u8; P::L];
        base_w::<P>(&res, &mut digits);
        return Ok((ctr, digits));
    }

    Err(Error::GrindFailed)
}

/// Recompute and validate the WOTS+C digest for a single counter (`no_std`).
///
/// Returns `Some(digits)` (an `L`-byte `Vec`) when the digit sum equals `SWN`.
pub fn wots_digest<P: Params>(
    message: &[u8],
    hash_ctx: &Sha256Ctx,
    ctr: u32,
    adrs: &mut Adrs,
    keypair: u32,
    sf: bool,
) -> Option<Vec<u8>> {
    let grind_type = if sf { SF_WOTS_GRIND } else { SL_WOTS_GRIND };

    set_type_and_clear(adrs, grind_type);
    set_key_pair_address(adrs, keypair);

    let ctx = hash_ctx
        .add_to_ctx(adrs)
        .add_to_ctx(message)
        .add_to_ctx(&ctr.to_be_bytes());

    let mut res = Node::default();
    sha256_finalize(&ctx, &mut res);

    let mut msg = vec![0u8; P::L];
    base_w::<P>(&res, &mut msg);

    let sum: u32 = msg.iter().map(|&b| b as u32).sum();
    if sum == P::SWN as u32 {
        Some(msg)
    } else {
        None
    }
}

/// Sign `message`, returning a WOTS+C signature of `WOTS_SIGN_LEN` bytes.
///
/// When `is_internal` the message is used directly as the digest (XMSS
/// chaining); otherwise hashed under the `H_MSG` domain. Signing-only.
#[cfg(feature = "std")]
pub fn wots_sign<P: Params>(
    message: &[u8],
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    hash_ctx: &Sha256Ctx,
    adrs: &mut Adrs,
    keypair: u32,
    sf: bool,
    is_internal: bool,
) -> Result<Vec<u8>, Error> {
    let (wots_hash, _wots_pk, wots_prf) = types(sf);
    let h_msg_type = if sf { SF_H_MSG } else { SL_H_MSG };

    let opt_rand = pk_seed;

    let mut sig = vec![0u8; P::WOTS_SIGN_LEN];

    let mut r = [0u8; 32];
    prf_msg(
        sk_prf,
        pk_seed,
        opt_rand,
        message,
        false,
        0,
        P::R_LEN,
        &mut r,
    );

    let mut digest = Node::default();
    if is_internal {
        digest.copy_from_slice(&message[..P::N]);
    } else {
        set_type_and_clear(adrs, h_msg_type);
        let ctx = hash_ctx
            .add_to_ctx(adrs)
            .add_to_ctx(&r)
            .add_to_ctx(pk_root)
            .add_to_ctx(message);
        sha256_finalize(&ctx, &mut digest);
    }

    let (ctr, msg) = wots_grind::<P>(&digest, hash_ctx, adrs, keypair, sf)?;

    sig[..P::R_LEN].copy_from_slice(&r);
    let mut offset = P::R_LEN;
    sig[offset..offset + 4].copy_from_slice(&ctr.to_be_bytes());
    offset += 4;

    for (i, &msg_digit) in msg.iter().enumerate().take(P::L) {
        set_type_and_clear(adrs, wots_prf);
        set_key_pair_address(adrs, keypair);
        set_chain_address(adrs, i as u32);
        let ctx = hash_ctx.add_to_ctx(adrs).add_to_ctx(sk_seed);
        let mut sk_i = Node::default();
        sha256_finalize(&ctx, &mut sk_i);

        set_type_and_clear(adrs, wots_hash);
        set_key_pair_address(adrs, keypair);
        set_chain_address(adrs, i as u32);
        let mut tmp = Node::default();
        chain::<P>(&sk_i, 0, msg_digit as u32, hash_ctx, adrs, &mut tmp);
        sig[offset..offset + P::N].copy_from_slice(&tmp);
        offset += P::N;
    }

    Ok(sig)
}

/// Recover the WOTS+C public key from a signature (verification, `no_std`).
///
/// Returns `Err(DigestInvalid)` when the digest sum check fails. Port of C++
/// `wots_pk_from_sig`.
pub fn wots_pk_from_sig<P: Params>(
    sig: &[u8],
    message: &[u8],
    pk_root: &[u8],
    hash_ctx: &Sha256Ctx,
    adrs: &mut Adrs,
    keypair: u32,
    sf: bool,
    is_internal: bool,
) -> Result<Node, Error> {
    let (wots_hash, wots_pk, _wots_prf) = types(sf);
    let h_msg_type = if sf { SF_H_MSG } else { SL_H_MSG };

    // NOTE: `r` is read to bound the signature layout, but for *internal*
    // signatures (XMSS hypertree chaining) the digest is the raw chained
    // message and `r` is not cryptographically bound — matching the C++
    // reference exactly.
    let mut r = [0u8; 32];
    r.copy_from_slice(&sig[..P::R_LEN]);
    let offset0 = P::R_LEN;

    let ctr = u32::from_be_bytes(sig[offset0..offset0 + 4].try_into().unwrap());
    let mut offset = offset0 + 4;

    let mut digest = Node::default();
    if is_internal {
        digest.copy_from_slice(&message[..P::N]);
    } else {
        set_type_and_clear(adrs, h_msg_type);
        let ctx = hash_ctx
            .add_to_ctx(adrs)
            .add_to_ctx(&r)
            .add_to_ctx(pk_root)
            .add_to_ctx(message);
        sha256_finalize(&ctx, &mut digest);
    }

    let msg =
        wots_digest::<P>(&digest, hash_ctx, ctr, adrs, keypair, sf).ok_or(Error::DigestInvalid)?;

    let to_step = (P::W - 1) as u32;
    let mut pk_nodes = Vec::with_capacity(P::L * P::N);
    let mut sig_i = Node::default();
    for (i, &msg_digit) in msg.iter().enumerate().take(P::L) {
        set_type_and_clear(adrs, wots_hash);
        set_key_pair_address(adrs, keypair);
        set_chain_address(adrs, i as u32);

        sig_i.copy_from_slice(&sig[offset..offset + P::N]);
        offset += P::N;

        let mut pk_i = Node::default();
        chain::<P>(
            &sig_i,
            msg_digit as u32,
            to_step - msg_digit as u32,
            hash_ctx,
            adrs,
            &mut pk_i,
        );
        pk_nodes.extend_from_slice(&pk_i);
    }

    set_type_and_clear(adrs, wots_pk);
    set_key_pair_address(adrs, keypair);
    let ctx = hash_ctx.add_to_ctx(adrs).add_to_ctx(&pk_nodes);
    let mut res = Node::default();
    sha256_finalize(&ctx, &mut res);
    Ok(res)
}
