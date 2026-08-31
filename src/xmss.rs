//! XMSS (eXtended Merkle Signature Scheme) — one layer of the stateless
//! hypertree.
//!
//! Each XMSS tree has height [`Params::H_PRIME`] with a WOTS+C key pair at each
//! leaf. Tree construction and signing require `std`; `xmss_pk_from_sig` is
//! `no_std`-safe and used by verification.

#[cfg(feature = "std")]
use alloc::vec::Vec;

use crate::address::*;
use crate::constants::Params;
use crate::constants::address_types::SL_TREE;
use crate::hash::{Sha256Ctx, sha256_finalize};
use crate::wots_c::{self, Node};

/// Recursively build the subtree of `target_height` at `start_idx`.
/// Signing-only (`std`). Port of C++ `xmss_treehash`.
#[cfg(feature = "std")]
pub fn xmss_treehash<P: Params>(
    sk_seed: &[u8],
    hash_ctx: &Sha256Ctx,
    adrs: &mut Adrs,
    target_height: u32,
    start_idx: u32,
) -> Node {
    if target_height == 0 {
        return wots_c::wots_pk_gen::<P>(sk_seed, hash_ctx, adrs, start_idx, false);
    }

    let left = xmss_treehash::<P>(sk_seed, hash_ctx, adrs, target_height - 1, start_idx);
    let right = xmss_treehash::<P>(
        sk_seed,
        hash_ctx,
        adrs,
        target_height - 1,
        start_idx + (1u32 << (target_height - 1)),
    );

    set_type_and_clear(adrs, SL_TREE);
    set_tree_height(adrs, target_height);
    set_tree_index(adrs, start_idx >> target_height);

    let ctx = hash_ctx
        .add_to_ctx(adrs)
        .add_to_ctx(&left)
        .add_to_ctx(&right);
    let mut res = Node::default();
    sha256_finalize(&ctx, &mut res);
    res
}

/// Root of a full `h_prime`-high XMSS tree. Signing-only (`std`).
#[cfg(feature = "std")]
pub fn xmss_root<P: Params>(
    sk_seed: &[u8],
    hash_ctx: &Sha256Ctx,
    adrs: &mut Adrs,
    h_prime: u32,
) -> Node {
    xmss_treehash::<P>(sk_seed, hash_ctx, adrs, h_prime, 0)
}

/// Authentication path (one sibling per level) for leaf `idx`.
/// Signing-only (`std`). Returns `h_prime * N` bytes.
#[cfg(feature = "std")]
pub fn xmss_auth_path<P: Params>(
    sk_seed: &[u8],
    hash_ctx: &Sha256Ctx,
    adrs: &mut Adrs,
    h_prime: u32,
    idx: u32,
) -> Vec<u8> {
    let mut auth = Vec::with_capacity((h_prime as usize) * P::N);
    for i in 0..h_prime {
        let sibling_start = ((idx ^ (1 << i)) >> i) << i;
        let tmp = xmss_treehash::<P>(sk_seed, hash_ctx, adrs, i, sibling_start);
        auth.extend_from_slice(&tmp);
    }
    auth
}

/// Rebuild the XMSS root from a WOTS+C signature and authentication path.
/// `no_std`-safe. Port of C++ `xmss_pk_from_sig`.
pub fn xmss_pk_from_sig<P: Params>(
    wots_sig: &[u8],
    auth: &[u8],
    message: &[u8],
    pk_root: &[u8],
    hash_ctx: &Sha256Ctx,
    adrs: &mut Adrs,
    h_prime: u32,
    idx: u32,
) -> Result<Node, wots_c::Error> {
    let mut node = wots_c::wots_pk_from_sig::<P>(
        wots_sig, message, pk_root, hash_ctx, adrs, idx, false, true,
    )?;

    let mut idx = idx;
    for i in 0..h_prime as usize {
        set_type_and_clear(adrs, SL_TREE);
        set_tree_height(adrs, (i + 1) as u32);
        set_tree_index(adrs, idx >> 1);

        let base = i * P::N;
        let ctx = hash_ctx.add_to_ctx(adrs);
        let ctx = if (idx & 1) == 0 {
            ctx.add_to_ctx(&node).add_to_ctx(&auth[base..base + P::N])
        } else {
            ctx.add_to_ctx(&auth[base..base + P::N]).add_to_ctx(&node)
        };
        sha256_finalize(&ctx, &mut node);
        idx >>= 1;
    }

    Ok(node)
}

/// Produce an XMSS signature (WOTS+C signature + authentication path) for leaf
/// `idx`. Signing-only (`std`). Returns `XMSS_SIGN_LEN` bytes.
#[cfg(feature = "std")]
pub fn xmss_sign<P: Params>(
    message: &[u8],
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    hash_ctx: &Sha256Ctx,
    adrs: &mut Adrs,
    h_prime: u32,
    idx: u32,
) -> Result<Vec<u8>, wots_c::Error> {
    let wots_sig = wots_c::wots_sign::<P>(
        message, sk_seed, sk_prf, pk_seed, pk_root, hash_ctx, adrs, idx, false, true,
    )?;
    let auth = xmss_auth_path::<P>(sk_seed, hash_ctx, adrs, h_prime, idx);

    let mut sig = Vec::with_capacity(P::XMSS_SIGN_LEN);
    sig.extend_from_slice(&wots_sig);
    sig.extend_from_slice(&auth);
    Ok(sig)
}
