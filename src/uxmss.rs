//! UXMSS — the "unbalanced" XMSS variant used for the **stateful** tree.
//!
//! The stateful signature tree is a single unbalanced Merkle tree of height
//! [`Params::HSF`] built from WOTS+C leaves. It supports `HSF + 1` signatures:
//! leaves `1..=HSF` plus one extra leaf (`HSF + 1`).

#[cfg(feature = "std")]
use alloc::vec::Vec;

use crate::address::*;
use crate::constants::address_types::SF_TREE;
use crate::constants::Params;
use crate::hash::{sha256_finalize, Sha256Ctx};
use crate::wots_c::{self, Node};

/// Recursively build the UXMSS subtree at `level` (0 = root). Signing-only.
///
/// At the deepest level (`HSF - 1`), the right child is the extra leaf key pair
/// `HSF + 1`. Port of C++ `uxmss_treehash`.
#[cfg(feature = "std")]
pub fn uxmss_treehash<P: Params>(
    sk_seed: &[u8],
    hash_ctx: &Sha256Ctx,
    adrs: &mut Adrs,
    level: u32,
) -> Node {
    let left = wots_c::wots_pk_gen::<P>(sk_seed, hash_ctx, adrs, level + 1, true);

    let right = if level == (P::HSF - 1) as u32 {
        wots_c::wots_pk_gen::<P>(sk_seed, hash_ctx, adrs, (P::HSF + 1) as u32, true)
    } else {
        uxmss_treehash::<P>(sk_seed, hash_ctx, adrs, level + 1)
    };

    set_type_and_clear(adrs, SF_TREE);
    set_tree_height(adrs, P::HSF as u32 - level);
    set_tree_index(adrs, 0);

    let ctx = hash_ctx
        .add_to_ctx(adrs)
        .add_to_ctx(&left)
        .add_to_ctx(&right);
    let mut res = Node::default();
    sha256_finalize(&ctx, &mut res);
    res
}

/// The stateful tree root (layer 0, tree 0). Signing-only (`std`).
#[cfg(feature = "std")]
pub fn uxmss_root<P: Params>(sk_seed: &[u8], hash_ctx: &Sha256Ctx, adrs: &mut Adrs) -> Node {
    set_layer_address(adrs, 0);
    set_tree_address(adrs, 0, 0);
    uxmss_treehash::<P>(sk_seed, hash_ctx, adrs, 0)
}

/// The UXMSS authentication path for signature number `q` (1-based).
///
/// Returns `min(q, HSF)` nodes. Signing-only. Port of C++ `uxmss_auth_path`.
#[cfg(feature = "std")]
pub fn uxmss_auth_path<P: Params>(
    sk_seed: &[u8],
    hash_ctx: &Sha256Ctx,
    adrs: &mut Adrs,
    q: u32,
) -> Vec<u8> {
    let node_count = if q > P::HSF as u32 {
        P::HSF
    } else {
        q as usize
    };
    let mut auth = Vec::with_capacity(node_count * P::N);

    set_layer_address(adrs, 0);
    set_tree_address(adrs, 0, 0);

    if q <= P::HSF as u32 {
        let first = if q == P::HSF as u32 {
            wots_c::wots_pk_gen::<P>(sk_seed, hash_ctx, adrs, (P::HSF + 1) as u32, true)
        } else {
            uxmss_treehash::<P>(sk_seed, hash_ctx, adrs, q)
        };
        auth.extend_from_slice(&first);

        for i in 1..q as usize {
            let tmp = wots_c::wots_pk_gen::<P>(sk_seed, hash_ctx, adrs, q - i as u32, true);
            auth.extend_from_slice(&tmp);
        }
    } else {
        for i in 0..P::HSF {
            let tmp = wots_c::wots_pk_gen::<P>(sk_seed, hash_ctx, adrs, (P::HSF - i) as u32, true);
            auth.extend_from_slice(&tmp);
        }
    }

    auth
}

/// Rebuild the stateful root from a WOTS+C signature and authentication path.
/// `no_std`-safe. Port of C++ `uxmss_pk_from_sig`.
pub fn uxmss_pk_from_sig<P: Params>(
    wots_sig: &[u8],
    auth: &[u8],
    message: &[u8],
    pk_root: &[u8],
    hash_ctx: &Sha256Ctx,
    adrs: &mut Adrs,
    q: u32,
) -> Result<Node, wots_c::Error> {
    set_layer_address(adrs, 0);
    set_tree_address(adrs, 0, 0);
    let mut node =
        wots_c::wots_pk_from_sig::<P>(wots_sig, message, pk_root, hash_ctx, adrs, q, true, false)?;

    set_type_and_clear(adrs, SF_TREE);
    if q <= P::HSF as u32 {
        set_tree_height(adrs, P::HSF as u32 - (q - 1));
        set_tree_index(adrs, 0);

        let ctx = hash_ctx
            .add_to_ctx(adrs)
            .add_to_ctx(&node)
            .add_to_ctx(&auth[..P::N]);
        sha256_finalize(&ctx, &mut node);

        for i in 1..q as usize {
            set_tree_height(adrs, P::HSF as u32 - (q - 1 - i as u32));
            set_tree_index(adrs, 0);

            let base = i * P::N;
            let ctx = hash_ctx
                .add_to_ctx(adrs)
                .add_to_ctx(&auth[base..base + P::N])
                .add_to_ctx(&node);
            sha256_finalize(&ctx, &mut node);
        }
    } else {
        for i in 0..P::HSF {
            set_tree_height(adrs, (i + 1) as u32);
            set_tree_index(adrs, 0);

            let base = i * P::N;
            let ctx = hash_ctx
                .add_to_ctx(adrs)
                .add_to_ctx(&auth[base..base + P::N])
                .add_to_ctx(&node);
            sha256_finalize(&ctx, &mut node);
        }
    }

    Ok(node)
}

/// Produce a stateful UXMSS signature for signature number `q`. Signing-only.
/// Returns `WOTS_SIGN_LEN + min(q, HSF) * N` bytes.
#[cfg(feature = "std")]
pub fn uxmss_sign<P: Params>(
    message: &[u8],
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    hash_ctx: &Sha256Ctx,
    adrs: &mut Adrs,
    q: u32,
) -> Result<Vec<u8>, wots_c::Error> {
    set_layer_address(adrs, 0);
    set_tree_address(adrs, 0, 0);
    let wots_sig = wots_c::wots_sign::<P>(
        message, sk_seed, sk_prf, pk_seed, pk_root, hash_ctx, adrs, q, true, false,
    )?;
    let auth = uxmss_auth_path::<P>(sk_seed, hash_ctx, adrs, q);

    let q_auth = if q > P::HSF as u32 { q - 1 } else { q } as usize;

    let mut res = Vec::with_capacity(P::WOTS_SIGN_LEN + q_auth * P::N);
    res.extend_from_slice(&wots_sig);
    res.extend_from_slice(&auth[..q_auth * P::N]);
    Ok(res)
}
