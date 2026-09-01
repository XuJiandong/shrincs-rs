//! PORS+FP — Pseudorandom Obtainable Random Subset with Fallback Path.
//!
//! The stateless signature's FORS-like layer: `K` secret values are selected
//! from the XOF output, revealed, and authenticated with a compressed
//! "octopus" Merkle authentication path.

use alloc::vec;
use alloc::vec::Vec;

use crate::address::*;
use crate::constants::Params;
#[cfg(feature = "std")]
use crate::constants::address_types::SL_H_MSG;
use crate::constants::address_types::{PORS_HASH, PORS_PK, PORS_PRF, PORS_TREE, PORS_XOF};
#[cfg(feature = "std")]
use crate::hash::prf_msg;
use crate::hash::{Sha256Ctx, sha256_finalize, sha256_finalize_32};
use crate::wots_c::Node;

/// Error raised by PORS+FP operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// No valid index set (or too-long octopus path) could be found.
    GrindFailed,
    /// The octopus path did not terminate in a single root.
    OctopusFailed,
}

/// Ceiling of `log2(T)` for a given `Params::T`.
#[inline]
pub fn tree_height<P: Params>() -> usize {
    let mut h = 0usize;
    while (1usize << h) < P::T {
        h += 1;
    }
    h
}

/// Extract `bits_amount` bits starting at absolute bit `start_bit_idx`.
/// Port of C++ `extract_bits`.
pub fn extract_bits(message: &[u8], start_bit_idx: u32, bits_amount: u32) -> u32 {
    let mut res = 0u32;
    for i in 0..bits_amount {
        let bit_idx = start_bit_idx + i;
        let byte_idx = (bit_idx / 8) as usize;
        let bit_in_byte = bit_idx % 8;
        let bit = (message[byte_idx] >> (7 - bit_in_byte)) & 1;
        res = (res << 1) | bit as u32;
    }
    res
}

/// Whether `elem` occurs anywhere in `arr`.
pub fn uint32_arr_have(arr: &[u32], elem: u32) -> bool {
    arr.contains(&elem)
}

/// Derive `K` distinct indices in `[0, T)` from a 32-byte digest via a
/// SHA-256 counter-mode XOF, storing the first `XOF_BLOCK_IDX * 32` XOF bytes
/// into `xof_out`. Returns the `K` indices (sorted). `no_std`-safe.
pub fn pors_msg_to_indices<P: Params>(
    message: &[u8],
    adrs: &mut Adrs,
    hash_ctx: &Sha256Ctx,
    xof_out: &mut [u8],
) -> Vec<u32> {
    debug_assert!(xof_out.len() >= P::XOF_BLOCK_IDX * 32);

    let mut block = [0u8; 32];
    let mut xof_offset = 0usize;

    let mut indices = Vec::with_capacity(P::K);
    let mut indices_amount = 0usize;

    set_type_and_clear(adrs, PORS_XOF);
    let ctx = hash_ctx.add_to_ctx(adrs).add_to_ctx(message);

    let mut blk: u32 = 0;
    loop {
        let ctx_blk = ctx.add_to_ctx(&blk.to_be_bytes());
        sha256_finalize_32(&ctx_blk, &mut block);

        if (blk as usize) < P::XOF_BLOCK_IDX {
            xof_out[xof_offset..xof_offset + 32].copy_from_slice(&block);
            xof_offset += 32;
        }

        for i in 0..P::C {
            if indices_amount == P::K {
                break;
            }
            let candidate = extract_bits(&block, (i * P::B) as u32, P::B as u32);
            if (candidate as usize) < P::T && !uint32_arr_have(&indices, candidate) {
                indices.push(candidate);
                indices_amount += 1;
            }
        }

        if (blk as usize) >= P::XOF_BLOCK_IDX && indices_amount == P::K {
            indices.sort_unstable();
            return indices;
        }

        if blk == u32::MAX {
            break;
        }
        blk += 1;
    }

    indices
}

/// The compressed octopus authentication path.
///
/// Given sorted `K` indices, compute the `(level, sibling_index)` nodes needed
/// to authenticate all `K` leaves. Returns `None` if the path exceeds `M_MAX`
/// nodes (mirrors C++ returning `false`). `no_std`-safe.
pub fn pors_octopus<P: Params>(indices: &[u32]) -> Option<Vec<(u32, u32)>> {
    let s = (P::T - (1 << (P::B - 1))) as u32;

    let mut i_list: Vec<(u32, u32)> = Vec::with_capacity(P::K);
    let mut p_list: Vec<(u32, u32)> = Vec::with_capacity(P::K);

    let mut a_out: Vec<(u32, u32)> = Vec::with_capacity(P::M_MAX);

    for &i in indices {
        if i < 2 * s {
            i_list.push((0, i));
        } else {
            p_list.push((1, i - s));
        }
    }

    for current_lvl in 0..P::B as u32 {
        let mut p_next: Vec<(u32, u32)> = Vec::with_capacity(i_list.len());

        let mut i = 0usize;
        while i < i_list.len() {
            let (lvl, idx) = i_list[i];
            let sib = idx ^ 1;

            if i + 1 < i_list.len() && i_list[i + 1].1 == sib {
                i += 2;
            } else {
                if a_out.len() == P::M_MAX {
                    return None;
                }
                a_out.push((current_lvl, sib));
                i += 1;
            }

            p_next.push((lvl + 1, idx >> 1));
        }

        i_list = p_next;
        i_list.append(&mut p_list);

        if i_list.len() == 1 && i_list[0].1 == 0 {
            break;
        }
    }

    Some(a_out)
}

/// Result of a successful [`pors_grind`]: the randomizer `r`, the 32-byte
/// digest, and the sorted `K` indices.
pub type PorsGrindResult = ([u8; 32], [u8; 32], Vec<u32>);

/// Grind for a randomizer `r` whose indices admit an octopus path within
/// `M_MAX`. Multi-threaded, signing-only (`std`). Port of C++ `pors_grind`.
#[cfg(feature = "std")]
pub fn pors_grind<P: Params>(
    message: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    adrs: &mut Adrs,
    opt_rand: &[u8],
    hash_ctx: &Sha256Ctx,
) -> Result<PorsGrindResult, Error> {
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;

    set_type_and_clear(adrs, SL_H_MSG);
    let ctx = hash_ctx.add_to_ctx(adrs);

    // Own the inputs so threads get 'static data.
    let message = message.to_vec();
    let sk_prf = sk_prf.to_vec();
    let pk_seed = pk_seed.to_vec();
    let pk_root = pk_root.to_vec();
    let opt_rand = opt_rand.to_vec();
    let hash_ctx = *hash_ctx;

    let current_ctr = Arc::new(AtomicU64::new(0));
    let found = Arc::new(AtomicBool::new(false));

    let num_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    let mut threads = Vec::with_capacity(num_threads);
    for _ in 0..num_threads {
        let current_ctr = Arc::clone(&current_ctr);
        let found = Arc::clone(&found);
        let message = message.clone();
        let sk_prf = sk_prf.clone();
        let pk_seed = pk_seed.clone();
        let pk_root = pk_root.clone();
        let opt_rand = opt_rand.clone();
        threads.push(std::thread::spawn(move || -> Option<PorsGrindResult> {
            let mut local_xof_out = vec![0u8; P::XOF_BLOCK_IDX * 32];
            let mut local_r_out = [0u8; 32];
            let mut local_digest_out = [0u8; 32];
            let mut local_adrs: crate::address::Adrs = [0u8; 32];

            loop {
                if found.load(Ordering::Relaxed) {
                    break;
                }
                let ctr = current_ctr.fetch_add(1, Ordering::Relaxed);
                if ctr > u32::MAX as u64 {
                    break;
                }

                prf_msg(
                    &sk_prf,
                    &pk_seed,
                    &opt_rand,
                    &message,
                    true,
                    ctr as u32,
                    P::R_LEN,
                    &mut local_r_out,
                );

                let ctx_ = ctx
                    .add_to_ctx(&local_r_out)
                    .add_to_ctx(&pk_root)
                    .add_to_ctx(&message);
                sha256_finalize_32(&ctx_, &mut local_digest_out);

                let a_indices = pors_msg_to_indices::<P>(
                    &local_digest_out,
                    &mut local_adrs,
                    &hash_ctx,
                    &mut local_xof_out,
                );

                if pors_octopus::<P>(&a_indices).is_some() {
                    if found
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                        .is_ok()
                    {
                        return Some((local_r_out, local_digest_out, a_indices));
                    }
                    break;
                }
            }
            None
        }));
    }

    for t in threads {
        if let Ok(Some(r)) = t.join() {
            return Ok(r);
        }
    }

    Err(Error::GrindFailed)
}

/// Derive one PORS+FP secret value for `leaf_idx`. `no_std`-safe.
pub fn pors_sk_gen<P: Params>(
    sk_seed: &[u8],
    hash_ctx: &Sha256Ctx,
    adrs: &mut Adrs,
    leaf_idx: u32,
) -> Node {
    set_type_and_clear(adrs, PORS_PRF);
    set_key_pair_address(adrs, 0);
    set_tree_index(adrs, leaf_idx);

    let ctx = hash_ctx.add_to_ctx(adrs).add_to_ctx(sk_seed);
    let mut res = Node::default();
    sha256_finalize(&ctx, &mut res);
    res
}

/// Build the PORS+FP subtree of `target_height` at `idx`. Signing-only.
/// Port of C++ `pors_treehash`.
#[cfg(feature = "std")]
pub fn pors_treehash<P: Params>(
    sk_seed: &[u8],
    hash_ctx: &Sha256Ctx,
    adrs: &mut Adrs,
    target_height: u32,
    idx: u32,
) -> Node {
    let h = tree_height::<P>();
    let s = (P::T - (1 << (h - 1))) as u32;

    if target_height == 0 {
        return leaf_node::<P>(sk_seed, hash_ctx, adrs, idx);
    } else if target_height == 1 && idx >= s {
        return leaf_node::<P>(sk_seed, hash_ctx, adrs, s + idx);
    }

    let left = pors_treehash::<P>(sk_seed, hash_ctx, adrs, target_height - 1, 2 * idx);
    let right = pors_treehash::<P>(sk_seed, hash_ctx, adrs, target_height - 1, 2 * idx + 1);

    set_type_and_clear(adrs, PORS_TREE);
    set_key_pair_address(adrs, 0);
    set_tree_height(adrs, target_height);
    set_tree_index(adrs, idx);
    let ctx = hash_ctx
        .add_to_ctx(adrs)
        .add_to_ctx(&left)
        .add_to_ctx(&right);
    let mut res = Node::default();
    sha256_finalize(&ctx, &mut res);
    res
}

/// A single PORS+FP leaf node (hashed secret). `no_std`-safe.
#[cfg(feature = "std")]
fn leaf_node<P: Params>(
    sk_seed: &[u8],
    hash_ctx: &Sha256Ctx,
    adrs: &mut Adrs,
    leaf_idx: u32,
) -> Node {
    let sk = pors_sk_gen::<P>(sk_seed, hash_ctx, adrs, leaf_idx);
    set_type_and_clear(adrs, PORS_HASH);
    set_key_pair_address(adrs, 0);
    set_tree_height(adrs, 0);
    set_tree_index(adrs, leaf_idx);
    let ctx = hash_ctx.add_to_ctx(adrs).add_to_ctx(&sk);
    let mut res = Node::default();
    sha256_finalize(&ctx, &mut res);
    res
}

/// Produce the PORS+FP authentication path for `indices`.
/// Returns `(auth_bytes, a_len)`. Signing-only.
#[cfg(feature = "std")]
pub fn pors_auth_path<P: Params>(
    sk_seed: &[u8],
    hash_ctx: &Sha256Ctx,
    adrs: &mut Adrs,
    indices: &[u32],
) -> (Vec<u8>, usize) {
    let a = pors_octopus::<P>(indices).expect("indices must admit an octopus path");
    let a_len = a.len();
    let mut auth = Vec::with_capacity(a_len * P::N);
    for (lvl, idx) in a {
        let tmp = pors_treehash::<P>(sk_seed, hash_ctx, adrs, lvl, idx);
        auth.extend_from_slice(&tmp);
    }
    (auth, a_len)
}

/// Build the PORS+FP subtree of `target_height` at `idx` consulting a
/// precomputed subtree-root checkpoint cache (see
/// [`crate::shrincs::sign_stateless_prepare`]). Signing-only.
///
/// `cache` holds `1 << (B - PORS_CHECKPOINT)` subtree roots (each `N` bytes)
/// for the fixed PORS tree. Subtrees at height `PORS_CHECKPOINT` and above are
/// reconstructed from the cache; shallower subtrees fall back to the
/// (uncached) [`pors_treehash`]. Produces byte-identical output to
/// [`pors_treehash`] for the same inputs.
#[cfg(feature = "std")]
pub fn pors_treehash_cached<P: Params>(
    sk_seed: &[u8],
    hash_ctx: &Sha256Ctx,
    adrs: &mut Adrs,
    target_height: u32,
    idx: u32,
    cache: &[u8],
) -> Node {
    let ck = P::PORS_CHECKPOINT as u32;

    if target_height < ck {
        return pors_treehash::<P>(sk_seed, hash_ctx, adrs, target_height, idx);
    }

    if target_height == ck {
        let offset = (idx as usize) * P::N;
        debug_assert!(offset + P::N <= cache.len());
        let mut res = Node::default();
        res.copy_from_slice(&cache[offset..offset + P::N]);
        return res;
    }

    // target_height > ck: combine two (target_height - 1) subtrees.
    let left =
        pors_treehash_cached::<P>(sk_seed, hash_ctx, adrs, target_height - 1, 2 * idx, cache);
    let right = pors_treehash_cached::<P>(
        sk_seed,
        hash_ctx,
        adrs,
        target_height - 1,
        2 * idx + 1,
        cache,
    );

    set_type_and_clear(adrs, PORS_TREE);
    set_key_pair_address(adrs, 0);
    set_tree_height(adrs, target_height);
    set_tree_index(adrs, idx);
    let ctx = hash_ctx
        .add_to_ctx(adrs)
        .add_to_ctx(&left)
        .add_to_ctx(&right);
    let mut res = Node::default();
    sha256_finalize(&ctx, &mut res);
    res
}

/// Produce the PORS+FP authentication path for `indices`, consulting the
/// precomputed checkpoint cache. `no_std`-safe. Returns `(auth_bytes, a_len)`.
#[cfg(feature = "std")]
pub fn pors_auth_path_cached<P: Params>(
    sk_seed: &[u8],
    hash_ctx: &Sha256Ctx,
    adrs: &mut Adrs,
    indices: &[u32],
    cache: &[u8],
) -> (Vec<u8>, usize) {
    let a = pors_octopus::<P>(indices).expect("indices must admit an octopus path");
    let a_len = a.len();
    let mut auth = Vec::with_capacity(a_len * P::N);
    for (lvl, idx) in a {
        let tmp = pors_treehash_cached::<P>(sk_seed, hash_ctx, adrs, lvl, idx, cache);
        auth.extend_from_slice(&tmp);
    }
    (auth, a_len)
}

/// Precompute the PORS+FP subtree roots at [`Params::PORS_CHECKPOINT`].
///
/// Returns `1 << (B - PORS_CHECKPOINT) * N` bytes: the cached roots of every
/// height-`PORS_CHECKPOINT` subtree of the fixed PORS tree, in index order.
/// Signing-only. This is the PORS half of
/// [`crate::shrincs::sign_stateless_prepare`] and is independent of the message.
#[cfg(feature = "std")]
pub fn pors_checkpoint_roots<P: Params>(sk_seed: &[u8], hash_ctx: &Sha256Ctx) -> Vec<u8> {
    let ck = P::PORS_CHECKPOINT as u32;
    let count = 1usize << (P::B - P::PORS_CHECKPOINT);
    let mut roots = Vec::with_capacity(count * P::N);
    let mut adrs: Adrs = [0u8; 32];
    for idx in 0..count as u32 {
        let node = pors_treehash::<P>(sk_seed, hash_ctx, &mut adrs, ck, idx);
        roots.extend_from_slice(&node);
    }
    roots
}

/// Sign the message with PORS+FP. Returns a `PORS_SIGN_LEN`-byte signature
/// (zero-padded after the used auth path) and the 32-byte digest. Signing-only.
#[cfg(feature = "std")]
pub fn pors_sign<P: Params>(
    message: &[u8],
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    hash_ctx: &Sha256Ctx,
    adrs: &mut Adrs,
) -> Result<(Vec<u8>, [u8; 32]), Error> {
    pors_sign_inner::<P>(
        message, sk_seed, sk_prf, pk_seed, pk_root, hash_ctx, adrs, None,
    )
}

/// [`pors_sign`] that consults a precomputed checkpoint `cache`
/// (see [`crate::shrincs::sign_stateless_prepare`]). Signing-only.
#[cfg(feature = "std")]
pub fn pors_sign_cached<P: Params>(
    message: &[u8],
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    hash_ctx: &Sha256Ctx,
    adrs: &mut Adrs,
    cache: &[u8],
) -> Result<(Vec<u8>, [u8; 32]), Error> {
    pors_sign_inner::<P>(
        message,
        sk_seed,
        sk_prf,
        pk_seed,
        pk_root,
        hash_ctx,
        adrs,
        Some(cache),
    )
}

#[cfg(feature = "std")]
fn pors_sign_inner<P: Params>(
    message: &[u8],
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    hash_ctx: &Sha256Ctx,
    adrs: &mut Adrs,
    cache: Option<&[u8]>,
) -> Result<(Vec<u8>, [u8; 32]), Error> {
    let mut sig = vec![0u8; P::PORS_SIGN_LEN];

    let opt_rand = pk_seed;
    let (r, digest, indices) =
        pors_grind::<P>(message, sk_prf, pk_seed, pk_root, adrs, opt_rand, hash_ctx)?;

    sig[..P::R_LEN].copy_from_slice(&r);
    let mut offset = P::R_LEN;

    for &i in &indices {
        let sk_i = pors_sk_gen::<P>(sk_seed, hash_ctx, adrs, i);
        sig[offset..offset + P::N].copy_from_slice(&sk_i);
        offset += P::N;
    }

    let (auth, a_len) = match cache {
        Some(cache) => pors_auth_path_cached::<P>(sk_seed, hash_ctx, adrs, &indices, cache),
        None => pors_auth_path::<P>(sk_seed, hash_ctx, adrs, &indices),
    };
    sig[offset..offset + a_len * P::N].copy_from_slice(&auth);

    Ok((sig, digest))
}

/// Recover the PORS+FP public key from a signature (verification, `no_std`).
/// Port of C++ `pors_pk_from_sig`.
pub fn pors_pk_from_sig<P: Params>(
    sig: &[u8],
    indices: &[u32],
    hash_ctx: &Sha256Ctx,
    adrs: &mut Adrs,
) -> Result<Node, Error> {
    let mut offset = P::R_LEN;

    let h = tree_height::<P>();
    let s = (P::T - (1 << (h - 1))) as u32;

    #[derive(Clone)]
    struct Node2 {
        idx: u32,
        val: Node,
    }

    let mut i_list: Vec<Node2> = Vec::with_capacity(P::K);
    let mut p_list: Vec<Node2> = Vec::with_capacity(P::K);

    for &k in indices {
        let mut sk_i = Node::default();
        sk_i.copy_from_slice(&sig[offset..offset + P::N]);
        offset += P::N;

        set_type_and_clear(adrs, PORS_HASH);
        set_key_pair_address(adrs, 0);
        set_tree_height(adrs, 0);
        set_tree_index(adrs, k);
        let ctx = hash_ctx.add_to_ctx(adrs).add_to_ctx(&sk_i);
        let mut val = Node::default();
        sha256_finalize(&ctx, &mut val);

        if k < 2 * s {
            i_list.push(Node2 { idx: k, val });
        } else {
            p_list.push(Node2 { idx: k - s, val });
        }
    }

    let mut parent_val = Node::default();
    let mut auth_val = Node::default();

    for cur_lvl in 0..h as u32 {
        let mut paired = vec![false; i_list.len()];
        for i in 0..i_list.len() {
            if i + 1 < i_list.len() && i_list[i + 1].idx == (i_list[i].idx ^ 1) {
                paired[i] = true;
                paired[i + 1] = true;
            }
        }

        let mut p_next: Vec<Node2> = Vec::with_capacity(i_list.len());

        for i in 0..i_list.len() {
            let node = i_list[i].clone();
            if paired[i] && (node.idx & 1) == 0 {
                continue;
            }

            set_type_and_clear(adrs, PORS_TREE);
            set_key_pair_address(adrs, 0);
            set_tree_height(adrs, cur_lvl + 1);
            set_tree_index(adrs, node.idx >> 1);

            let ctx = hash_ctx.add_to_ctx(adrs);

            if paired[i] {
                let left_val = &i_list[i - 1].val;
                let ctx = ctx.add_to_ctx(left_val).add_to_ctx(&node.val);
                sha256_finalize(&ctx, &mut parent_val);
            } else {
                auth_val.copy_from_slice(&sig[offset..offset + P::N]);
                offset += P::N;
                if (node.idx & 1) == 0 {
                    let ctx = ctx.add_to_ctx(&node.val).add_to_ctx(&auth_val);
                    sha256_finalize(&ctx, &mut parent_val);
                } else {
                    let ctx = ctx.add_to_ctx(&auth_val).add_to_ctx(&node.val);
                    sha256_finalize(&ctx, &mut parent_val);
                }
            }

            p_next.push(Node2 {
                idx: node.idx >> 1,
                val: parent_val,
            });
        }

        i_list = p_next;
        i_list.append(&mut p_list);

        if i_list.len() == 1 && i_list[0].idx == 0 {
            break;
        }
    }

    let root = i_list.first().ok_or(Error::OctopusFailed)?.val;

    set_type_and_clear(adrs, PORS_PK);
    let ctx = hash_ctx.add_to_ctx(adrs).add_to_ctx(&root);
    let mut res = Node::default();
    sha256_finalize(&ctx, &mut res);
    Ok(res)
}
