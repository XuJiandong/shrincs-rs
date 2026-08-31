//! Top-level SHRINCS API: key generation, signing, and verification.
//!
//! Mirrors the C++ `shrincs.h` / `shrincs.cpp`. The public types are
//! parameter-independent; only the signing/verification functions are generic
//! over [`Params`].

use alloc::vec;
#[cfg(feature = "std")]
use alloc::vec::Vec;

use crate::address::*;
use crate::constants::Params;
use crate::constants::address_types::{ROOT, SL_H_MSG};
use crate::hash::{Sha256Ctx, sha256_finalize, sha256_finalize_32};
use crate::{pors_fp, uxmss, wots_c, xmss};

/// Errors produced by SHRINCS operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The state was not marked valid before stateful signing.
    InvalidState,
    /// The stateful signature counter exceeded the allowed maximum.
    InvalidSignatureNumber,
    /// The recovered WOTS+C digest was invalid.
    WotsDigestInvalid,
    /// The PORS+FP grind failed to find a valid index set.
    PorsGrindFailed,
    /// The WOTS+C grind failed to find a valid digest (unreachable).
    WotsGrindFailed,
    /// The OS random source failed.
    Random,
}

impl From<wots_c::Error> for Error {
    fn from(e: wots_c::Error) -> Self {
        match e {
            wots_c::Error::DigestInvalid => Error::WotsDigestInvalid,
            wots_c::Error::GrindFailed => Error::WotsGrindFailed,
        }
    }
}

impl From<pors_fp::Error> for Error {
    fn from(e: pors_fp::Error) -> Self {
        match e {
            pors_fp::Error::GrindFailed => Error::PorsGrindFailed,
            pors_fp::Error::OctopusFailed => Error::PorsGrindFailed,
        }
    }
}

/// The SHRINCS public key: `(seed, root)`, each 16 bytes.
#[derive(Default, Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// The 16-byte public seed.
    pub seed: [u8; 16],
    /// The 16-byte compressed public root.
    pub root: [u8; 16],
}

/// The SHRINCS secret key.
#[derive(Default, Clone, PartialEq, Eq)]
pub struct SecretKey {
    /// The 16-byte secret seed.
    pub seed: [u8; 16],
    /// The 16-byte secret PRF key.
    pub prf: [u8; 16],
    /// The 16-byte stateful-tree root (`sf`).
    pub sf: [u8; 16],
    /// The 16-byte stateless-tree root (`sl`).
    pub sl: [u8; 16],
    /// The corresponding public key.
    pub pk: PublicKey,
}

/// State tracking for stateful signing.
#[derive(Default, Clone, PartialEq, Eq)]
pub struct State {
    /// The number of stateful signatures produced so far.
    pub q: u32,
    /// Whether this state is safe to sign with.
    pub valid: bool,
}

/// Fill `buffer` with cryptographically secure random bytes (signing only).
#[cfg(feature = "std")]
pub fn generate_random_bytes(buffer: &mut [u8]) -> Result<(), Error> {
    getrandom::getrandom(buffer).map_err(|_| Error::Random)
}

/// Parse an `HSL`-bit hypertree index from the XOF output into per-layer tree
/// and leaf indices. Port of C++ `parse_idx`.
///
/// `tree_idx` and `leaf_idx` each receive `D` entries. The top layer's tree
/// index is always 0.
pub fn parse_idx<P: Params>(xof: &[u8], tree_idx: &mut [u32], leaf_idx: &mut [u32]) {
    let mut idx = pors_fp::extract_bits(xof, P::XOF_OFFSET_BITS as u32, P::HSL as u32);

    for layer in 0..P::D {
        let leaf = idx & ((1u32 << P::H_PRIME) - 1);
        leaf_idx[layer] = leaf;
        idx >>= P::H_PRIME;
        tree_idx[layer] = idx;
    }
}

/// Build the shared hash "base context" from `pk_seed` plus 48 zero bytes.
#[inline]
pub(crate) fn base_ctx(pk_seed: &[u8]) -> Sha256Ctx {
    let adrs = [0u8; 32];
    Sha256Ctx::new()
        .add_to_ctx(pk_seed)
        .add_to_ctx(&adrs)
        .add_to_ctx(&adrs[..16])
}

/// Generate a fresh key pair and state (signing only, uses OS randomness).
#[cfg(feature = "std")]
pub fn key_gen<P: Params>(
    out_pk: &mut PublicKey,
    out_sk: &mut SecretKey,
    out_state: &mut State,
) -> Result<(), Error> {
    let mut seed = [0u8; 48];
    generate_random_bytes(&mut seed)?;
    restore::<P>(&seed, out_pk, out_sk, out_state);
    out_state.valid = true;
    Ok(())
}

/// Restore a key pair and state deterministically from a 48-byte seed
/// (`sk_seed ‖ sk_prf ‖ pk_seed`). `no_std`-safe (std tree hashing is gated,
/// see note below).
#[cfg(feature = "std")]
pub fn restore<P: Params>(
    seed: &[u8; 48],
    out_pk: &mut PublicKey,
    out_sk: &mut SecretKey,
    out_state: &mut State,
) {
    let mut sk_seed = [0u8; 16];
    let mut sk_prf = [0u8; 16];
    let mut pk_seed = [0u8; 16];
    sk_seed.copy_from_slice(&seed[..16]);
    sk_prf.copy_from_slice(&seed[16..32]);
    pk_seed.copy_from_slice(&seed[32..48]);

    let mut adrs: Adrs = [0u8; 32];
    let hash_ctx = base_ctx(&pk_seed);

    let pk_sf = uxmss::uxmss_root::<P>(&sk_seed, &hash_ctx, &mut adrs);

    set_layer_address(&mut adrs, (P::D - 1) as u32);
    set_tree_address(&mut adrs, 0, 0);
    let pk_sl = xmss::xmss_root::<P>(&sk_seed, &hash_ctx, &mut adrs, P::H_PRIME as u32);

    set_layer_address(&mut adrs, 0);
    set_tree_address(&mut adrs, 0, 0);
    set_type_and_clear(&mut adrs, ROOT);
    let ctx = hash_ctx
        .add_to_ctx(&adrs)
        .add_to_ctx(&pk_sf)
        .add_to_ctx(&pk_sl);
    let mut pk_root = [0u8; 16];
    sha256_finalize(&ctx, &mut pk_root);

    out_sk.seed = sk_seed;
    out_sk.prf = sk_prf;
    out_sk.sf = pk_sf;
    out_sk.sl = pk_sl;
    out_sk.pk.seed = pk_seed;
    out_sk.pk.root = pk_root;

    out_pk.seed = pk_seed;
    out_pk.root = pk_root;

    out_state.q = 0;
    out_state.valid = false;
}

/// Produce a stateful signature (signing only).
///
/// The signature is `N (sl) ‖ WOTS_SIGN_LEN (wots) ‖ min(q, HSF) * N (auth)`
/// bytes long; `state.q` advances atomically with signing.
#[cfg(feature = "std")]
pub fn sign_stateful<P: Params>(
    message: &[u8],
    sk: &mut SecretKey,
    state: &mut State,
) -> Result<Vec<u8>, Error> {
    if !state.valid {
        return Err(Error::InvalidState);
    }

    let q = state.q + 1;
    if q > (P::HSF + 1) as u32 {
        return Err(Error::InvalidSignatureNumber);
    }

    let mut adrs: Adrs = [0u8; 32];
    let hash_ctx = base_ctx(&sk.pk.seed);

    let uxmss_sig = uxmss::uxmss_sign::<P>(
        message,
        &sk.seed,
        &sk.prf,
        &sk.pk.seed,
        &sk.pk.root,
        &hash_ctx,
        &mut adrs,
        q,
    )?;
    state.q = q;
    state.valid = true;

    let mut sig = Vec::with_capacity(P::N + uxmss_sig.len());
    sig.extend_from_slice(&sk.sl);
    sig.extend_from_slice(&uxmss_sig);
    Ok(sig)
}

/// Precomputed, message-independent data used to accelerate
/// [`sign_stateless`](sign_stateless) signing for a fixed key pair.
///
/// Produced once per key pair by [`sign_stateless_prepare`] and reused across
/// many signatures. It caches the checkpoint subtree roots of:
///
/// * the fixed PORS+FP tree, and
/// * the single fixed XMSS hypertree layer `D - 1` (the only layer whose tree
///   address is always `0`, regardless of the message).
///
/// The serialized form is `8192 + 512 + 4` = 8,708 bytes, under the 10 KiB
/// guidance. The struct is plain data: serialize with [`to_bytes`] and restore
/// with [`from_bytes`]; the caller owns any file I/O.
///
/// [`to_bytes`]: Self::to_bytes
/// [`from_bytes`]: Self::from_bytes
#[cfg(feature = "std")]
pub struct PreparedStatelessKey<P: Params> {
    /// PORS+FP checkpoint subtree roots: `1 << (B - PORS_CHECKPOINT) * N` bytes.
    pors_roots: Vec<u8>,
    /// XMSS checkpoint subtree roots for layer `D - 1`:
    /// `1 << (H_PRIME - XMSS_CHECKPOINT) * N` bytes.
    xmss_roots: Vec<u8>,
    _marker: core::marker::PhantomData<fn() -> P>,
}

#[cfg(feature = "std")]
impl<P: Params> PreparedStatelessKey<P> {
    /// Size in bytes of the checkpoint roots for the fixed PORS tree.
    pub const fn pors_len() -> usize {
        (1usize << (P::B - P::PORS_CHECKPOINT)) * P::N
    }

    /// Size in bytes of the checkpoint roots for the fixed XMSS layer `D - 1`.
    pub const fn xmss_layer_len() -> usize {
        (1usize << (P::H_PRIME - P::XMSS_CHECKPOINT)) * P::N
    }

    /// Total serialized length in bytes.
    pub const fn serialized_len() -> usize {
        Self::pors_len() + Self::xmss_layer_len() + MAGIC_LEN
    }

    /// Serialize this prepared key into a flat byte vector.
    ///
    /// Layout: `MAGIC_LEN`-byte header (magic) followed by the PORS checkpoint
    /// roots and then the XMSS layer `D - 1` checkpoint roots, all densely
    /// packed. The layout is fully determined by `P`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::serialized_len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.pors_roots);
        out.extend_from_slice(&self.xmss_roots);
        out
    }

    /// Deserialize a flat byte vector previously produced by [`to_bytes`].
    /// Returns `None` on any header or length mismatch.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::serialized_len() || !bytes.starts_with(MAGIC) {
            return None;
        }
        let mut off = MAGIC_LEN;
        let pors_roots = bytes[off..off + Self::pors_len()].to_vec();
        off += Self::pors_len();
        let xmss_roots = bytes[off..off + Self::xmss_layer_len()].to_vec();
        Some(Self {
            pors_roots,
            xmss_roots,
            _marker: core::marker::PhantomData,
        })
    }
}

/// Serialization magic and its byte length for [`PreparedStatelessKey`].
#[cfg(feature = "std")]
const MAGIC: &[u8; 4] = b"SPSK";
#[cfg(feature = "std")]
const MAGIC_LEN: usize = MAGIC.len();

/// Precompute the message-independent data that accelerates
/// [`sign_stateless`](sign_stateless) for a given key pair.
///
/// Call this once per key pair (its output is reused across every signature),
/// serialize the result with [`PreparedStatelessKey::to_bytes`], persist it,
/// then load it (via [`PreparedStatelessKey::from_bytes`]) and pass it to
/// [`sign_stateless_with_prepare`] for each signature. The computation is
/// deterministic and depends only on the secret/public seeds embedded in `sk`.
#[cfg(feature = "std")]
pub fn sign_stateless_prepare<P: Params>(sk: &SecretKey) -> PreparedStatelessKey<P> {
    let hash_ctx = base_ctx(&sk.pk.seed);

    // Fixed PORS+FP tree (tree address 0, key pair 0).
    let pors_roots = pors_fp::pors_checkpoint_roots::<P>(&sk.seed, &hash_ctx);

    // Fixed XMSS hypertree layer D - 1: the only layer whose tree address
    // (`tree_idx[D - 1]`) is always 0. All shallower layers use the
    // message-derived `tree_idx[layer]` as their tree address, so their trees
    // are not fixed and cannot be precomputed.
    let mut adrs: Adrs = [0u8; 32];
    set_layer_address(&mut adrs, (P::D - 1) as u32);
    set_tree_address(&mut adrs, 0, 0);
    let xmss_roots = xmss::xmss_checkpoint_roots::<P>(&sk.seed, &hash_ctx, &mut adrs);

    PreparedStatelessKey {
        pors_roots,
        xmss_roots,
        _marker: core::marker::PhantomData,
    }
}

/// Produce a stateless signature (signing only, multi-threaded grind).
#[cfg(feature = "std")]
pub fn sign_stateless<P: Params>(message: &[u8], sk: &SecretKey) -> Result<Vec<u8>, Error> {
    sign_stateless_core::<P>(message, sk, None)
}

/// Produce a stateless signature accelerated by a [`PreparedStatelessKey`]
/// previously built with [`sign_stateless_prepare`] (signing only).
///
/// Produces a signature byte-identical to [`sign_stateless`] for the same
/// message and key, but skips the message-independent tree reconstruction.
#[cfg(feature = "std")]
pub fn sign_stateless_with_prepare<P: Params>(
    message: &[u8],
    sk: &SecretKey,
    prepared: &PreparedStatelessKey<P>,
) -> Result<Vec<u8>, Error> {
    sign_stateless_core::<P>(message, sk, Some(prepared))
}

#[cfg(feature = "std")]
fn sign_stateless_core<P: Params>(
    message: &[u8],
    sk: &SecretKey,
    prepared: Option<&PreparedStatelessKey<P>>,
) -> Result<Vec<u8>, Error> {
    let mut adrs: Adrs = [0u8; 32];
    let hash_ctx = base_ctx(&sk.pk.seed);

    let (pors_sig, digest) = match prepared {
        Some(p) => pors_fp::pors_sign_cached::<P>(
            message,
            &sk.seed,
            &sk.prf,
            &sk.pk.seed,
            &sk.pk.root,
            &hash_ctx,
            &mut adrs,
            &p.pors_roots,
        )?,
        None => pors_fp::pors_sign::<P>(
            message,
            &sk.seed,
            &sk.prf,
            &sk.pk.seed,
            &sk.pk.root,
            &hash_ctx,
            &mut adrs,
        )?,
    };

    let mut xof_buf = vec![0u8; P::XOF_BLOCK_IDX * 32];
    let indices = pors_fp::pors_msg_to_indices::<P>(&digest, &mut adrs, &hash_ctx, &mut xof_buf);

    let mut tree_idx = vec![0u32; P::D];
    let mut leaf_idx = vec![0u32; P::D];
    parse_idx::<P>(&xof_buf, &mut tree_idx, &mut leaf_idx);

    set_layer_address(&mut adrs, 0);
    set_tree_address(
        &mut adrs,
        0,
        tree_idx[0] as u64 * (1u64 << P::H_PRIME) + leaf_idx[0] as u64,
    );
    let pors_pk = pors_fp::pors_pk_from_sig::<P>(&pors_sig, &indices, &hash_ctx, &mut adrs)?;

    let mut sig = Vec::with_capacity(P::SL_SIZE);
    sig.extend_from_slice(&sk.sf);
    sig.extend_from_slice(&pors_sig);

    let mut msg = pors_pk;
    let mut ht_sig = Vec::with_capacity(P::XMSS_SIGN_LEN * P::D);
    for layer in 0..P::D {
        set_layer_address(&mut adrs, layer as u32);
        set_tree_address(&mut adrs, 0, tree_idx[layer] as u64);

        // Only the last layer (D - 1) has a fixed tree (tree address 0) and thus
        // a cached checkpoint.
        let layer_cache =
            prepared.and_then(|p| (layer == P::D - 1).then_some(p.xmss_roots.as_slice()));

        let xmss_sig = match layer_cache {
            Some(cache) => xmss::xmss_sign_cached::<P>(
                &msg,
                &sk.seed,
                &sk.prf,
                &sk.pk.seed,
                &sk.pk.root,
                &hash_ctx,
                &mut adrs,
                P::H_PRIME as u32,
                leaf_idx[layer],
                cache,
            )?,
            None => xmss::xmss_sign::<P>(
                &msg,
                &sk.seed,
                &sk.prf,
                &sk.pk.seed,
                &sk.pk.root,
                &hash_ctx,
                &mut adrs,
                P::H_PRIME as u32,
                leaf_idx[layer],
            )?,
        };
        ht_sig.extend_from_slice(&xmss_sig);

        if layer < P::D - 1 {
            msg = xmss::xmss_root::<P>(&sk.seed, &hash_ctx, &mut adrs, P::H_PRIME as u32);
        }
    }
    sig.extend_from_slice(&ht_sig);

    Ok(sig)
}

/// Verify a stateful signature. `no_std`-safe. Returns `false` on any error.
pub fn verify_stateful<P: Params>(message: &[u8], sig: &[u8], pk: &PublicKey) -> bool {
    if sig.len() < P::N + P::WOTS_SIGN_LEN {
        return false;
    }

    let mut adrs: Adrs = [0u8; 32];
    let sl = &sig[..P::N];
    let uxmss_sig = &sig[P::N..];

    let auth_len = sig.len() - P::N - P::WOTS_SIGN_LEN;
    if !auth_len.is_multiple_of(P::N) {
        return false;
    }

    let q_raw = (auth_len / P::N) as u32;
    if q_raw < 1 || q_raw > P::HSF as u32 {
        return false;
    }

    let last_sf_level = q_raw == P::HSF as u32;

    let hash_ctx = base_ctx(&pk.seed);

    for j in 0..if last_sf_level { 2 } else { 1 } {
        let q_attempt = if last_sf_level {
            P::HSF as u32 + j
        } else {
            q_raw
        };

        let wots_sig = &uxmss_sig[..P::WOTS_SIGN_LEN];
        let auth = &uxmss_sig[P::WOTS_SIGN_LEN..];
        let sf = match uxmss::uxmss_pk_from_sig::<P>(
            wots_sig, auth, message, &pk.root, &hash_ctx, &mut adrs, q_attempt,
        ) {
            Ok(x) => x,
            Err(_) => continue,
        };

        set_type_and_clear(&mut adrs, ROOT);
        let ctx = hash_ctx.add_to_ctx(&adrs).add_to_ctx(&sf).add_to_ctx(sl);
        let mut root = [0u8; 16];
        sha256_finalize(&ctx, &mut root);

        if root == pk.root {
            return true;
        }
    }

    false
}

/// Verify a stateless signature. `no_std`-safe. Returns `false` on any error.
pub fn verify_stateless<P: Params>(message: &[u8], sig: &[u8], pk: &PublicKey) -> bool {
    if sig.len() != P::SL_SIZE {
        return false;
    }

    let mut adrs: Adrs = [0u8; 32];
    let sf = &sig[..P::N];
    let pors_sig = &sig[P::N..P::N + P::PORS_SIGN_LEN];
    let r = &pors_sig[..P::R_LEN];

    let hash_ctx = base_ctx(&pk.seed);

    set_type_and_clear(&mut adrs, SL_H_MSG);
    let ctx = hash_ctx
        .add_to_ctx(&adrs)
        .add_to_ctx(r)
        .add_to_ctx(&pk.root)
        .add_to_ctx(message);
    let mut digest = [0u8; 32];
    sha256_finalize_32(&ctx, &mut digest);

    let mut xof = vec![0u8; P::XOF_BLOCK_IDX * 32];
    let indices = pors_fp::pors_msg_to_indices::<P>(&digest, &mut adrs, &hash_ctx, &mut xof);

    let oct = pors_fp::pors_octopus::<P>(&indices);
    let a_len = match oct {
        Some(a) => a.len(),
        None => return false,
    };

    // Enforce zero padding of the unused authentication tail.
    let mut offset_back = P::PORS_SIGN_LEN - P::N;
    for _i in a_len..P::M_MAX {
        if pors_sig[offset_back..offset_back + P::N]
            .iter()
            .any(|&b| b != 0)
        {
            return false;
        }
        offset_back -= P::N;
    }

    let mut tree_idx = vec![0u32; P::D];
    let mut leaf_idx = vec![0u32; P::D];
    parse_idx::<P>(&xof, &mut tree_idx, &mut leaf_idx);

    set_layer_address(&mut adrs, 0);
    set_tree_address(
        &mut adrs,
        0,
        tree_idx[0] as u64 * (1u64 << P::H_PRIME) + leaf_idx[0] as u64,
    );

    let pors_pk = match pors_fp::pors_pk_from_sig::<P>(pors_sig, &indices, &hash_ctx, &mut adrs) {
        Ok(x) => x,
        Err(_) => return false,
    };

    let mut msg = pors_pk;
    let mut offset = P::N + P::PORS_SIGN_LEN;
    for layer in 0..P::D {
        let xmss_sig = &sig[offset..offset + P::XMSS_SIGN_LEN];
        offset += P::XMSS_SIGN_LEN;
        let wots_sig = &xmss_sig[..P::WOTS_SIGN_LEN];
        let auth = &xmss_sig[P::WOTS_SIGN_LEN..];
        set_layer_address(&mut adrs, layer as u32);
        set_tree_address(&mut adrs, 0, tree_idx[layer] as u64);
        msg = match xmss::xmss_pk_from_sig::<P>(
            wots_sig,
            auth,
            &msg,
            &pk.root,
            &hash_ctx,
            &mut adrs,
            P::H_PRIME as u32,
            leaf_idx[layer],
        ) {
            Ok(x) => x,
            Err(_) => return false,
        };
    }

    let sl = msg;
    set_layer_address(&mut adrs, 0);
    set_tree_address(&mut adrs, 0, 0);
    set_type_and_clear(&mut adrs, ROOT);
    let ctx = hash_ctx.add_to_ctx(&adrs).add_to_ctx(sf).add_to_ctx(&sl);
    let mut root = [0u8; 16];
    sha256_finalize(&ctx, &mut root);

    root == pk.root
}

/// Verify a signature, dispatching on its length. `no_std`-safe.
///
/// Signatures up to [`Params::MAX_SF_SIZE`] bytes are treated as stateful;
/// larger ones as stateless.
pub fn verify<P: Params>(message: &[u8], sig: &[u8], pk: &PublicKey) -> bool {
    if sig.len() <= P::MAX_SF_SIZE {
        verify_stateful::<P>(message, sig, pk)
    } else {
        verify_stateless::<P>(message, sig, pk)
    }
}
