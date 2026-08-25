//! Deterministic AES-256-CTR random byte generator, ported from the C++
//! `kat/rng.c` (Markku-Juhani O. Saarinen's seed expander).
//!
//! Used to reproduce the KAT byte streams. This is `std`-gated and not part of
//! the core `no_std` verification surface.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;

/// AES-256 block cipher over a single 16-byte block (ECB).
type Block = [u8; 16];

/// The AES-256 CTR seed expander state.
pub struct SeedExpander {
    key: Aes256,
    ctr: Block,
    buf: Block,
    ptr: usize,
}

impl SeedExpander {
    /// Initialize the seed expander.
    ///
    /// `seed` is a 32-byte AES key, `diversifier` is an 8-byte value, and
    /// `maxlen` is spliced into the counter bytes (big-endian into ctr[8..12]).
    pub fn init(seed: &[u8; 32], diversifier: &[u8; 8], maxlen: u32) -> Self {
        let mut ctr = [0u8; 16];
        ctr[..8].copy_from_slice(diversifier);
        ctr[8..12].copy_from_slice(&maxlen.to_be_bytes());
        // ctr[12..16] stays zero (matches C memset(ctx->ctr+12, 0, 4)).

        Self {
            key: Aes256::new_from_slice(seed).expect("AES-256 key must be 32 bytes"),
            ctr,
            buf: [0u8; 16],
            // ptr starts at 16 so the first read triggers a block generation.
            ptr: 16,
        }
    }

    /// Increment the 16-byte big-endian counter in place.
    fn increment_ctr(ctr: &mut Block) {
        for j in (0..16).rev() {
            if ctr[j] == 0xFF {
                ctr[j] = 0x00;
            } else {
                ctr[j] += 1;
                break;
            }
        }
    }

    /// Generate `xlen` bytes into `out`.
    pub fn generate(&mut self, out: &mut [u8]) {
        for byte in out.iter_mut() {
            if self.ptr >= 16 {
                Self::increment_ctr(&mut self.ctr);
                self.buf = self.ctr;
                let mut block = aes::cipher::Block::<Aes256>::default();
                block.copy_from_slice(&self.buf);
                self.key.encrypt_block(&mut block);
                self.buf.copy_from_slice(&block);
                self.ptr = 0;
            }
            *byte = self.buf[self.ptr];
            self.ptr += 1;
        }
    }
}

/// The global RNG state for `randombytes`, guarded by a mutex (std only).
static RB_STATE: std::sync::OnceLock<std::sync::Mutex<SeedExpander>> = std::sync::OnceLock::new();

/// Initialize the global RNG from a 48-byte entropy input (and optional
/// 48-byte personalization string XORed in). Mirrors C `randombytes_init`.
pub fn randombytes_init(entropy_input: &[u8; 48], personalization: Option<&[u8; 48]>) {
    let mut seed = [0u8; 48];
    seed.copy_from_slice(entropy_input);
    if let Some(pers) = personalization {
        for i in 0..48 {
            seed[i] ^= pers[i];
        }
    }

    let key: [u8; 32] = seed[..32].try_into().unwrap();
    let diversifier: [u8; 8] = seed[32..40].try_into().unwrap();
    let expander = SeedExpander::init(&key, &diversifier, 0xFFFF_FFFF);

    if let Some(cell) = RB_STATE.get() {
        let mut guard = cell.lock().unwrap();
        *guard = expander;
    } else {
        let _ = RB_STATE.set(std::sync::Mutex::new(expander));
    }
}

/// Fill `out` with deterministic bytes from the global RNG. Mirrors C
/// `randombytes`.
pub fn randombytes(out: &mut [u8]) {
    let mut guard = RB_STATE
        .get()
        .expect("randombytes_init must be called first")
        .lock()
        .unwrap();
    guard.generate(out);
}
