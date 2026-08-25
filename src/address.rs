//! SHRINCS address manipulation.
//!
//! An [`Adrs`] is a fixed 32-byte domain-separation value. Its fields (written
//! big-endian, matching the C++ `htonl`/`htobe64` calls) occupy fixed offsets:
//!
//! | offset | size | field       |
//! |--------|------|-------------|
//! | 0      | 4    | layer       |
//! | 4      | 4    | tree (low)  |
//! | 8      | 8    | tree (high) |
//! | 16     | 4    | type        |
//! | 20     | 4    | key pair    |
//! | 24     | 4    | chain/height|
//! | 28     | 4    | hash/index  |

/// A 32-byte SHRINCS address.
pub type Adrs = [u8; 32];

/// Set the layer address (offset 0, big-endian `u32`).
pub fn set_layer_address(adrs: &mut Adrs, layer: u32) {
    adrs[0..4].copy_from_slice(&layer.to_be_bytes());
}

/// Set the tree address (offset 4 `u32` big-endian, offset 8 `u64` big-endian).
pub fn set_tree_address(adrs: &mut Adrs, tree_addr1: u32, tree_addr2: u64) {
    adrs[4..8].copy_from_slice(&tree_addr1.to_be_bytes());
    adrs[8..16].copy_from_slice(&tree_addr2.to_be_bytes());
}

/// Set the type field (offset 16) and zero out offsets 20..32.
pub fn set_type_and_clear(adrs: &mut Adrs, ty: u32) {
    adrs[16..20].copy_from_slice(&ty.to_be_bytes());
    adrs[20..32].fill(0);
}

/// Set the key-pair address (offset 20, big-endian `u32`).
pub fn set_key_pair_address(adrs: &mut Adrs, keypair: u32) {
    adrs[20..24].copy_from_slice(&keypair.to_be_bytes());
}

/// Set the chain address (offset 24, big-endian `u32`).
pub fn set_chain_address(adrs: &mut Adrs, chain: u32) {
    adrs[24..28].copy_from_slice(&chain.to_be_bytes());
}

/// Set the hash address (offset 28, big-endian `u32`).
pub fn set_hash_address(adrs: &mut Adrs, hash: u32) {
    adrs[28..32].copy_from_slice(&hash.to_be_bytes());
}

/// Set the tree height (offset 24, big-endian `u32`).
pub fn set_tree_height(adrs: &mut Adrs, height: u32) {
    adrs[24..28].copy_from_slice(&height.to_be_bytes());
}

/// Set the tree index (offset 28, big-endian `u32`).
pub fn set_tree_index(adrs: &mut Adrs, index: u32) {
    adrs[28..32].copy_from_slice(&index.to_be_bytes());
}
