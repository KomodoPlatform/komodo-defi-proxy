use serialization::hash::H256;
use sha3::{Digest, Keccak256};

/// Keccak-256
#[inline]
pub fn keccak256(input: &[u8]) -> H256 {
    let mut hasher = Keccak256::new();
    hasher.update(input);
    (*hasher.finalize()).into()
}
