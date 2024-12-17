use super::fields::qm31::SecureField;
use super::vcs::ops::MerkleHasher;

#[cfg(not(target_arch = "wasm32"))]
mod poseidon252;
#[cfg(not(target_arch = "wasm32"))]
pub use poseidon252::Poseidon252Channel;

pub mod sha256;
pub use sha256::Sha256Channel;

use crate::core::fields::m31::M31;

pub mod blake3;
pub use blake3::Blake3Channel;

pub mod poseidon31;

pub const EXTENSION_FELTS_PER_HASH: usize = 2;

#[derive(Clone, Default)]
#[allow(unused)]
pub struct ChannelTime {
    pub n_challenges: usize,
    n_sent: usize,
}

#[allow(unused)]
impl ChannelTime {
    fn inc_sent(&mut self) {
        self.n_sent += 1;
    }

    fn inc_challenges(&mut self) {
        self.n_challenges += 1;
        self.n_sent = 0;
    }
}

pub trait Channel: Default + Clone {
    const BYTES_PER_HASH: usize;

    fn trailing_zeros(&self) -> u32;

    // Mix functions.
    fn mix_felts(&mut self, felts: &[SecureField]);
    fn mix_nonce(&mut self, nonce: u64);

    // Draw functions.
    fn draw_felt(&mut self) -> SecureField;
    /// Generates a uniform random vector of SecureField elements.
    fn draw_felts(&mut self, n_felts: usize) -> Vec<SecureField>;
    /// Returns a vector of random bytes of length `BYTES_PER_HASH`.
    fn draw_random_bytes(&mut self) -> Vec<u8>;
}

pub trait MerkleChannel: Default {
    type C: Channel;
    type H: MerkleHasher;
    fn mix_root(channel: &mut Self::C, root: <Self::H as MerkleHasher>::Hash);
}

pub(crate) fn extract_common(hash: &[u8]) -> M31 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&hash[0..4]);

    let mut res = u32::from_le_bytes(bytes);
    res &= 0x7fffffff;
    res %= (1 << 31) - 1;

    M31::from(res)
}
