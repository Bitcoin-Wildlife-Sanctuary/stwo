use serde::{Deserialize, Serialize};

use super::{Backend, BackendForChannel};
use crate::core::vcs::blake3_merkle::Blake3MerkleChannel;
use crate::core::vcs::poseidon31_merkle::Poseidon31MerkleChannel;
use crate::core::vcs::sha256_merkle::Sha256MerkleChannel;

pub mod accumulation;
pub mod bit_reverse;
pub mod blake3;
pub mod circle;
pub mod cm31;
pub mod column;
pub mod domain;
pub mod fft;
pub mod fri;
mod grind;
pub mod lookups;
pub mod m31;
pub mod poseidon31;
pub mod prefix_sum;
pub mod qm31;
pub mod quotients;
pub mod sha256;
mod utils;
pub mod very_packed_m31;

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct SimdBackend;

impl Backend for SimdBackend {}
impl BackendForChannel<Sha256MerkleChannel> for SimdBackend {}
impl BackendForChannel<Blake3MerkleChannel> for SimdBackend {}
impl BackendForChannel<Poseidon31MerkleChannel> for SimdBackend {}
