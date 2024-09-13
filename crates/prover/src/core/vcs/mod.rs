//! Vector commitment scheme (VCS) module.

pub mod hash;
pub mod ops;
#[cfg(not(target_arch = "wasm32"))]
pub mod poseidon252_merkle;
pub mod prover;
pub mod sha256_hash;
pub mod sha256_merkle;
mod utils;
pub mod verifier;

#[cfg(test)]
mod test_utils;
