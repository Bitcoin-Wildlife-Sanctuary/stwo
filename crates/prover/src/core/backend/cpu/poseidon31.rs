use itertools::Itertools;

use crate::core::backend::CpuBackend;
use crate::core::fields::m31::BaseField;
use crate::core::vcs::ops::{MerkleHasher, MerkleOps};
use crate::core::vcs::poseidon31_hash::Poseidon31Hash;
use crate::core::vcs::poseidon31_merkle::Poseidon31MerkleHasher;

impl MerkleOps<Poseidon31MerkleHasher> for CpuBackend {
    fn commit_on_layer(
        log_size: u32,
        prev_layer: Option<&Vec<Poseidon31Hash>>,
        columns: &[&Vec<BaseField>],
    ) -> Vec<Poseidon31Hash> {
        (0..(1 << log_size))
            .map(|i| {
                Poseidon31MerkleHasher::hash_node(
                    prev_layer.map(|prev_layer| (prev_layer[2 * i], prev_layer[2 * i + 1])),
                    &columns.iter().map(|column| column[i]).collect_vec(),
                )
            })
            .collect()
    }
}
