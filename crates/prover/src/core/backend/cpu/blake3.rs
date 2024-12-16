use itertools::Itertools;

use crate::core::backend::CpuBackend;
use crate::core::fields::m31::BaseField;
use crate::core::vcs::blake3_hash::Blake3Hash;
use crate::core::vcs::blake3_merkle::Blake3MerkleHasher;
use crate::core::vcs::ops::{MerkleHasher, MerkleOps};

impl MerkleOps<Blake3MerkleHasher> for CpuBackend {
    fn commit_on_layer(
        log_size: u32,
        prev_layer: Option<&Vec<Blake3Hash>>,
        columns: &[&Vec<BaseField>],
    ) -> Vec<Blake3Hash> {
        (0..(1 << log_size))
            .map(|i| {
                Blake3MerkleHasher::hash_node(
                    prev_layer.map(|prev_layer| (prev_layer[2 * i], prev_layer[2 * i + 1])),
                    &columns.iter().map(|column| column[i]).collect_vec(),
                )
            })
            .collect()
    }
}
