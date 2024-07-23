use itertools::Itertools;

use crate::core::backend::CpuBackend;
use crate::core::fields::m31::BaseField;
use crate::core::vcs::bws_sha256_hash::BWSSha256Hash;
use crate::core::vcs::bws_sha256_merkle::BWSSha256MerkleHasher;
use crate::core::vcs::ops::{MerkleHasher, MerkleOps};

impl MerkleOps<BWSSha256MerkleHasher> for CpuBackend {
    fn commit_on_layer(
        log_size: u32,
        prev_layer: Option<&Vec<BWSSha256Hash>>,
        columns: &[&Vec<BaseField>],
    ) -> Vec<BWSSha256Hash> {
        (0..(1 << log_size))
            .map(|i| {
                BWSSha256MerkleHasher::hash_node(
                    prev_layer.map(|prev_layer| (prev_layer[2 * i], prev_layer[2 * i + 1])),
                    &columns.iter().map(|column| column[i]).collect_vec(),
                )
            })
            .collect()
    }
}
