use itertools::Itertools;

use crate::core::backend::simd::column::BaseFieldVec;
use crate::core::backend::simd::SimdBackend;
use crate::core::backend::{Column, ColumnOps};
use crate::core::vcs::bws_sha256_hash::BWSSha256Hash;
use crate::core::vcs::bws_sha256_merkle::BWSSha256MerkleHasher;
use crate::core::vcs::ops::{MerkleHasher, MerkleOps};

impl ColumnOps<BWSSha256Hash> for SimdBackend {
    type Column = Vec<BWSSha256Hash>;

    fn bit_reverse_column(_column: &mut Self::Column) {
        unimplemented!()
    }
}

// TODO(BWS): not simd at all
impl MerkleOps<BWSSha256MerkleHasher> for SimdBackend {
    fn commit_on_layer(
        log_size: u32,
        prev_layer: Option<&Vec<BWSSha256Hash>>,
        columns: &[&BaseFieldVec],
    ) -> Vec<BWSSha256Hash> {
        return (0..1 << log_size)
            .map(|i| {
                BWSSha256MerkleHasher::hash_node(
                    prev_layer.map(|prev_layer| (prev_layer[2 * i], prev_layer[2 * i + 1])),
                    &columns.iter().map(|column| column.at(i)).collect_vec(),
                )
            })
            .collect();
    }
}
