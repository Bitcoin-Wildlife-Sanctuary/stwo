use itertools::Itertools;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::core::backend::simd::column::BaseColumn;
use crate::core::backend::simd::SimdBackend;
use crate::core::backend::{Column, ColumnOps};
use crate::core::vcs::blake3_hash::Blake3Hash;
use crate::core::vcs::blake3_merkle::Blake3MerkleHasher;
use crate::core::vcs::ops::{MerkleHasher, MerkleOps};

impl ColumnOps<Blake3Hash> for SimdBackend {
    type Column = Vec<Blake3Hash>;

    fn bit_reverse_column(_column: &mut Self::Column) {
        unimplemented!()
    }
}

// TODO(BWS): not simd at all
impl MerkleOps<Blake3MerkleHasher> for SimdBackend {
    fn commit_on_layer(
        log_size: u32,
        prev_layer: Option<&Vec<Blake3Hash>>,
        columns: &[&BaseColumn],
    ) -> Vec<Blake3Hash> {
        #[cfg(not(feature = "parallel"))]
        let iter = 0..1 << log_size;

        #[cfg(feature = "parallel")]
        let iter = (0..1 << log_size).into_par_iter();

        iter.map(|i| {
            Blake3MerkleHasher::hash_node(
                prev_layer.map(|prev_layer| (prev_layer[2 * i], prev_layer[2 * i + 1])),
                &columns.iter().map(|column| column.at(i)).collect_vec(),
            )
        })
        .collect()
    }
}
