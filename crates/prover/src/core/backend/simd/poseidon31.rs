use itertools::Itertools;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::core::backend::simd::column::BaseColumn;
use crate::core::backend::simd::SimdBackend;
use crate::core::backend::{Column, ColumnOps};
use crate::core::vcs::ops::{MerkleHasher, MerkleOps};
use crate::core::vcs::poseidon31_hash::Poseidon31Hash;
use crate::core::vcs::poseidon31_merkle::Poseidon31MerkleHasher;

impl ColumnOps<Poseidon31Hash> for SimdBackend {
    type Column = Vec<Poseidon31Hash>;

    fn bit_reverse_column(_: &mut Self::Column) {
        unimplemented!()
    }
}

impl MerkleOps<Poseidon31MerkleHasher> for SimdBackend {
    fn commit_on_layer(
        log_size: u32,
        prev_layer: Option<&Vec<Poseidon31Hash>>,
        columns: &[&BaseColumn],
    ) -> Vec<Poseidon31Hash> {
        #[cfg(not(feature = "parallel"))]
        let iter = 0..1 << log_size;

        #[cfg(feature = "parallel")]
        let iter = (0..1 << log_size).into_par_iter();

        iter.map(|i| {
            Poseidon31MerkleHasher::hash_node(
                prev_layer.map(|prev_layer| (prev_layer[2 * i], prev_layer[2 * i + 1])),
                &columns.iter().map(|column| column.at(i)).collect_vec(),
            )
        })
        .collect()
    }
}
