use poseidon2_m31::Poseidon31CRH;
use serde::{Deserialize, Serialize};

use crate::core::channel::poseidon31::Poseidon31Channel;
use crate::core::channel::{Channel, MerkleChannel};
use crate::core::fields::m31::BaseField;
use crate::core::fields::qm31::SecureField;
use crate::core::vcs::ops::MerkleHasher;
use crate::core::vcs::poseidon31_hash::Poseidon31Hash;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default, Deserialize, Serialize)]
pub struct Poseidon31MerkleHasher;
impl MerkleHasher for Poseidon31MerkleHasher {
    type Hash = Poseidon31Hash;

    fn hash_node(
        children_hashes: Option<(Self::Hash, Self::Hash)>,
        column_values: &[BaseField],
    ) -> Self::Hash {
        let column_hash = if column_values.is_empty() {
            None
        } else {
            let mut data = Vec::with_capacity(column_values.len());
            for column_value in column_values.iter() {
                data.push(column_value.0);
            }
            Some(Poseidon31CRH::hash_fixed_length(&data))
        };

        match (children_hashes, column_hash) {
            (Some(children_hashes), Some(column_hash)) => {
                let mut data = [0u32; 24];
                data[0..8].copy_from_slice(&children_hashes.0.as_limbs());
                data[8..16].copy_from_slice(&column_hash);
                data[16..24].copy_from_slice(&children_hashes.1.as_limbs());
                Poseidon31CRH::hash_fixed_length(&data).into()
            }
            (Some(children_hashes), None) => {
                let mut data = [0u32; 16];
                data[0..8].copy_from_slice(&children_hashes.0.as_limbs());
                data[8..16].copy_from_slice(&children_hashes.1.as_limbs());
                Poseidon31CRH::hash_fixed_length(&data).into()
            }
            (None, Some(column_hash)) => {
                // omit this hash assuming that we always know a leaf is a leaf
                // which is the case in FRI protocols, but not for the general usage
                column_hash.into()
            }
            (None, None) => unreachable!(),
        }
    }
}

#[derive(Default)]
pub struct Poseidon31MerkleChannel;

impl MerkleChannel for Poseidon31MerkleChannel {
    type C = Poseidon31Channel;
    type H = Poseidon31MerkleHasher;

    fn mix_root(channel: &mut Self::C, root: <Self::H as MerkleHasher>::Hash) {
        let r1 = SecureField::from_m31(root.0[0], root.0[1], root.0[2], root.0[3]);
        let r2 = SecureField::from_m31(root.0[4], root.0[5], root.0[6], root.0[7]);
        channel.mix_felts(&[r1, r2]);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use itertools::Itertools;
    use num_traits::Zero;
    use rand::rngs::SmallRng;
    use rand::{Rng, SeedableRng};

    use crate::core::backend::CpuBackend;
    use crate::core::fields::m31::BaseField;
    use crate::core::vcs::poseidon31_hash::Poseidon31Hash;
    use crate::core::vcs::poseidon31_merkle::Poseidon31MerkleHasher;
    use crate::core::vcs::prover::{MerkleDecommitment, MerkleProver};
    use crate::core::vcs::verifier::{MerkleVerificationError, MerkleVerifier};

    type TestData = (
        BTreeMap<u32, Vec<usize>>,
        MerkleDecommitment<Poseidon31MerkleHasher>,
        Vec<Vec<BaseField>>,
        MerkleVerifier<Poseidon31MerkleHasher>,
    );
    fn prepare_merkle() -> TestData {
        const N_COLS: usize = 400;
        const N_QUERIES: usize = 7;
        let log_size_range = 6..9;

        let mut rng = SmallRng::seed_from_u64(0);
        let log_sizes = (0..N_COLS)
            .map(|_| rng.gen_range(log_size_range.clone()))
            .collect_vec();
        let cols = log_sizes
            .iter()
            .map(|&log_size| {
                (0..(1 << log_size))
                    .map(|_| BaseField::from(rng.gen_range(0..(1 << 30))))
                    .collect_vec()
            })
            .collect_vec();
        let merkle =
            MerkleProver::<CpuBackend, Poseidon31MerkleHasher>::commit(cols.iter().collect_vec());

        let mut queries = BTreeMap::<u32, Vec<usize>>::new();
        for log_size in log_size_range.rev() {
            let layer_queries = (0..N_QUERIES)
                .map(|_| rng.gen_range(0..(1 << log_size)))
                .sorted()
                .dedup()
                .collect_vec();
            queries.insert(log_size, layer_queries);
        }

        let (values, decommitment) = merkle.decommit(queries.clone(), cols.iter().collect_vec());

        let verifier = MerkleVerifier {
            root: merkle.root(),
            column_log_sizes: log_sizes,
        };
        (queries, decommitment, values, verifier)
    }

    #[test]
    fn test_merkle_success() {
        let (queries, decommitment, values, verifier) = prepare_merkle();

        verifier.verify(queries, values, decommitment).unwrap();
    }

    #[test]
    fn test_merkle_invalid_witness() {
        let (queries, mut decommitment, values, verifier) = prepare_merkle();
        decommitment.hash_witness[20] = Poseidon31Hash::default();

        assert_eq!(
            verifier.verify(queries, values, decommitment).unwrap_err(),
            MerkleVerificationError::RootMismatch
        );
    }

    #[test]
    fn test_merkle_invalid_value() {
        let (queries, decommitment, mut values, verifier) = prepare_merkle();
        values[3][6] = BaseField::zero();

        assert_eq!(
            verifier.verify(queries, values, decommitment).unwrap_err(),
            MerkleVerificationError::RootMismatch
        );
    }

    #[test]
    fn test_merkle_witness_too_short() {
        let (queries, mut decommitment, values, verifier) = prepare_merkle();
        decommitment.hash_witness.pop();

        assert_eq!(
            verifier.verify(queries, values, decommitment).unwrap_err(),
            MerkleVerificationError::WitnessTooShort
        );
    }

    #[test]
    fn test_merkle_column_values_too_long() {
        let (queries, decommitment, mut values, verifier) = prepare_merkle();
        values[3].push(BaseField::zero());

        assert_eq!(
            verifier.verify(queries, values, decommitment).unwrap_err(),
            MerkleVerificationError::ColumnValuesTooLong
        );
    }

    #[test]
    fn test_merkle_column_values_too_short() {
        let (queries, decommitment, mut values, verifier) = prepare_merkle();
        values[3].pop();

        assert_eq!(
            verifier.verify(queries, values, decommitment).unwrap_err(),
            MerkleVerificationError::ColumnValuesTooShort
        );
    }

    #[test]
    fn test_merkle_witness_too_long() {
        let (queries, mut decommitment, values, verifier) = prepare_merkle();
        decommitment.hash_witness.push(Poseidon31Hash::default());

        assert_eq!(
            verifier.verify(queries, values, decommitment).unwrap_err(),
            MerkleVerificationError::WitnessTooLong
        );
    }
}
