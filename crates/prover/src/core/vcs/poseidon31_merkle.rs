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
