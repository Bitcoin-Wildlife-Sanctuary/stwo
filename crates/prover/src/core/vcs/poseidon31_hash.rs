use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::core::fields::m31::M31;

#[repr(align(32))]
#[derive(Clone, Debug, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Poseidon31Hash(pub(crate) [M31; 8]);

impl From<Poseidon31Hash> for Vec<u8> {
    fn from(value: Poseidon31Hash) -> Vec<u8> {
        let mut res = vec![];
        for limb in value.0.iter() {
            res.extend(limb.0.to_le_bytes());
        }
        res
    }
}

impl std::fmt::Display for Poseidon31Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Poseidon31Hash as Debug>::fmt(self, f)
    }
}

impl super::hash::Hash for Poseidon31Hash {}
