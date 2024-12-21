use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::core::fields::m31::M31;

#[repr(align(32))]
#[derive(Clone, Debug, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Poseidon31Hash(pub [M31; 8]);

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

impl Poseidon31Hash {
    pub fn as_limbs(&self) -> [u32; 8] {
        [
            self.0[0].0,
            self.0[1].0,
            self.0[2].0,
            self.0[3].0,
            self.0[4].0,
            self.0[5].0,
            self.0[6].0,
            self.0[7].0,
        ]
    }
}

impl From<[u32; 8]> for Poseidon31Hash {
    fn from(value: [u32; 8]) -> Self {
        Self([
            M31::from(value[0]),
            M31::from(value[1]),
            M31::from(value[2]),
            M31::from(value[3]),
            M31::from(value[4]),
            M31::from(value[5]),
            M31::from(value[6]),
            M31::from(value[7]),
        ])
    }
}
