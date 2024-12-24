use poseidon2_m31::Poseidon31Sponge;

use crate::core::channel::Channel;
use crate::core::fields::m31::BaseField;
use crate::core::fields::qm31::SecureField;
use crate::core::fields::secure_column::SECURE_EXTENSION_DEGREE;

#[derive(Clone, Default)]
pub struct Poseidon31Channel {
    pub sponge: Poseidon31Sponge,
}

impl Poseidon31Channel {
    fn draw_base_felts(&mut self) -> [BaseField; 4] {
        let u32s = self.sponge.squeeze(4);

        [
            BaseField::from(u32s[0]),
            BaseField::from(u32s[1]),
            BaseField::from(u32s[2]),
            BaseField::from(u32s[3]),
        ]
    }
}

impl Channel for Poseidon31Channel {
    const BYTES_PER_HASH: usize = 32;

    fn trailing_zeros(&self) -> u32 {
        let res = &self.sponge.state[8..12];

        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&res[0].to_le_bytes());
        bytes[4..8].copy_from_slice(&res[1].to_le_bytes());
        bytes[8..12].copy_from_slice(&res[2].to_le_bytes());
        bytes[12..16].copy_from_slice(&res[3].to_le_bytes());

        u128::from_le_bytes(bytes).trailing_zeros()
    }

    fn mix_felts(&mut self, felts: &[SecureField]) {
        let mut inputs = Vec::with_capacity(felts.len() * 4);

        for felt in felts.iter() {
            inputs.push(felt.0 .0 .0);
            inputs.push(felt.0 .1 .0);
            inputs.push(felt.1 .0 .0);
            inputs.push(felt.1 .1 .0);
        }

        self.sponge.absorb(&inputs);
    }

    fn mix_nonce(&mut self, nonce: u64) {
        let n1 = nonce % ((1 << 22) - 1); // 22 bytes
        let n2 = (nonce >> 22) & ((1 << 21) - 1); // 21 bytes
        let n3 = (nonce >> 43) & ((1 << 21) - 1); // 21 bytes

        self.sponge.absorb(&[n1 as u32, n2 as u32, n3 as u32, 0]);
    }

    fn draw_felt(&mut self) -> SecureField {
        let felts: [BaseField; 4] = self.draw_base_felts();
        SecureField::from_m31_array(felts[..SECURE_EXTENSION_DEGREE].try_into().unwrap())
    }

    fn draw_felts(&mut self, n_felts: usize) -> Vec<SecureField> {
        let mut res = vec![];
        for _ in 0..n_felts {
            res.push(self.draw_felt());
        }
        res
    }

    fn draw_random_bytes(&mut self) -> Vec<u8> {
        // the implementation here is based on the assumption that the only place draw_random_bytes
        // will be used is in generating the queries, where only the lowest n bits of every 4 bytes
        // slice would be used.
        let elems = self.sponge.squeeze(8);

        let mut res = Vec::with_capacity(32);
        for elem in elems.iter() {
            res.extend_from_slice(&elem.to_le_bytes());
        }

        res
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::core::channel::poseidon31::Poseidon31Channel;
    use crate::core::channel::Channel;
    use crate::core::fields::qm31::SecureField;
    use crate::m31;

    #[test]
    fn test_draw_random_bytes() {
        let mut channel = Poseidon31Channel::default();

        let first_random_bytes = channel.draw_random_bytes();

        // Assert that next random bytes are different.
        assert_ne!(first_random_bytes, channel.draw_random_bytes());
    }

    #[test]
    pub fn test_draw_felt() {
        let mut channel = Poseidon31Channel::default();

        let first_random_felt = channel.draw_felt();

        // Assert that next random felt is different.
        assert_ne!(first_random_felt, channel.draw_felt());
    }

    #[test]
    pub fn test_draw_felts() {
        let mut channel = Poseidon31Channel::default();

        let mut random_felts = channel.draw_felts(5);
        random_felts.extend(channel.draw_felts(4));

        // Assert that all the random felts are unique.
        assert_eq!(
            random_felts.len(),
            random_felts.iter().collect::<BTreeSet<_>>().len()
        );
    }

    #[test]
    pub fn test_mix_felts() {
        let mut channel = Poseidon31Channel::default();
        let initial_digest = channel.sponge.state;
        let felts: Vec<SecureField> = (0..2)
            .map(|i| SecureField::from(m31!(i + 1923782)))
            .collect();

        channel.mix_felts(felts.as_slice());
        // this works because aftering mixing with 8 elements, the state should be updated

        assert!(channel.sponge.buffer.is_empty());
        assert_ne!(initial_digest, channel.sponge.state);
    }
}
