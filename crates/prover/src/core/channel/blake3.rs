use crate::core::channel::{extract_common, Channel};
use crate::core::fields::cm31::CM31;
use crate::core::fields::qm31::{SecureField, QM31};
use crate::core::utils::sha256_qm31;
use crate::core::vcs::blake3_hash::{Blake3Hash, Blake3Hasher};

#[derive(Default, Clone)]
/// A channel.
pub struct Blake3Channel {
    /// Current state of the channel
    pub digest: Blake3Hash,
}

impl Blake3Channel {
    pub fn digest(&self) -> Blake3Hash {
        self.digest
    }

    pub fn update_digest(&mut self, digest: Blake3Hash) {
        self.digest = digest;
    }
}

impl Channel for Blake3Channel {
    const BYTES_PER_HASH: usize = 32;

    fn mix_felts(&mut self, felts: &[SecureField]) {
        for felt in felts.iter() {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&sha256_qm31(felt));
            hasher.update(self.digest.as_ref());
            self.update_digest(hasher.finalize().as_bytes().as_ref().into())
        }
    }

    fn mix_nonce(&mut self, nonce: u64) {
        // mix_nonce is called during PoW. However, later we plan to replace it by a Bitcoin block
        // inclusion proof, then this function would never be called.

        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&nonce.to_le_bytes());

        self.digest = Blake3Hasher::concat_and_hash(&Blake3Hash(hash), &self.digest);
    }

    fn draw_felt(&mut self) -> SecureField {
        let mut extract = [0u8; 32];

        let mut hasher = blake3::Hasher::new();
        hasher.update(self.digest.as_ref());
        hasher.update(&[0u8]);
        extract.copy_from_slice(hasher.finalize().as_bytes());

        let mut hasher = blake3::Hasher::new();
        hasher.update(self.digest.as_ref());
        self.update_digest(hasher.finalize().as_bytes().as_ref().into());

        let res_1 = extract_common(&extract);
        let res_2 = extract_common(&extract[4..]);
        let res_3 = extract_common(&extract[8..]);
        let res_4 = extract_common(&extract[12..]);

        QM31(CM31(res_1, res_2), CM31(res_3, res_4))
    }

    fn draw_felts(&mut self, n_felts: usize) -> Vec<SecureField> {
        let mut res = vec![];
        for _ in 0..n_felts {
            res.push(self.draw_felt());
        }
        res
    }

    fn draw_random_bytes(&mut self) -> Vec<u8> {
        let mut extract = [0u8; 32];

        let mut hasher = blake3::Hasher::new();
        hasher.update(self.digest.as_ref());
        hasher.update(&[0u8]);
        extract.copy_from_slice(hasher.finalize().as_bytes());

        let mut hasher = blake3::Hasher::new();
        hasher.update(self.digest.as_ref());
        self.update_digest(hasher.finalize().as_bytes().as_ref().into());

        extract.to_vec()
    }

    fn trailing_zeros(&self) -> u32 {
        let mut n_bits = 0;
        for byte in self.digest.0.iter().rev() {
            if *byte == 0 {
                n_bits += 8;
            } else {
                n_bits += byte.leading_zeros();
                break;
            }
        }
        n_bits
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::core::channel::blake3::Blake3Channel;
    use crate::core::channel::Channel;
    use crate::core::fields::qm31::SecureField;
    use crate::m31;

    #[test]
    fn test_draw_random_bytes() {
        let mut channel = Blake3Channel::default();

        let first_random_bytes = channel.draw_random_bytes();

        // Assert that next random bytes are different.
        assert_ne!(first_random_bytes, channel.draw_random_bytes());
    }

    #[test]
    pub fn test_draw_felt() {
        let mut channel = Blake3Channel::default();

        let first_random_felt = channel.draw_felt();

        // Assert that next random felt is different.
        assert_ne!(first_random_felt, channel.draw_felt());
    }

    #[test]
    pub fn test_draw_felts() {
        let mut channel = Blake3Channel::default();

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
        let mut channel = Blake3Channel::default();
        let initial_digest = channel.digest;
        let felts: Vec<SecureField> = (0..2)
            .map(|i| SecureField::from(m31!(i + 1923782)))
            .collect();

        channel.mix_felts(felts.as_slice());

        assert_ne!(initial_digest, channel.digest);
    }
}
