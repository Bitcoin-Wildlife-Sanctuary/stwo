use sha2::{Digest, Sha256};

use crate::core::channel::Channel;
use crate::core::fields::cm31::CM31;
use crate::core::fields::m31::M31;
use crate::core::fields::qm31::{SecureField, QM31};
use crate::core::utils::bws_hash_qm31;
use crate::core::vcs::bws_sha256_hash::BWSSha256Hash;

pub const BLAKE_BYTES_PER_HASH: usize = 32;
pub const FELTS_PER_HASH: usize = 8;
pub const EXTENSION_FELTS_PER_HASH: usize = 2;

#[derive(Clone)]
/// A channel.
pub struct BWSSha256Channel {
    /// Current state of the channel.
    pub digest: BWSSha256Hash,
}

impl Channel for BWSSha256Channel {
    type Digest = BWSSha256Hash;
    const BYTES_PER_HASH: usize = 32;

    fn new(digest: Self::Digest) -> Self {
        Self { digest }
    }

    fn get_digest(&self) -> Self::Digest {
        self.digest
    }

    fn mix_digest(&mut self, digest: Self::Digest) {
        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, digest);
        Digest::update(&mut hasher, self.digest);
        self.digest.0.copy_from_slice(hasher.finalize().as_slice());
    }

    fn mix_felts(&mut self, felts: &[SecureField]) {
        for felt in felts.iter() {
            let mut hasher = Sha256::new();
            Digest::update(&mut hasher, bws_hash_qm31(felt));
            Digest::update(&mut hasher, self.digest);
            self.digest.0.copy_from_slice(hasher.finalize().as_slice());
        }
    }

    fn mix_nonce(&mut self, nonce: u64) {
        // mix_nonce is called during PoW. However, later we plan to replace it by a Bitcoin block
        // inclusion proof, then this function would never be called.

        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&nonce.to_le_bytes());

        self.mix_digest(BWSSha256Hash(hash));
    }

    fn draw_felt(&mut self) -> SecureField {
        let mut extract = [0u8; 32];

        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, self.digest);
        Digest::update(&mut hasher, [0u8]);
        extract.copy_from_slice(hasher.finalize().as_slice());

        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, self.digest);
        self.digest.0.copy_from_slice(hasher.finalize().as_slice());

        let res_1 = Self::extract_common(&extract);
        let res_2 = Self::extract_common(&extract[4..]);
        let res_3 = Self::extract_common(&extract[8..]);
        let res_4 = Self::extract_common(&extract[12..]);

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

        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, self.digest);
        Digest::update(&mut hasher, [0u8]);
        extract.copy_from_slice(hasher.finalize().as_slice());

        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, self.digest);
        self.digest.0.copy_from_slice(hasher.finalize().as_slice());

        extract.to_vec()
    }
}

impl BWSSha256Channel {
    fn extract_common(hash: &[u8]) -> M31 {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&hash[0..4]);

        let mut res = u32::from_le_bytes(bytes);
        res &= 0x7fffffff;
        res %= (1 << 31) - 1;

        M31::from(res)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::core::channel::{BWSSha256Channel, Channel};
    use crate::core::fields::qm31::SecureField;
    use crate::core::vcs::bws_sha256_hash::BWSSha256Hash;
    use crate::m31;

    #[test]
    fn test_initialize_channel() {
        let initial_digest = BWSSha256Hash::from(vec![0; 32]);
        let channel = BWSSha256Channel::new(initial_digest);

        // Assert that the channel is initialized correctly.
        assert_eq!(channel.digest, initial_digest);
    }

    #[test]
    fn test_draw_random_bytes() {
        let initial_digest = BWSSha256Hash::from(vec![1; 32]);
        let mut channel = BWSSha256Channel::new(initial_digest);

        let first_random_bytes = channel.draw_random_bytes();

        // Assert that next random bytes are different.
        assert_ne!(first_random_bytes, channel.draw_random_bytes());
    }

    #[test]
    pub fn test_draw_felt() {
        let initial_digest = BWSSha256Hash::from(vec![2; 32]);
        let mut channel = BWSSha256Channel::new(initial_digest);

        let first_random_felt = channel.draw_felt();

        // Assert that next random felt is different.
        assert_ne!(first_random_felt, channel.draw_felt());
    }

    #[test]
    pub fn test_draw_felts() {
        let initial_digest = BWSSha256Hash::from(vec![2; 32]);
        let mut channel = BWSSha256Channel::new(initial_digest);

        let mut random_felts = channel.draw_felts(5);
        random_felts.extend(channel.draw_felts(4));

        // Assert that all the random felts are unique.
        assert_eq!(
            random_felts.len(),
            random_felts.iter().collect::<BTreeSet<_>>().len()
        );
    }

    #[test]
    pub fn test_mix_digest() {
        let initial_digest = BWSSha256Hash::from(vec![0; 32]);
        let mut channel = BWSSha256Channel::new(initial_digest);

        for _ in 0..10 {
            channel.draw_random_bytes();
            channel.draw_felt();
        }

        // Reseed channel and check the digest was changed.
        channel.mix_digest(BWSSha256Hash::from(vec![1; 32]));
        assert_ne!(initial_digest, channel.digest);
    }

    #[test]
    pub fn test_mix_felts() {
        let initial_digest = BWSSha256Hash::from(vec![0; 32]);
        let mut channel = BWSSha256Channel::new(initial_digest);
        let felts: Vec<SecureField> = (0..2)
            .map(|i| SecureField::from(m31!(i + 1923782)))
            .collect();

        channel.mix_felts(felts.as_slice());

        assert_ne!(initial_digest, channel.digest);
    }
}
