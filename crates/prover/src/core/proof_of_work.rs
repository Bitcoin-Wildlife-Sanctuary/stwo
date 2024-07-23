use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{span, Level};

use crate::core::channel::sha256::BWSSha256Channel;
use crate::core::channel::Channel;
use crate::core::vcs::bws_sha256_hash::{BWSSha256Hash, BWSSha256Hasher};
use crate::core::vcs::hasher::Hasher;

// TODO(ShaharS): generalize to more channels and create a from function in the hash traits.
pub struct ProofOfWork {
    // Proof of work difficulty.
    pub n_bits: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofOfWorkProof {
    pub nonce: u64,
}

impl ProofOfWork {
    pub fn new(n_bits: u32) -> Self {
        Self { n_bits }
    }

    pub fn prove(&self, channel: &mut BWSSha256Channel) -> ProofOfWorkProof {
        let _span = span!(Level::INFO, "Proof of work").entered();
        let seed = channel.get_digest().as_ref().to_vec();
        let proof = self.grind(seed);
        channel.mix_nonce(proof.nonce);
        proof
    }

    pub fn verify(
        &self,
        channel: &mut BWSSha256Channel,
        proof: &ProofOfWorkProof,
    ) -> Result<(), ProofOfWorkVerificationError> {
        let seed = channel.get_digest().as_ref().to_vec();
        let verified = check_leading_zeros(
            self.hash_with_nonce(&seed, proof.nonce).as_ref(),
            self.n_bits,
        );

        if !verified {
            return Err(ProofOfWorkVerificationError::ProofOfWorkVerificationFailed);
        }

        channel.mix_nonce(proof.nonce);
        Ok(())
    }

    fn grind(&self, seed: Vec<u8>) -> ProofOfWorkProof {
        let mut nonce = 0u64;
        // TODO(ShaharS): naive implementation, should be replaced with a parallel one.
        loop {
            let hash = self.hash_with_nonce(&seed, nonce);
            if check_leading_zeros(hash.as_ref(), self.n_bits) {
                return ProofOfWorkProof { nonce };
            }
            nonce += 1;
        }
    }

    fn hash_with_nonce(&self, seed: &[u8], nonce: u64) -> BWSSha256Hash {
        let hash_input = seed
            .iter()
            .chain(nonce.to_le_bytes().iter())
            .cloned()
            .collect::<Vec<_>>();
        BWSSha256Hasher::hash(&hash_input)
    }
}

/// Check that the prefix leading zeros is greater than `bound_bits`.
fn check_leading_zeros(bytes: &[u8], bound_bits: u32) -> bool {
    let mut n_bits = 0;
    // bytes are in little endian order.
    for byte in bytes.iter().rev() {
        if *byte == 0 {
            n_bits += 8;
        } else {
            n_bits += byte.leading_zeros();
            break;
        }
    }
    n_bits >= bound_bits
}

#[derive(Clone, Copy, Debug, Error)]
pub enum ProofOfWorkVerificationError {
    #[error("Proof of work verification failed.")]
    ProofOfWorkVerificationFailed,
}

#[cfg(test)]
mod tests {
    use crate::core::channel::{BWSSha256Channel, Channel};
    use crate::core::proof_of_work::{ProofOfWork, ProofOfWorkProof};
    use crate::core::vcs::bws_sha256_hash::BWSSha256Hash;

    #[test]
    fn test_verify_proof_of_work_success() {
        let mut channel = BWSSha256Channel::new(BWSSha256Hash::from(vec![0; 32]));

        let proof_of_work_prover = ProofOfWork { n_bits: 11 };
        let proof = ProofOfWorkProof { nonce: 3566 };

        proof_of_work_prover.verify(&mut channel, &proof).unwrap();
    }

    #[test]
    fn test_verify_proof_of_work_fail() {
        let mut channel = BWSSha256Channel::new(BWSSha256Hash::from(vec![0; 32]));
        let proof_of_work_prover = ProofOfWork { n_bits: 1 };
        let invalid_proof = ProofOfWorkProof { nonce: 0 };

        proof_of_work_prover
            .verify(&mut channel, &invalid_proof)
            .unwrap_err();
    }

    #[test]
    fn test_proof_of_work() {
        let n_bits = 12;
        let mut prover_channel = BWSSha256Channel::new(BWSSha256Hash::default());
        let mut verifier_channel = BWSSha256Channel::new(BWSSha256Hash::default());
        let prover = ProofOfWork::new(n_bits);
        let verifier = ProofOfWork::new(n_bits);

        let proof = prover.prove(&mut prover_channel);
        verifier.verify(&mut verifier_channel, &proof).unwrap();

        assert_eq!(prover_channel.get_digest(), verifier_channel.get_digest());
    }
}
