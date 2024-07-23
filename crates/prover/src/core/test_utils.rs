use super::backend::cpu::CpuCircleEvaluation;
use super::fields::m31::BaseField;
use super::fields::qm31::SecureField;
use crate::core::channel::sha256::BWSSha256Channel;
use crate::core::channel::Channel;
use crate::core::vcs::bws_sha256_hash::BWSSha256Hash;

pub fn secure_eval_to_base_eval<EvalOrder>(
    eval: &CpuCircleEvaluation<SecureField, EvalOrder>,
) -> CpuCircleEvaluation<BaseField, EvalOrder> {
    CpuCircleEvaluation::new(
        eval.domain,
        eval.values.iter().map(|x| x.to_m31_array()[0]).collect(),
    )
}

pub fn test_channel() -> BWSSha256Channel {
    let seed = BWSSha256Hash::from(vec![0; 32]);
    BWSSha256Channel::new(seed)
}
