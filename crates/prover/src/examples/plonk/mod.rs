use itertools::{chain, Itertools};
use num_traits::One;
use tracing::{span, Level};

use crate::constraint_framework::logup::{LogupAtRow, LogupTraceGenerator, LookupElements};
use crate::constraint_framework::{EvalAtRow, FrameworkComponent};
use crate::core::backend::simd::column::BaseColumn;
use crate::core::backend::simd::m31::LOG_N_LANES;
use crate::core::backend::simd::qm31::PackedSecureField;
use crate::core::backend::simd::SimdBackend;
use crate::core::backend::{BackendForChannel, Column};
use crate::core::channel::MerkleChannel;
use crate::core::fields::m31::{BaseField, M31};
use crate::core::fields::qm31::SecureField;
use crate::core::pcs::{CommitmentSchemeProver, PcsConfig};
use crate::core::poly::circle::{CanonicCoset, CircleEvaluation, PolyOps};
use crate::core::poly::BitReversedOrder;
use crate::core::prover::{prove, StarkProof};
use crate::core::{ColumnVec, InteractionElements};

#[derive(Clone)]
pub struct PlonkComponent {
    pub log_n_rows: u32,
    pub lookup_elements: LookupElements<2>,
    pub claimed_sum: SecureField,
}

impl FrameworkComponent for PlonkComponent {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let mut logup = LogupAtRow::<2, _>::new(1, self.claimed_sum, self.log_n_rows);

        let [a_wire] = eval.next_interaction_mask(2, [0]);
        let [b_wire] = eval.next_interaction_mask(2, [0]);
        // Note: c_wire could also be implicit: (self.eval.point() - M31_CIRCLE_GEN.into_ef()).x.
        //   A constant column is easier though.
        let [c_wire] = eval.next_interaction_mask(2, [0]);
        let [op] = eval.next_interaction_mask(2, [0]);

        let mult = eval.next_trace_mask();
        let a_val = eval.next_trace_mask();
        let b_val = eval.next_trace_mask();
        let c_val = eval.next_trace_mask();

        eval.add_constraint(c_val - op * (a_val + b_val) - (E::F::one() - op) * a_val * b_val);

        logup.push_lookup(
            &mut eval,
            E::EF::one(),
            &[a_wire, a_val],
            &self.lookup_elements,
        );
        logup.push_lookup(
            &mut eval,
            E::EF::one(),
            &[b_wire, b_val],
            &self.lookup_elements,
        );
        logup.push_lookup(
            &mut eval,
            E::EF::from(-mult),
            &[c_wire, c_val],
            &self.lookup_elements,
        );

        logup.finalize(&mut eval);
        eval
    }
}

#[derive(Clone)]
pub struct PlonkCircuitTrace {
    pub mult: BaseColumn,
    pub a_wire: BaseColumn,
    pub b_wire: BaseColumn,
    pub c_wire: BaseColumn,
    pub op: BaseColumn,
    pub a_val: BaseColumn,
    pub b_val: BaseColumn,
    pub c_val: BaseColumn,
}
pub fn gen_trace(
    log_size: u32,
    circuit: &PlonkCircuitTrace,
) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    let _span = span!(Level::INFO, "Generation").entered();

    let domain = CanonicCoset::new(log_size).circle_domain();
    [
        &circuit.mult,
        &circuit.a_val,
        &circuit.b_val,
        &circuit.c_val,
    ]
    .into_iter()
    .map(|eval| CircleEvaluation::<SimdBackend, _, BitReversedOrder>::new(domain, eval.clone()))
    .collect_vec()
}

pub fn gen_interaction_trace(
    log_size: u32,
    circuit: &PlonkCircuitTrace,
    lookup_elements: &LookupElements<2>,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SecureField,
) {
    let _span = span!(Level::INFO, "Generate interaction trace").entered();
    let mut logup_gen = LogupTraceGenerator::new(log_size);

    let mut col_gen = logup_gen.new_col();
    for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
        let q0: PackedSecureField =
            lookup_elements.combine(&[circuit.a_wire.data[vec_row], circuit.a_val.data[vec_row]]);
        let q1: PackedSecureField =
            lookup_elements.combine(&[circuit.b_wire.data[vec_row], circuit.b_val.data[vec_row]]);
        col_gen.write_frac(vec_row, q0 + q1, q0 * q1);
    }
    col_gen.finalize_col();

    let mut col_gen = logup_gen.new_col();
    for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
        let p = -circuit.mult.data[vec_row];
        let q: PackedSecureField =
            lookup_elements.combine(&[circuit.c_wire.data[vec_row], circuit.c_val.data[vec_row]]);
        col_gen.write_frac(vec_row, p.into(), q);
    }
    col_gen.finalize_col();

    logup_gen.finalize()
}

pub fn prove_fibonacci_plonk<MC: MerkleChannel>(
    log_n_rows: u32,
    config: PcsConfig,
) -> (PlonkComponent, StarkProof<MC::H>)
where
    SimdBackend: BackendForChannel<MC>,
{
    assert!(log_n_rows >= LOG_N_LANES);

    // Prepare a fibonacci circuit.
    let mut fib_values = vec![BaseField::one(), BaseField::one()];
    for _ in 0..(1 << log_n_rows) {
        fib_values.push(fib_values[fib_values.len() - 1] + fib_values[fib_values.len() - 2]);
    }
    let range = 0..(1 << log_n_rows);
    let mut circuit = PlonkCircuitTrace {
        mult: range.clone().map(|_| 2.into()).collect(),
        a_wire: range.clone().map(|i| i.into()).collect(),
        b_wire: range.clone().map(|i| (i + 1).into()).collect(),
        c_wire: range.clone().map(|i| (i + 2).into()).collect(),
        op: range.clone().map(|_| 1.into()).collect(),
        a_val: range.clone().map(|i| fib_values[i]).collect(),
        b_val: range.clone().map(|i| fib_values[i + 1]).collect(),
        c_val: range.clone().map(|i| fib_values[i + 2]).collect(),
    };
    circuit.mult.set((1 << log_n_rows) - 1, 0.into());
    circuit.mult.set((1 << log_n_rows) - 2, 1.into());

    // Precompute twiddles.
    let span = span!(Level::INFO, "Precompute twiddles").entered();
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(log_n_rows + config.fri_config.log_blowup_factor + 1)
            .circle_domain()
            .half_coset,
    );
    span.exit();

    // Setup protocol.
    let channel = &mut MC::C::default();
    let commitment_scheme = &mut CommitmentSchemeProver::new(config, &twiddles);

    // Trace.
    let span = span!(Level::INFO, "Trace").entered();
    let trace = gen_trace(log_n_rows, &circuit);
    let max_degree = log_n_rows + 1;
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace, max_degree);
    tree_builder.commit(channel);
    span.exit();

    // Draw lookup element.
    let lookup_elements = LookupElements::draw(channel);

    // Interaction trace.
    let span = span!(Level::INFO, "Interaction").entered();
    let (trace, claimed_sum) = gen_interaction_trace(log_n_rows, &circuit, &lookup_elements);
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace, max_degree);
    tree_builder.commit(channel);
    span.exit();

    // Constant trace.
    let span = span!(Level::INFO, "Constant").entered();
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(
        chain!([circuit.a_wire, circuit.b_wire, circuit.c_wire, circuit.op]
            .into_iter()
            .map(|col| {
                CircleEvaluation::<SimdBackend, M31, BitReversedOrder>::new(
                    CanonicCoset::new(log_n_rows).circle_domain(),
                    col,
                )
            }))
        .collect_vec(),
        max_degree,
    );
    tree_builder.commit(channel);
    span.exit();

    // Prove constraints.
    let component = PlonkComponent {
        log_n_rows,
        lookup_elements,
        claimed_sum,
    };

    let proof = prove::<SimdBackend, MC>(
        &[&component],
        channel,
        &InteractionElements::default(),
        commitment_scheme,
    )
    .unwrap();

    (component, proof)
}

#[cfg(test)]
mod tests {
    use std::env;

    use crate::constraint_framework::logup::LookupElements;
    use crate::core::channel::blake3::Blake3Channel;
    use crate::core::channel::poseidon31::Poseidon31Channel;
    use crate::core::channel::Sha256Channel;
    use crate::core::fri::FriConfig;
    use crate::core::pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec};
    use crate::core::prover::verify;
    use crate::core::vcs::blake3_merkle::Blake3MerkleChannel;
    use crate::core::vcs::poseidon31_merkle::Poseidon31MerkleChannel;
    use crate::core::vcs::sha256_merkle::Sha256MerkleChannel;
    use crate::core::InteractionElements;
    use crate::examples::plonk::prove_fibonacci_plonk;

    #[test_log::test]
    fn test_simd_plonk_prove_blake3() {
        // Get from environment variable:
        let log_n_instances = env::var("LOG_N_INSTANCES")
            .unwrap_or_else(|_| "5".to_string())
            .parse::<u32>()
            .unwrap();
        let config = PcsConfig {
            pow_bits: 10,
            fri_config: FriConfig::new(0, 4, 64),
        };

        // Prove.
        let (component, proof) =
            prove_fibonacci_plonk::<Blake3MerkleChannel>(log_n_instances, config);

        // Verify.
        // TODO: Create Air instance independently.
        let channel = &mut Blake3Channel::default();
        let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake3MerkleChannel>::new(config);

        // Decommit.
        // Retrieve the expected column sizes in each commitment interaction, from the AIR.
        let max_degree = log_n_instances + 1;

        let sizes = TreeVec::new(vec![
            vec![max_degree; 4],
            vec![max_degree; 8],
            vec![max_degree; 4],
        ]);

        // Trace columns.
        commitment_scheme.commit(proof.commitments[0], &sizes[0], channel);
        // Draw lookup element.
        let lookup_elements = LookupElements::<2>::draw(channel);
        assert_eq!(lookup_elements, component.lookup_elements);
        // TODO(spapini): Check claimed sum against first and last instances.
        // Interaction columns.
        commitment_scheme.commit(proof.commitments[1], &sizes[1], channel);
        // Constant columns.
        commitment_scheme.commit(proof.commitments[2], &sizes[2], channel);

        verify(
            &[&component],
            channel,
            &InteractionElements::default(),
            commitment_scheme,
            proof,
        )
        .unwrap();
    }

    #[test_log::test]
    fn test_simd_plonk_prove_sha256() {
        // Get from environment variable:
        let log_n_instances = env::var("LOG_N_INSTANCES")
            .unwrap_or_else(|_| "5".to_string())
            .parse::<u32>()
            .unwrap();
        let config = PcsConfig {
            pow_bits: 10,
            fri_config: FriConfig::new(0, 4, 64),
        };

        // Prove.
        let (component, proof) =
            prove_fibonacci_plonk::<Sha256MerkleChannel>(log_n_instances, config);

        // Verify.
        // TODO: Create Air instance independently.
        let channel = &mut Sha256Channel::default();
        let commitment_scheme = &mut CommitmentSchemeVerifier::<Sha256MerkleChannel>::new(config);

        // Decommit.
        // Retrieve the expected column sizes in each commitment interaction, from the AIR.
        let max_degree = log_n_instances + 1;

        let sizes = TreeVec::new(vec![
            vec![max_degree; 4],
            vec![max_degree; 8],
            vec![max_degree; 4],
        ]);

        // Trace columns.
        commitment_scheme.commit(proof.commitments[0], &sizes[0], channel);
        // Draw lookup element.
        let lookup_elements = LookupElements::<2>::draw(channel);
        assert_eq!(lookup_elements, component.lookup_elements);
        // TODO(spapini): Check claimed sum against first and last instances.
        // Interaction columns.
        commitment_scheme.commit(proof.commitments[1], &sizes[1], channel);
        // Constant columns.
        commitment_scheme.commit(proof.commitments[2], &sizes[2], channel);

        verify(
            &[&component],
            channel,
            &InteractionElements::default(),
            commitment_scheme,
            proof,
        )
        .unwrap();
    }

    #[test_log::test]
    fn test_simd_plonk_prove_poseidon31() {
        // Get from environment variable:
        let log_n_instances = env::var("LOG_N_INSTANCES")
            .unwrap_or_else(|_| "5".to_string())
            .parse::<u32>()
            .unwrap();
        let config = PcsConfig {
            pow_bits: 10,
            fri_config: FriConfig::new(0, 4, 64),
        };

        // Prove.
        let (component, proof) =
            prove_fibonacci_plonk::<Poseidon31MerkleChannel>(log_n_instances, config);

        // Verify.
        // TODO: Create Air instance independently.
        let channel = &mut Poseidon31Channel::default();
        let commitment_scheme =
            &mut CommitmentSchemeVerifier::<Poseidon31MerkleChannel>::new(config);

        // Decommit.
        // Retrieve the expected column sizes in each commitment interaction, from the AIR.
        let max_degree = log_n_instances + 1;

        let sizes = TreeVec::new(vec![
            vec![max_degree; 4],
            vec![max_degree; 8],
            vec![max_degree; 4],
        ]);

        // Trace columns.
        commitment_scheme.commit(proof.commitments[0], &sizes[0], channel);
        // Draw lookup element.
        let lookup_elements = LookupElements::<2>::draw(channel);
        assert_eq!(lookup_elements, component.lookup_elements);
        // TODO(spapini): Check claimed sum against first and last instances.
        // Interaction columns.
        commitment_scheme.commit(proof.commitments[1], &sizes[1], channel);
        // Constant columns.
        commitment_scheme.commit(proof.commitments[2], &sizes[2], channel);

        verify(
            &[&component],
            channel,
            &InteractionElements::default(),
            commitment_scheme,
            proof,
        )
        .unwrap();
    }
}
