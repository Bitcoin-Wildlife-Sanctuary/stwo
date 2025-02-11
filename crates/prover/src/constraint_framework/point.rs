use std::ops::Mul;

use super::EvalAtRow;
use crate::core::air::accumulation::PointEvaluationAccumulator;
use crate::core::fields::qm31::SecureField;
use crate::core::fields::secure_column::SECURE_EXTENSION_DEGREE;
use crate::core::pcs::TreeVec;
use crate::core::ColumnVec;

/// Evaluates expressions at a point out of domain.
pub struct PointEvaluator<'a> {
    pub mask: TreeVec<&'a ColumnVec<Vec<SecureField>>>,
    pub evaluation_accumulator: &'a mut PointEvaluationAccumulator,
    pub evaluation_hint: Vec<SecureField>,
    pub col_index: Vec<usize>,
    pub denom_inverse: SecureField,
}
impl<'a> PointEvaluator<'a> {
    pub fn new(
        mask: TreeVec<&'a ColumnVec<Vec<SecureField>>>,
        evaluation_accumulator: &'a mut PointEvaluationAccumulator,
        denom_inverse: SecureField,
    ) -> Self {
        let col_index = vec![0; mask.len()];
        Self {
            mask,
            evaluation_accumulator,
            evaluation_hint: vec![],
            col_index,
            denom_inverse,
        }
    }
}
impl EvalAtRow for PointEvaluator<'_> {
    type F = SecureField;
    type EF = SecureField;

    fn next_interaction_mask<const N: usize>(
        &mut self,
        interaction: usize,
        _offsets: [isize; N],
    ) -> [Self::F; N] {
        let col_index = self.col_index[interaction];
        self.col_index[interaction] += 1;
        let mask = self.mask[interaction][col_index].clone();
        assert_eq!(mask.len(), N);
        mask.try_into().unwrap()
    }
    fn add_constraint<G>(&mut self, constraint: G)
    where
        Self::EF: Mul<G, Output = Self::EF>,
    {
        let evaluation = self.denom_inverse * constraint;
        self.evaluation_hint.push(evaluation);
        self.evaluation_accumulator.accumulate(evaluation);
    }
    fn combine_ef(values: [Self::F; SECURE_EXTENSION_DEGREE]) -> Self::EF {
        SecureField::from_partial_evals(values)
    }
}
