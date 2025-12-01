pub use crate::cut_and_choose::vanilla::groth16::DEFAULT_CAPACITY;

pub type Config = crate::cut_and_choose::Config<crate::garbled_groth16::GarblerCompressedInput>;
pub type Garbler = super::Garbler<crate::garbled_groth16::GarblerCompressedInput>;
pub type Evaluator<
    GH = crate::AesCcrGateHasher,
    LH = crate::cut_and_choose::DefaultLabelCommitHasher,
> = super::Evaluator<crate::garbled_groth16::GarblerCompressedInput, GH, LH>;

pub type EvaluatorCaseInput = crate::cut_and_choose::vanilla::EvaluatorCaseInput<
    crate::garbled_groth16::EvaluatorCompressedInput,
>;
pub type Seed = crate::cut_and_choose::Seed;

pub fn prepare_input_labels(
    garbler: &super::Garbler<crate::garbled_groth16::GarblerCompressedInput>,
    public_params: Vec<crate::ark::Fr>,
    challenge_proof: crate::garbled_groth16::SnarkProof,
    index: usize,
) -> EvaluatorCaseInput {
    let input = crate::garbled_groth16::EvaluatorCompressedInput::new(
        public_params,
        challenge_proof,
        garbler.config().input().vk.clone(),
        garbler.input_labels_for(index),
    );

    EvaluatorCaseInput { index, input }
}
