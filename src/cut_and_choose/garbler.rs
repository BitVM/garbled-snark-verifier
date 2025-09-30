use std::{
    mem,
    thread::{self, JoinHandle},
};

use rand::Rng;
use rayon::{iter::IntoParallelRefIterator, prelude::*};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    AESAccumulatingHash, AesNiHasher, GarbleMode, GarbledWire, WireId,
    circuit::{
        CiphertextHandler, CircuitBuilder, CircuitInput, EncodeInput, StreamingMode,
        StreamingResult,
    },
    cut_and_choose::{
        CiphertextCommit, Config, DefaultLabelCommitHasher, LabelCommit, LabelCommitHasher, Seed,
        commit_label_with,
    },
};

#[derive(Debug, Serialize, Deserialize)]
pub struct GarbledInstance {
    /// Constant to represent false wire constant
    ///
    /// Necessary to restart the scheme and consistency
    pub false_wire_constant: GarbledWire,

    /// Constant to represent true wire constant
    ///
    /// Necessary to restart the scheme and consistency
    pub true_wire_constant: GarbledWire,

    /// Output `WireId` in return order
    pub output_wire_values: GarbledWire,

    /// Values of the input Wires, which were fed to the circuit input
    pub input_wire_values: Vec<GarbledWire>,

    pub ciphertext_handler_result: CiphertextCommit,
}

impl<I: CircuitInput>
    From<StreamingResult<GarbleMode<AesNiHasher, AESAccumulatingHash>, I, GarbledWire>>
    for GarbledInstance
{
    fn from(
        res: StreamingResult<GarbleMode<AesNiHasher, AESAccumulatingHash>, I, GarbledWire>,
    ) -> Self {
        GarbledInstance {
            false_wire_constant: res.false_wire_constant,
            true_wire_constant: res.true_wire_constant,
            output_wire_values: res.output_value,
            input_wire_values: res.input_wire_values,
            ciphertext_handler_result: res.ciphertext_handler_result,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq)]
#[serde(bound = "H: LabelCommitHasher")]
pub struct GarbledInstanceCommit<H: LabelCommitHasher = DefaultLabelCommitHasher> {
    ciphertext_commit: CiphertextCommit,
    input_labels_commit: Vec<LabelCommit<H::Output>>,
    // Separate commits for output labels: one for label1 and one for label0
    output_label1_commit: H::Output,
    output_label0_commit: H::Output,
    true_constant_commit: H::Output,
    false_constant_commit: H::Output,
}

impl<H: LabelCommitHasher> PartialEq for GarbledInstanceCommit<H> {
    fn eq(&self, other: &Self) -> bool {
        self.ciphertext_commit == other.ciphertext_commit
            && self.input_labels_commit == other.input_labels_commit
            && self.output_label1_commit == other.output_label1_commit
            && self.output_label0_commit == other.output_label0_commit
            && self.true_constant_commit == other.true_constant_commit
            && self.false_constant_commit == other.false_constant_commit
    }
}

impl<H: LabelCommitHasher> GarbledInstanceCommit<H> {
    pub fn new(instance: &GarbledInstance) -> Self {
        Self {
            ciphertext_commit: instance.ciphertext_handler_result,
            input_labels_commit: Self::commit_garbled_wires(&instance.input_wire_values),

            output_label1_commit: Self::commit_label1(&instance.output_wire_values),

            output_label0_commit: Self::commit_label0(&instance.output_wire_values),

            true_constant_commit: commit_label_with::<H>(instance.true_wire_constant.select(true)),
            false_constant_commit: commit_label_with::<H>(
                instance.false_wire_constant.select(false),
            ),
        }
    }

    pub fn commit_garbled_wires(inputs: &[GarbledWire]) -> Vec<LabelCommit<H::Output>> {
        inputs
            .iter()
            .map(|GarbledWire { label0, label1 }| {
                LabelCommit::<H::Output>::new::<H>(*label0, *label1)
            })
            .collect()
    }

    fn commit_label1(input: &GarbledWire) -> H::Output {
        commit_label_with::<H>(input.label1)
    }

    fn commit_label0(input: &GarbledWire) -> H::Output {
        commit_label_with::<H>(input.label0)
    }

    pub fn output_label1_commit(&self) -> H::Output {
        self.output_label1_commit
    }

    pub fn output_label0_commit(&self) -> H::Output {
        self.output_label0_commit
    }

    pub fn true_consatnt_wire_commit(&self) -> H::Output {
        self.true_constant_commit
    }

    pub fn false_consatnt_wire_commit(&self) -> H::Output {
        self.false_constant_commit
    }

    pub fn ciphertext_commit(&self) -> CiphertextCommit {
        self.ciphertext_commit
    }

    pub fn input_labels_commit(&self) -> &[LabelCommit<H::Output>] {
        &self.input_labels_commit
    }
}

pub enum OpenForInstance {
    Open(usize, Seed),
    Closed {
        index: usize,
        garbling_thread: JoinHandle<()>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum GarblerStage {
    Generating { seeds: Box<[Seed]> },
    PreparedForEval { indexes_to_eval: Box<[usize]> },
}

impl GarblerStage {
    fn next_stage(&mut self, indexes_to_eval: Box<[usize]>) -> Box<[Seed]> {
        assert!(matches!(self, Self::Generating { .. }));

        let mut n = GarblerStage::PreparedForEval { indexes_to_eval };

        mem::swap(self, &mut n);

        match n {
            Self::Generating { seeds } => seeds,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Garbler<I: CircuitInput + Clone> {
    stage: GarblerStage,
    instances: Vec<GarbledInstance>,
    config: Config<I>,
    live_capacity: usize,
}

impl<I> Garbler<I>
where
    I: CircuitInput
        + Clone
        + Send
        + Sync
        + EncodeInput<GarbleMode<AesNiHasher, AESAccumulatingHash>>,
    <I as CircuitInput>::WireRepr: Send,
    I: 'static,
{
    /// Create garbled instances in parallel using the provided circuit builder function.
    pub fn create<F>(mut rng: impl Rng, config: Config<I>, live_capacity: usize, builder: F) -> Self
    where
        F: Fn(
                &mut StreamingMode<GarbleMode<AesNiHasher, AESAccumulatingHash>>,
                &I::WireRepr,
            ) -> WireId
            + Send
            + Sync
            + Copy,
    {
        let seeds = (0..config.total)
            .map(|_| rng.r#gen())
            .collect::<Box<[Seed]>>();

        // Use optimized thread pool internally
        let instances: Vec<_> = super::get_optimized_pool().install(|| {
            seeds
                .par_iter()
                .enumerate()
                .map(|(index, garbling_seed)| {
                    let inputs = config.input.clone();
                    let hasher = AESAccumulatingHash::default();

                    let span = tracing::info_span!("garble", instance = index);
                    let _enter = span.enter();

                    info!("Starting garbling of circuit (cut-and-choose)");

                    let res: StreamingResult<
                        GarbleMode<AesNiHasher, AESAccumulatingHash>,
                        I,
                        GarbledWire,
                    > = CircuitBuilder::streaming_garbling(
                        inputs,
                        live_capacity,
                        *garbling_seed,
                        hasher,
                        builder,
                    );

                    GarbledInstance::from(res)
                })
                .collect()
        });

        Self {
            stage: GarblerStage::Generating { seeds },
            instances,
            live_capacity,
            config,
        }
    }

    pub fn commit(&self) -> Vec<GarbledInstanceCommit> {
        self.commit_with_hasher::<DefaultLabelCommitHasher>()
    }

    pub fn commit_with_hasher<HHasher>(&self) -> Vec<GarbledInstanceCommit<HHasher>>
    where
        HHasher: LabelCommitHasher,
    {
        // Build commits in parallel; independent per instance
        self.instances
            .iter()
            .map(GarbledInstanceCommit::<HHasher>::new)
            .collect()
    }

    pub fn open_commit<F, CTH: 'static + Send + CiphertextHandler>(
        &mut self,
        mut indexes_to_finalize: Vec<(usize, CTH)>,
        builder: F,
    ) -> Vec<OpenForInstance>
    where
        F: 'static
            + Fn(&mut StreamingMode<GarbleMode<AesNiHasher, CTH>>, &I::WireRepr) -> WireId
            + Send
            + Sync
            + Copy,
        I: EncodeInput<GarbleMode<AesNiHasher, CTH>>,
    {
        let seeds = self
            .stage
            .next_stage(indexes_to_finalize.iter().map(|(i, _)| *i).collect());

        // TODO #37 Since at this point the number but finalization is no more than 7, we just run
        // threads here, without rayon
        seeds
            .iter()
            .enumerate()
            .map(|(index, garbling_seed)| {
                let pos = indexes_to_finalize
                    .iter()
                    .position(|(index_to_eval, _sender)| index_to_eval.eq(&index));

                if let Some(pos) = pos {
                    let sender = indexes_to_finalize.remove(pos).1;

                    let inputs = self.config.input.clone();
                    let garbling_seed = *garbling_seed;

                    let live_capacity = self.live_capacity;

                    let garbling_thread = thread::spawn(move || {
                        let _span =
                            tracing::info_span!("regarble2send", instance = index).entered();

                        info!("Starting");

                        let _: StreamingResult<_, I, GarbledWire> =
                            CircuitBuilder::<GarbleMode<AesNiHasher, _>>::streaming_garbling(
                                inputs,
                                live_capacity,
                                garbling_seed,
                                sender,
                                builder,
                            );
                    });

                    OpenForInstance::Closed {
                        index,
                        garbling_thread,
                    }
                } else {
                    OpenForInstance::Open(index, *garbling_seed)
                }
            })
            .collect()
    }

    /// Return the constant labels for true/false as u128 words for a given instance.
    pub fn true_wire_constant_for(&self, index: usize) -> u128 {
        self.instances[index]
            .true_wire_constant
            .select(true)
            .to_u128()
    }

    /// Return the constant labels for true/false as u128 words for a given instance.
    pub fn false_wire_constant_for(&self, index: usize) -> u128 {
        self.instances[index]
            .false_wire_constant
            .select(false)
            .to_u128()
    }

    /// Return a clone of the input garbled labels for a given instance.
    pub fn input_labels_for(&self, index: usize) -> Vec<GarbledWire> {
        self.instances[index].input_wire_values.clone()
    }

    pub fn config(&self) -> &Config<I> {
        &self.config
    }

    pub fn stage(&self) -> &GarblerStage {
        &self.stage
    }

    pub fn output_wire(&self, index: usize) -> Option<&GarbledWire> {
        self.instances.get(index).map(|gw| &gw.output_wire_values)
    }
}
