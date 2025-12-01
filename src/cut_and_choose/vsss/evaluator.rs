//! VSSS-specific Evaluator for the cut-and-choose Setup phase.
//!
//! This module provides the VSSS (Verifiable Secret Sharing Scheme) evaluator
//! which uses polynomial commitments and share verification.

use itertools::*;
use rand::Rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tracing::{error, info};

use super::{
    OpenVsssInstance, PolynomialCommits, Secp256k1, ShareCommits, VsssCommit,
    garbler::InstanceWideLabelLookup, wide_garbling::GarbledWideLabelTable,
};
use crate::{
    AesCcrGateHasher, Blake3AccumulatingHash, EvaluatedWire, GarbleMode, GarbledWire, S, WireId,
    circuit::{
        CiphertextHandler, CiphertextSource, CircuitBuilder, CircuitInput, EncodeInput,
        StreamingMode, StreamingResult, modes::EvaluateMode,
    },
    cut_and_choose::{
        CiphertextCommit, CiphertextHandlerProvider, CiphertextSourceProvider, Config,
        DefaultLabelCommitHasher, LabelCommitHasher, commit_label_with,
        vanilla::{CommitPhaseOne, ConsistencyError, EvaluatorCaseInput, GarbledInstance},
    },
    hashers::GateHasher,
};

/// VSSS-specific evaluator stage.
#[derive(Default, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "GH: GateHasher, LH: LabelCommitHasher")]
pub enum Stage<GH: GateHasher, LH: LabelCommitHasher> {
    #[default]
    Empty,
    Vsss {
        commits: VsssCommit<GH, LH>,
    },
}

impl<GH: GateHasher, LH: LabelCommitHasher> Stage<GH, LH> {
    fn get_commit_if_ready(&self, regarbled: bool) -> Option<&[CommitPhaseOne<GH, LH>]> {
        if !regarbled {
            return None;
        }
        match self {
            Stage::Empty => None,
            Stage::Vsss {
                commits: VsssCommit {
                    circuit_commits, ..
                },
            } => Some(circuit_commits),
        }
    }
}

/// VSSS Evaluator for the cut-and-choose protocol.
///
/// This evaluator uses Verifiable Secret Sharing Scheme (VSSS) for the
/// cut-and-choose protocol, using polynomial commitments and share verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "GH: GateHasher, LH: LabelCommitHasher")]
pub struct Evaluator<
    I: CircuitInput + Clone + Serialize + DeserializeOwned,
    GH: GateHasher = AesCcrGateHasher,
    LH: LabelCommitHasher = DefaultLabelCommitHasher,
> {
    config: Config<I>,
    /// To protect against the second-preimage of input-label hash, this nonce supplements the
    /// commit from `Garbler`
    nonce: S,
    finalized_indexes: Box<[usize]>,
    /// Tracks whether opened instances have been successfully regarbled and verified
    regarbled: bool,
    stage: Stage<GH, LH>,
}

impl<I, GH, LH> Evaluator<I, GH, LH>
where
    I: CircuitInput + Clone + Send + Sync + EncodeInput<GarbleMode<GH, Blake3AccumulatingHash>>,
    <I as CircuitInput>::WireRepr: Send + Sync,
    I: Serialize + DeserializeOwned,
    GH: GateHasher + 'static,
    LH: LabelCommitHasher,
{
    /// Create a VSSS evaluator from VSSS commits.
    pub fn create(mut rng: impl Rng, config: Config<I>, commits: VsssCommit<GH, LH>) -> Self {
        let polynomial_commits = commits
            .polynomial_commits
            .iter()
            .map(PolynomialCommits::from_canonical)
            .collect_vec();
        let share_commits = commits
            .share_commits
            .iter()
            .map(ShareCommits::from_canonical)
            .collect_vec();

        let mut x = 0;
        let allocated = config.input().allocate(|| {
            x += 1;
            WireId(x)
        });
        let num_inputs = <I as CircuitInput>::collect_wire_ids(&allocated).len();

        let expected_len = (0..num_inputs)
            .chunks(8)
            .into_iter()
            .map(|chunk| {
                let num_bits = chunk.count();
                2u32.pow(num_bits as u32) as usize
            })
            .sum::<usize>();

        assert_eq!(polynomial_commits.len(), expected_len);
        assert_eq!(share_commits.len(), expected_len);

        info!("Evaluator: Starting commit verification...");

        // Verifying the polynomials is computationally intensive, so we parallelize it
        crate::cut_and_choose::get_optimized_pool().install(|| {
            polynomial_commits
                .iter()
                .zip(share_commits.iter())
                .collect_vec()
                .into_par_iter()
                .for_each(|(polynomial_commits, share_commits)| {
                    share_commits
                        .verify(polynomial_commits)
                        .expect("Share commit verification failed");
                })
        });

        assert!(
            config.finalized_count() <= config.total,
            "finalized_count must be <= total"
        );

        assert_eq!(commits.circuit_commits.len(), config.total);

        info!("Evaluator: Finished commit verification...");

        // Sample without replacement: shuffle 0..total and take first `finalized_count`
        let mut idxs: Vec<usize> = (0..config.total).collect();
        // Fisher-Yates with unbiased rng
        for i in (1..idxs.len()).rev() {
            let j = rng.gen_range(0..=i);
            idxs.swap(i, j);
        }
        idxs.truncate(config.finalized_count());
        idxs.sort_unstable();

        Self {
            stage: Stage::Vsss { commits },
            finalized_indexes: idxs.into_boxed_slice(),
            config,
            nonce: S::from_u128(rng.r#gen()),
            regarbled: false,
        }
    }

    pub fn config(&self) -> &Config<I> {
        &self.config
    }

    pub fn finalized_indexes(&self) -> &[usize] {
        &self.finalized_indexes
    }

    /// Run VSSS-specific regarbling verification.
    ///
    /// 1. Check that `OpenForInstance` matches the ones stored in `self.finalized_indexes`.
    /// 2. For `Open` run `streaming_garbling` via rayon, where at the end it checks for a match with saved commits
    #[allow(clippy::result_unit_err)]
    pub fn run_regarbling<CSourceProvider, CHandlerProvider, F>(
        &mut self,
        open_instance_data: &[OpenVsssInstance],
        ciphertext_sources_provider: &CSourceProvider,
        ciphertext_handler_provider: &CHandlerProvider,
        live_capacity: usize,
        builder: F,
        wide_label_lookups: &[(usize, InstanceWideLabelLookup)],
    ) -> Result<(), ()>
    where
        CSourceProvider: CiphertextSourceProvider + Send + Sync,
        CHandlerProvider: CiphertextHandlerProvider + Send + Sync,
        CHandlerProvider::Handler: 'static,
        <CHandlerProvider::Handler as CiphertextHandler>::Result: 'static + Into<CiphertextCommit>,
        F: Fn(&mut StreamingMode<GarbleMode<GH, Blake3AccumulatingHash>>, &I::WireRepr) -> WireId
            + Send
            + Sync
            + Copy,
    {
        let Stage::Vsss { commits } = &mut self.stage else {
            panic!(
                "Can't run regarbling for not filled Evaluator, got stage: {:#?}",
                self.stage
            );
        };

        let iter = commits.circuit_commits.iter().enumerate();

        let inputs = self.config.input.clone();
        let finalized_indexes = &self.finalized_indexes;

        let secp = Secp256k1::new();
        let share_commits = &commits.share_commits;
        let garbling_table_commits = &commits.garbling_table_commits;

        info!("Evaluator: running share verification and regarbling in parallel...");

        // Run share commit verification AND regarbling in parallel using rayon::join
        let (share_verify_result, regarble_result) = crate::cut_and_choose::get_optimized_pool()
            .install(|| {
                rayon::join(
                    // Task 1: Verify share commits (secp256k1)
                    || {
                        info!("Evaluator: verifying share commits...");
                        let result = share_commits.iter().enumerate().par_bridge().try_for_each(
                            |(i, share_commit)| {
                                let shares = open_instance_data
                                    .iter()
                                    .map(|x| (x.index, x.shares[i].0))
                                    .collect_vec();

                                share_commit
                                    .from_canonical()
                                    .verify_shares(&secp, &shares)
                                    .map_err(|_| ())
                            },
                        );
                        info!("Evaluator: finished verifying share commits...");
                        result
                    },
                    // Task 2: Regarbling and ciphertext verification
                    || {
                        iter.par_bridge()
                            .map(|(index, first_commit)| {
                                if finalized_indexes.contains(&index) {
                                    let mut source = match ciphertext_sources_provider
                                        .source_for(index)
                                    {
                                        Ok(source) => source,
                                        Err(err) => {
                                            error!(index, ?err, "failed to get ciphertext source");
                                            return Err(());
                                        }
                                    };

                                    let mut handler = match ciphertext_handler_provider
                                        .handler_for(index)
                                    {
                                        Ok(sink) => sink,
                                        Err(err) => {
                                            error!(index, ?err, "failed to create ciphertext sink");
                                            return Err(());
                                        }
                                    };

                                    while let Some(s) = source.recv() {
                                        handler.handle(s);
                                    }

                                    let computed_commit: CiphertextCommit =
                                        handler.finalize().into();

                                    if computed_commit != first_commit.ciphertext_hash() {
                                        error!("ciphertext corrupted");
                                        return Err(());
                                    }

                                    let wide_label_lookup = wide_label_lookups
                                        .iter()
                                        .find(|x| x.0 == index)
                                        .unwrap()
                                        .1
                                        .clone();
                                    let tables_hash =
                                        GarbledWideLabelTable::aggregate_hash(&wide_label_lookup);
                                    if tables_hash != garbling_table_commits[index] {
                                        error!("wide label table corrupted");
                                        return Err(());
                                    }

                                    Ok(())
                                } else {
                                    let Some(info) =
                                        open_instance_data.iter().find(|x| x.index == index)
                                    else {
                                        error!("failed to find seed");
                                        return Err(());
                                    };
                                    let garbling_seed = info.seed;

                                    let inputs = inputs.clone();
                                    let hasher = Blake3AccumulatingHash::default();

                                    let span = tracing::info_span!("regarble", instance = index);
                                    let _enter = span.enter();

                                    info!("Starting regarbling of circuit (cut-and-choose)");

                                    let res: StreamingResult<
                                        GarbleMode<GH, Blake3AccumulatingHash>,
                                        I,
                                        GarbledWire,
                                    > = CircuitBuilder::streaming_garbling(
                                        inputs.clone(),
                                        live_capacity,
                                        garbling_seed,
                                        hasher,
                                        builder,
                                    );

                                    let instance = GarbledInstance::from_streaming_result(
                                        res,
                                        first_commit.gate_hasher_seed().clone(),
                                    );
                                    let wide_labels = info.shares.iter().map(|x| x.0).collect_vec();
                                    let tables = GarbledWideLabelTable::build_all(
                                        &wide_labels,
                                        &instance.input_wire_values,
                                    );
                                    let tables_hash =
                                        GarbledWideLabelTable::aggregate_hash(&tables);
                                    if tables_hash != garbling_table_commits[index] {
                                        error!(
                                            "regarbling failed, wide label table hash not equal"
                                        );
                                        return Err(());
                                    }

                                    let regarbling_first_commit =
                                        CommitPhaseOne::<GH, LH>::from_instance(&instance);
                                    if &regarbling_first_commit != first_commit {
                                        error!("regarbling failed, first commit not equal");
                                        return Err(());
                                    }

                                    Ok(())
                                }
                            })
                            .collect::<Result<Vec<()>, ()>>()
                    },
                )
            });

        // Check both results
        share_verify_result.map_err(|_| {
            error!("Share commit verification failed");
        })?;
        regarble_result?;

        self.regarbled = true;

        Ok(())
    }
}

impl<I, GH, LH> Evaluator<I, GH, LH>
where
    I: CircuitInput + Clone + Send + Sync + Serialize + DeserializeOwned,
    GH: GateHasher,
    LH: LabelCommitHasher,
{
    /// Evaluate all finalized instances from saved ciphertext files.
    /// Returns `(index, EvaluatedWire)` pairs.
    pub fn evaluate_from<E, F, CR>(
        &self,
        ciphertext_repo: &CR,
        input_cases: Vec<EvaluatorCaseInput<E>>,
        capacity: usize,
        builder: F,
    ) -> Result<Vec<(usize, EvaluatedWire)>, ConsistencyError<LH>>
    where
        CR: 'static + CiphertextSourceProvider + Sync,
        <CR::Source as CiphertextSource>::Result: Into<CiphertextCommit>,
        E: CircuitInput + Send + EncodeInput<EvaluateMode<GH, CR::Source>>,
        F: Fn(&mut StreamingMode<EvaluateMode<GH, CR::Source>>, &E::WireRepr) -> WireId
            + Send
            + Sync
            + Copy,
    {
        let commits = self.stage.get_commit_if_ready(self.regarbled).unwrap();

        crate::cut_and_choose::get_optimized_pool().install(|| {
            input_cases
                .into_par_iter()
                .map(|case| {
                    let EvaluatorCaseInput {
                        index,
                        input: eval_input,
                    } = case;

                    let commit = &commits[index];

                    let expected_input_commits = commit.input_commitments();

                    let source = match ciphertext_repo.source_for(index) {
                        Ok(src) => src,
                        Err(_) => {
                            return Err(ConsistencyError::MissingCiphertextHash(index));
                        }
                    };

                    let _span = tracing::info_span!("evaluate", instance = index).entered();

                    let gate_hasher = GH::from_seed(commit.gate_hasher_seed().clone());
                    let result =
                        CircuitBuilder::<EvaluateMode<GH, CR::Source>>::streaming_evaluation::<
                            _,
                            _,
                            EvaluatedWire,
                        >(
                            eval_input,
                            capacity,
                            commit.true_constant(),
                            commit.false_constant(),
                            gate_hasher,
                            source,
                            builder,
                        );

                    if expected_input_commits.len() != result.input_wire_values.len() {
                        return Err(ConsistencyError::InputLabelsCountMismatch {
                            index,
                            expected: expected_input_commits.len(),
                            actual: result.input_wire_values.len(),
                        });
                    }

                    for (label_index, (expected_commit, evaluated_wire)) in expected_input_commits
                        .iter()
                        .zip(result.input_wire_values)
                        .enumerate()
                    {
                        let expected_hash = expected_commit.commit_for_value(evaluated_wire.value);
                        let actual_hash = commit_label_with::<LH>(evaluated_wire.active_label);

                        if actual_hash != expected_hash {
                            let mut actual_commit = expected_commit.clone();

                            if evaluated_wire.value {
                                actual_commit.commit_true = actual_hash;
                            } else {
                                actual_commit.commit_false = actual_hash;
                            }

                            return Err(ConsistencyError::InputLabelsMismatch {
                                index,
                                label_index,
                                expected: expected_commit.clone(),
                                actual: actual_commit,
                            });
                        }
                    }

                    let new_ciphertext_commit: CiphertextCommit =
                        result.ciphertext_handler_result.into();
                    if new_ciphertext_commit != commit.ciphertext_hash() {
                        return Err(ConsistencyError::CiphertextMismatch {
                            index,
                            expected: commit.ciphertext_hash(),
                            actual: new_ciphertext_commit,
                        });
                    }

                    let output_hash = commit_label_with::<LH>(result.output_value.active_label);

                    let expected_output_hash = if result.output_value.value {
                        commit.output_commit_true()
                    } else {
                        commit.output_commit_false()
                    };

                    if output_hash != expected_output_hash {
                        return Err(ConsistencyError::OutputLabelMismatch {
                            index,
                            expected: expected_output_hash,
                            actual: output_hash,
                        });
                    }

                    Ok((index, result.output_value))
                })
                .collect()
        })
    }
}
