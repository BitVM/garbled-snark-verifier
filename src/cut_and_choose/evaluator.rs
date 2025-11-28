//! Evaluator-side state machine for the cut-and-choose Setup phase (see
//! `docs/gsv_spec.md`). The `Evaluator` mirrors the spec: it consumes `Commit₁`
//! (`commit_phase_one`) data, samples the challenge set, requests `Commit₂`, and
//! drives regarbling/opening plus soldering verification.
use std::{error, fmt, mem};

use itertools::*;
use rand::Rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tracing::{error, info};

use super::{
    Config,
    garbler::{CommitPhaseOne, CommitPhaseTwo},
    vsss::{self, PolynomialCommits, ShareCommits},
};
use crate::{
    AesCcrGateHasher, Blake3AccumulatingHash, EvaluatedWire, GarbleMode, GarbledWire, S, WireId,
    circuit::{
        CiphertextHandler, CiphertextSource, CircuitBuilder, CircuitInput, EncodeInput,
        StreamingMode, StreamingResult, modes::EvaluateMode,
    },
    cut_and_choose::{
        CiphertextCommit, CiphertextHandlerProvider, CiphertextSourceProvider,
        DefaultLabelCommitHasher, GarbledInstance, GarbledWideLabelTable, InstanceWideLabelLookup,
        LabelCommit, LabelCommitHasher, Seed, commit_label_with,
        vsss::{OpenVsssInstance, VsssCommit},
        write_commit_hex,
    },
    hashers::GateHasher,
};
#[cfg(feature = "sp1-soldering")]
use crate::{
    cut_and_choose::Sha256LabelCommitHasher,
    sp1_soldering::{Sha256Commit, SolderInput, SolderedLabels, SolderingProof},
};

#[derive(Default, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "GH: GateHasher, LH: LabelCommitHasher")]
pub enum Stage<GH: GateHasher, LH: LabelCommitHasher> {
    #[default]
    Empty,
    Created(Vec<CommitPhaseOne<GH, LH>>),
    Filled {
        first: Vec<CommitPhaseOne<GH, LH>>,
        second: Vec<CommitPhaseTwo<LH>>,
    },
    Vsss {
        commits: VsssCommit<GH, LH>,
    },
    #[cfg(feature = "sp1-soldering")]
    Soldered {
        first: Vec<CommitPhaseOne<GH, LH>>,
        second: Vec<CommitPhaseTwo<LH>>,
        soldering_deltas: Vec<Vec<(S, S)>>,
    },
}

impl<GH: GateHasher, LH: LabelCommitHasher> Stage<GH, LH> {
    fn get_commit_if_ready(&self, regarbled: bool) -> Option<&[CommitPhaseOne<GH, LH>]> {
        if !regarbled {
            return None;
        }
        match self {
            Stage::Empty => None,
            Stage::Created(_) => None,
            Stage::Filled { first, .. } => Some(first),
            Stage::Vsss {
                commits: VsssCommit {
                    circuit_commits, ..
                },
            } => Some(circuit_commits),
            #[cfg(feature = "sp1-soldering")]
            Stage::Soldered { first, .. } => Some(first),
        }
    }
}

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
    to_finalize: Box<[usize]>,
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
    pub fn create_vsss(mut rng: impl Rng, config: Config<I>, commits: VsssCommit<GH, LH>) -> Self {
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
        super::get_optimized_pool().install(|| {
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
            config.to_finalize <= config.total,
            "to_finalize must be <= total"
        );

        assert_eq!(commits.circuit_commits.len(), config.total);

        info!("Evaluator: Finished commit verification...");

        // Sample without replacement: shuffle 0..total and take first `to_finalize`
        let mut idxs: Vec<usize> = (0..config.total).collect();
        // Fisher-Yates with unbiased rng
        for i in (1..idxs.len()).rev() {
            let j = rng.gen_range(0..=i);
            idxs.swap(i, j);
        }
        idxs.truncate(config.to_finalize);
        idxs.sort_unstable();

        Self {
            stage: Stage::Vsss { commits },
            to_finalize: idxs.into_boxed_slice(),
            config,
            nonce: S::from_u128(rng.r#gen()),
            regarbled: false,
        }
    }

    // Generate `to_finalize` with `rng` based on data on `Config`
    pub fn create(
        mut rng: impl Rng,
        config: Config<I>,
        commits: Vec<CommitPhaseOne<GH, LH>>,
    ) -> Self {
        assert!(
            config.to_finalize <= config.total,
            "to_finalize must be <= total"
        );

        assert_eq!(commits.len(), config.total);

        // Sample without replacement: shuffle 0..total and take first `to_finalize`
        let mut idxs: Vec<usize> = (0..config.total).collect();
        // Fisher-Yates with unbiased rng
        for i in (1..idxs.len()).rev() {
            let j = rng.gen_range(0..=i);
            idxs.swap(i, j);
        }
        idxs.truncate(config.to_finalize);
        idxs.sort_unstable();

        Self {
            stage: Stage::Created(commits),
            to_finalize: idxs.into_boxed_slice(),
            config,
            nonce: S::from_u128(rng.r#gen()),
            regarbled: false,
        }
    }

    pub fn config(&self) -> &Config<I> {
        &self.config
    }

    pub fn fill_second_commit(&mut self, commits: Vec<CommitPhaseTwo<LH>>) {
        let first = match &mut self.stage {
            Stage::Created(first) => mem::take(first),
            _ => panic!("fill_second_commit can only be called once"),
        };

        self.stage = Stage::Filled {
            first,
            second: commits,
        };
    }

    pub fn get_nonce(&self) -> S {
        self.nonce
    }

    /// Get both phase one and phase two commitments if available (backward compatibility)
    pub fn get_commitment(&self) -> Option<super::Commitment<GH, LH>>
    where
        CommitPhaseOne<GH, LH>: Clone,
        CommitPhaseTwo<LH>: Clone,
    {
        match &self.stage {
            Stage::Filled { first, second } => Some((first.clone(), second.clone())),
            #[cfg(feature = "sp1-soldering")]
            Stage::Soldered { first, second, .. } => Some((first.clone(), second.clone())),
            _ => None,
        }
    }

    pub fn finalized_indexes(&self) -> &[usize] {
        &self.to_finalize
    }

    /// Returns whether opened instances have been successfully regarbled and verified
    pub fn is_regarbled(&self) -> bool {
        self.regarbled
    }

    /// Manually sets the `regarbled` flag to `true`.
    ///
    /// # Note
    ///
    /// This flag is automatically set by [`full_check_commit()`](Self::full_check_commit)
    /// and [`run_regarbling()`](Self::run_regarbling) after successful verification.
    ///
    /// Only call this method if you have verified the opened instances through an alternative
    /// mechanism or are restoring a previously verified state (e.g., from deserialization).
    /// Incorrect use may compromise the security of the cut-and-choose protocol.
    pub fn mark_regarbled(&mut self) {
        self.regarbled = true;
    }

    /// Get a specific commit from phase one by index (backward compatibility)
    pub fn get_commit_phase_one(&self, index: usize) -> Option<&CommitPhaseOne<GH, LH>> {
        match &self.stage {
            Stage::Empty => None,
            Stage::Created(first) => first.get(index),
            Stage::Filled { first, .. } => first.get(index),
            Stage::Vsss {
                commits: VsssCommit {
                    circuit_commits, ..
                },
            } => circuit_commits.get(index),
            #[cfg(feature = "sp1-soldering")]
            Stage::Soldered { first, .. } => first.get(index),
        }
    }

    /// Performs comprehensive verification of all commitments across finalized and opened instances.
    ///
    /// This method verifies:
    /// 1. For finalized instances: checks ciphertext hash matches the committed value
    /// 2. For opened instances: re-garbles the circuit and verifies both phase one and phase two commits
    ///
    /// This is a critical security step in the cut-and-choose protocol that ensures the garbler
    /// has honestly generated all garbled circuits.
    #[allow(clippy::result_unit_err)]
    pub fn full_check_commit<CSourceProvider, CHandlerProvider, F>(
        &mut self,
        seeds: Vec<(usize, Seed)>,
        ciphertext_sources_provider: &CSourceProvider,
        ciphertext_handler_provider: &CHandlerProvider,
        live_capacity: usize,
        builder: F,
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
        let (first, second) = match &mut self.stage {
            Stage::Filled { first, second } => (first, second),
            #[cfg(feature = "sp1-soldering")]
            Stage::Soldered { first, second, .. } => (first, second),
            _ => {
                panic!("Can't run full commit check for Evaluator not in Filled or Soldered stage")
            }
        };

        let iter = first.iter().zip_eq(second.iter()).enumerate();

        let inputs = self.config.input.clone();
        let to_finalize = &self.to_finalize;
        let nonce = self.nonce;

        super::get_optimized_pool().install(|| {
            iter.par_bridge()
                .map(|(index, (first_commit, second_commit))| {
                    if to_finalize.contains(&index) {
                        let mut source = match ciphertext_sources_provider.source_for(index) {
                            Ok(source) => source,
                            Err(err) => {
                                error!(index, ?err, "failed to get ciphertext source");
                                return Err(());
                            }
                        };

                        let mut handler = match ciphertext_handler_provider.handler_for(index) {
                            Ok(sink) => sink,
                            Err(err) => {
                                error!(index, ?err, "failed to create ciphertext sink");
                                return Err(());
                            }
                        };

                        while let Some(s) = source.recv() {
                            handler.handle(s);
                        }

                        let computed_commit: CiphertextCommit = handler.finalize().into();

                        if computed_commit != first_commit.ciphertext_hash() {
                            error!("ciphertext corrupted");
                            return Err(());
                        }

                        Ok(())
                    } else {
                        let Some(garbling_seed) = seeds
                            .iter()
                            .find_map(|(i, seed)| (i == &index).then_some(seed))
                        else {
                            error!("failed to find seed");
                            return Err(());
                        };

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
                            *garbling_seed,
                            hasher,
                            builder,
                        );

                        let res = GarbledInstance::from_streaming_result(
                            res,
                            first_commit.gate_hasher_seed().clone(),
                        );
                        let regarbling_first_commit = CommitPhaseOne::<GH, LH>::from_instance(&res);

                        if &regarbling_first_commit != first_commit {
                            error!("regarbling failed, first commit not equal");
                            return Err(());
                        }

                        let regarbling_second_commit =
                            CommitPhaseTwo::<LH>::from_instance(&res, nonce);

                        if regarbling_second_commit.input_commitments()
                            != second_commit.input_commitments()
                        {
                            error!("regarbling failed, second commit not equal");
                            return Err(());
                        }

                        Ok(())
                    }
                })
                .collect::<Result<Vec<()>, ()>>()
        })?;

        self.regarbled = true;

        Ok(())
    }

    /// Performs regarbling verification for all opened instances.
    ///
    /// This method regarbles circuits for all opened instances (those not in `to_finalize`)
    /// and verifies both phase one and phase two commitments against the provided seeds.
    ///
    /// Unlike `full_check_commit`, this method does NOT verify ciphertext commits for
    /// finalized instances, making it faster when you only need to verify the opened instances.
    #[allow(clippy::result_unit_err)]
    pub fn run_regarbling<F>(
        &mut self,
        seeds: Vec<(usize, Seed)>,
        live_capacity: usize,
        builder: F,
    ) -> Result<(), ()>
    where
        F: Fn(&mut StreamingMode<GarbleMode<GH, Blake3AccumulatingHash>>, &I::WireRepr) -> WireId
            + Send
            + Sync
            + Copy,
    {
        let (first, second) = match &mut self.stage {
            Stage::Filled { first, second } => (first, second),
            #[cfg(feature = "sp1-soldering")]
            Stage::Soldered { first, second, .. } => (first, second),
            _ => panic!("Can't run regarbling for Evaluator not in Filled or Soldered stage"),
        };

        let iter = first.iter().zip_eq(second.iter()).enumerate();

        let inputs = self.config.input.clone();
        let to_finalize = &self.to_finalize;
        let nonce = self.nonce;

        super::get_optimized_pool().install(|| {
            iter.par_bridge()
                .map(|(index, (first_commit, second_commit))| {
                    // Only process opened instances (not in to_finalize)
                    if to_finalize.contains(&index) {
                        return Ok(());
                    }

                    let Some(garbling_seed) = seeds
                        .iter()
                        .find_map(|(i, seed)| (i == &index).then_some(seed))
                    else {
                        error!("failed to find seed for instance {}", index);
                        return Err(());
                    };

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
                        *garbling_seed,
                        hasher,
                        builder,
                    );

                    let res = GarbledInstance::from_streaming_result(
                        res,
                        first_commit.gate_hasher_seed().clone(),
                    );
                    let regarbling_first_commit = CommitPhaseOne::<GH, LH>::from_instance(&res);

                    if &regarbling_first_commit != first_commit {
                        error!("regarbling failed, first commit not equal");
                        return Err(());
                    }

                    let regarbling_second_commit = CommitPhaseTwo::<LH>::from_instance(&res, nonce);

                    if regarbling_second_commit.input_commitments()
                        != second_commit.input_commitments()
                    {
                        error!("regarbling failed, second commit not equal");
                        return Err(());
                    }

                    Ok(())
                })
                .collect::<Result<Vec<()>, ()>>()
        })?;

        self.regarbled = true;

        Ok(())
    }

    // 1. Check that `OpenForInstance` matches the ones stored in `self.to_finalize`.
    // 2. For `Open` run `streaming_garbling` via rayon, where at the end it checks for a match with saved commits
    #[allow(clippy::result_unit_err)]
    pub fn run_regarbling_vsss<CSourceProvider, CHandlerProvider, F>(
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
        let to_finalize = &self.to_finalize;

        let secp = vsss::Secp256k1::new();
        let share_commits = &commits.share_commits;
        let garbling_table_commits = &commits.garbling_table_commits;

        info!("Evaluator: running share verification and regarbling in parallel...");

        // Run share commit verification AND regarbling in parallel using rayon::join
        let (share_verify_result, regarble_result) = super::get_optimized_pool().install(|| {
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
                            if to_finalize.contains(&index) {
                                let mut source = match ciphertext_sources_provider.source_for(index)
                                {
                                    Ok(source) => source,
                                    Err(err) => {
                                        error!(index, ?err, "failed to get ciphertext source");
                                        return Err(());
                                    }
                                };

                                let mut handler =
                                    match ciphertext_handler_provider.handler_for(index) {
                                        Ok(sink) => sink,
                                        Err(err) => {
                                            error!(index, ?err, "failed to create ciphertext sink");
                                            return Err(());
                                        }
                                    };

                                while let Some(s) = source.recv() {
                                    handler.handle(s);
                                }

                                let computed_commit: CiphertextCommit = handler.finalize().into();

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
                                let tables_hash = GarbledWideLabelTable::aggregate_hash(&tables);
                                if tables_hash != garbling_table_commits[index] {
                                    error!("regarbling failed, wide label table hash not equal");
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

#[cfg(feature = "test-utils")]
mod test_utils {
    use serde::{Deserialize, Serialize};

    use super::*;

    impl<I, GH, LH> Evaluator<I, GH, LH>
    where
        I: CircuitInput + Clone + Serialize + DeserializeOwned,
        GH: GateHasher,
        LH: LabelCommitHasher,
    {
        pub fn from_raw_parts(
            config: Config<I>,
            nonce: u128,
            to_finalize: Box<[usize]>,
            regarbled: bool,
            stage: Stage<GH, LH>,
        ) -> Self {
            Self {
                config,
                nonce: S::from_u128(nonce),
                to_finalize,
                regarbled,
                stage,
            }
        }

        #[allow(clippy::type_complexity)]
        pub fn into_raw_parts(self) -> (Config<I>, S, Box<[usize]>, bool, Stage<GH, LH>) {
            (
                self.config,
                self.nonce,
                self.to_finalize,
                self.regarbled,
                self.stage,
            )
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(
        bound = "I: CircuitInput + Clone + Serialize + DeserializeOwned, GH: GateHasher, LH: LabelCommitHasher"
    )]
    pub struct EvaluatorRawParts<I, GH, LH>
    where
        I: CircuitInput + Clone + Serialize + DeserializeOwned,
        GH: GateHasher,
        LH: LabelCommitHasher,
    {
        pub config: Config<I>,
        pub nonce: S,
        pub to_finalize: Box<[usize]>,
        pub regarbled: bool,
        pub stage: Stage<GH, LH>,
    }

    impl<I, GH, LH> From<EvaluatorRawParts<I, GH, LH>> for Evaluator<I, GH, LH>
    where
        I: CircuitInput
            + Clone
            + Send
            + Sync
            + EncodeInput<GarbleMode<GH, Blake3AccumulatingHash>>
            + Serialize
            + DeserializeOwned,
        <I as CircuitInput>::WireRepr: Send + Sync,
        GH: GateHasher + 'static,
        LH: LabelCommitHasher,
    {
        fn from(parts: EvaluatorRawParts<I, GH, LH>) -> Self {
            Self::from_raw_parts(
                parts.config,
                parts.nonce.to_u128(),
                parts.to_finalize,
                parts.regarbled,
                parts.stage,
            )
        }
    }

    impl<I, GH, LH> From<Evaluator<I, GH, LH>> for EvaluatorRawParts<I, GH, LH>
    where
        I: CircuitInput + Clone + Serialize + DeserializeOwned,
        GH: GateHasher,
        LH: LabelCommitHasher,
    {
        fn from(value: Evaluator<I, GH, LH>) -> Self {
            let (config, nonce, to_finalize, regarbled, stage) = value.into_raw_parts();
            Self {
                config,
                nonce,
                to_finalize,
                regarbled,
                stage,
            }
        }
    }
}

#[cfg(feature = "test-utils")]
pub use test_utils::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct EvaluatorCaseInput<I> {
    pub index: usize,
    pub input: I,
}

/// Errors that can occur during consistency checking.
#[derive(Debug)]
pub enum ConsistencyError<H: LabelCommitHasher = DefaultLabelCommitHasher> {
    CommitFileNotFound(usize),
    CommitFileInvalid(usize, String),
    TrueConstantMismatch {
        index: usize,
        expected: H::Output,
        actual: H::Output,
    },
    FalseConstantMismatch {
        index: usize,
        expected: H::Output,
        actual: H::Output,
    },
    CiphertextMismatch {
        index: usize,
        expected: CiphertextCommit,
        actual: CiphertextCommit,
    },
    InputLabelsMismatch {
        index: usize,
        label_index: usize,
        expected: LabelCommit<H::Output>,
        actual: LabelCommit<H::Output>,
    },
    InputLabelsCountMismatch {
        index: usize,
        expected: usize,
        actual: usize,
    },
    OutputLabelMismatch {
        index: usize,
        expected: H::Output,
        actual: H::Output,
    },
    MissingCiphertextHash(usize),
}

impl<H: LabelCommitHasher> error::Error for ConsistencyError<H> {}

impl<H: LabelCommitHasher> fmt::Display for ConsistencyError<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CommitFileNotFound(idx) => {
                write!(f, "Commit file not found for instance {}", idx)
            }
            Self::CommitFileInvalid(idx, err) => {
                write!(f, "Invalid commit file for instance {}: {}", idx, err)
            }
            Self::TrueConstantMismatch {
                index,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "True constant hash mismatch for instance {}: expected 0x",
                    index
                )?;
                write_commit_hex(f, expected.as_ref())?;
                write!(f, ", got 0x")?;
                write_commit_hex(f, actual.as_ref())
            }
            Self::FalseConstantMismatch {
                index,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "False constant hash mismatch for instance {}: expected 0x",
                    index
                )?;
                write_commit_hex(f, expected.as_ref())?;
                write!(f, ", got 0x")?;
                write_commit_hex(f, actual.as_ref())
            }
            Self::CiphertextMismatch {
                index,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "Ciphertext hash mismatch for instance {}: expected 0x",
                    index
                )?;
                write_commit_hex(f, expected.as_ref())?;
                write!(f, ", got 0x")?;
                write_commit_hex(f, actual.as_ref())
            }
            Self::InputLabelsMismatch {
                index,
                label_index,
                expected,
                actual,
            } => write!(
                f,
                "Input label commit mismatch for instance {}, label {}: expected {}, got {}",
                index, label_index, expected, actual
            ),
            Self::InputLabelsCountMismatch {
                index,
                expected,
                actual,
            } => write!(
                f,
                "Input labels count mismatch for instance {}: expected {}, got {}",
                index, expected, actual
            ),
            Self::OutputLabelMismatch {
                index,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "Output label hash mismatch for instance {}: expected 0x",
                    index
                )?;
                write_commit_hex(f, expected.as_ref())?;
                write!(f, ", got 0x")?;
                write_commit_hex(f, actual.as_ref())
            }
            Self::MissingCiphertextHash(idx) => {
                write!(f, "Missing ciphertext hash for instance {}", idx)
            }
        }
    }
}

impl<I, GH, LH> Evaluator<I, GH, LH>
where
    I: CircuitInput + Clone + Send + Sync + Serialize + DeserializeOwned,
    GH: GateHasher,
    LH: LabelCommitHasher,
{
    /// Evaluate all finalized instances from saved ciphertext files in `folder`.
    /// Returns `(index, EvaluatedWire)` pairs.
    ///
    /// **Note**: This method does NOT perform consistency checking. Use `evaluate_from_saved_all_with_consistency`
    /// for evaluation with commit verification.
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

        super::get_optimized_pool().install(|| {
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
                                actual_commit.commit_label1 = actual_hash;
                            } else {
                                actual_commit.commit_label0 = actual_hash;
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

/// Errors that can occur when verifying soldering data against local commits.
#[cfg(feature = "sp1-soldering")]
#[derive(Debug)]
pub enum SolderingCheckError {
    /// Unexpected size/layout of soldering data compared to local state
    ShapeMismatch(&'static str),
    /// Base instance per-wire commit mismatch
    BaseCommitMismatch {
        wire_index: usize,
        which: &'static str,
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// Base instance per-wire nonce commit mismatch
    BaseNonceCommitMismatch {
        wire_index: usize,
        which: &'static str,
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// Additional instance per-wire commit mismatch
    InstanceCommitMismatch {
        instance_index: usize,
        wire_index: usize,
        which: &'static str,
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// Failure during soldering verification
    SolderingFailed(String),
}

#[cfg(feature = "sp1-soldering")]
impl error::Error for SolderingCheckError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

#[cfg(feature = "sp1-soldering")]
impl fmt::Display for SolderingCheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ShapeMismatch(msg) => write!(f, "soldering data shape mismatch: {}", msg),
            Self::BaseCommitMismatch {
                wire_index,
                which,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "base commit mismatch at wire {} ({}): expected 0x",
                    wire_index, which
                )?;
                super::write_commit_hex(f, expected)?;
                write!(f, ", got 0x")?;
                super::write_commit_hex(f, actual)
            }
            Self::BaseNonceCommitMismatch {
                wire_index,
                which,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "base nonce commit mismatch at wire {} ({}): expected 0x",
                    wire_index, which
                )?;
                super::write_commit_hex(f, expected)?;
                write!(f, ", got 0x")?;
                super::write_commit_hex(f, actual)
            }
            Self::InstanceCommitMismatch {
                instance_index,
                wire_index,
                which,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "instance {} commit mismatch at wire {} ({}): expected 0x",
                    instance_index, wire_index, which
                )?;
                super::write_commit_hex(f, expected)?;
                write!(f, ", got 0x")?;
                super::write_commit_hex(f, actual)
            }
            Self::SolderingFailed(msg) => write!(f, "soldering verification failed: {}", msg),
        }
    }
}

impl<I, GH> Evaluator<I, GH, super::Sha256LabelCommitHasher>
where
    I: CircuitInput + Clone + Send + Sync + Serialize + DeserializeOwned,
    GH: GateHasher,
{
    /// Verify the garbler-provided soldering proof and compare its bound commitments
    /// against local commits for the finalized instances. Returns the verified
    /// soldering data (`SolderedLabels`) on success.
    ///
    /// Requirements:
    /// - Local commits must be produced with a hasher that outputs 32 bytes
    ///   (e.g., `Sha256LabelCommitHasher`) to compare with soldering commitments.
    /// - The garbler must build the proof using the same `to_finalize` ordering,
    ///   with the base at `to_finalize[0]` and additional instances following.
    #[cfg(feature = "sp1-soldering")]
    pub fn verify_soldering_against_commits(
        &mut self,
        proof: SolderingProof,
    ) -> Result<SolderedLabels, SolderingCheckError> {
        let Stage::Filled {
            first: first_commits,
            second: second_commits,
        } = mem::take(&mut self.stage)
        else {
            panic!()
        };

        // First, get the base index to prepare commitments
        let Some(&base_idx) = self.to_finalize.first() else {
            return Err(SolderingCheckError::ShapeMismatch(
                "to_finalize must contain at least one index",
            ));
        };

        // Prepare base commitments
        let base_commitment: Vec<(Sha256Commit, Sha256Commit)> = first_commits[base_idx]
            .input_commitments()
            .iter()
            .map(|lc| (lc.commit_label0, lc.commit_label1))
            .collect();

        // Prepare base nonce commitments (from second commit which has nonce applied)
        let base_nonce_commitment: Vec<(Sha256Commit, Sha256Commit)> = second_commits[base_idx]
            .input_commitments()
            .iter()
            .map(|lc| (lc.commit_label0, lc.commit_label1))
            .collect();

        // Prepare commitments for additional instances
        let additional_indexes = &self.to_finalize[1..];
        let commitments: Vec<Vec<(Sha256Commit, Sha256Commit)>> = additional_indexes
            .iter()
            .map(|&idx| {
                first_commits[idx]
                    .input_commitments()
                    .iter()
                    .map(|lc| (lc.commit_label0, lc.commit_label1))
                    .collect()
            })
            .collect();

        // Extract proof and deltas
        let SolderingProof {
            proof: groth16_proof,
            deltas,
        } = proof;

        // Verify using the new API
        if !crate::sp1_soldering::verify_soldering(
            SolderingProof {
                proof: groth16_proof,
                deltas: deltas.clone(),
            },
            base_commitment.clone(),
            base_nonce_commitment.clone(),
            self.nonce.to_u128(),
            commitments.clone(),
        ) {
            return Err(SolderingCheckError::SolderingFailed(
                "Soldering verification failed".to_string(),
            ));
        }

        // Reconstruct the verified public params
        let verified_public_params = SolderedLabels {
            deltas: deltas.clone(),
            base_commitment,
            base_nonce_commitment,
            nonce: self.nonce.to_u128(),
            commitments,
        };

        let soldered_instances_indexes = &self.to_finalize[1..];

        // Shape checks
        let expected_wires = first_commits[base_idx].input_commitments().len();
        if verified_public_params.base_commitment.len() != expected_wires {
            return Err(SolderingCheckError::ShapeMismatch(
                "base commitment wire count",
            ));
        }
        if verified_public_params.deltas.len() != soldered_instances_indexes.len() {
            return Err(SolderingCheckError::ShapeMismatch(
                "deltas count vs additional instances",
            ));
        }
        if verified_public_params.commitments.len() != soldered_instances_indexes.len() {
            return Err(SolderingCheckError::ShapeMismatch(
                "commitments count vs additional instances",
            ));
        }
        for (j, &inst_idx) in soldered_instances_indexes.iter().enumerate() {
            if first_commits[inst_idx].input_commitments().len() != expected_wires
                || verified_public_params.commitments[j].len() != expected_wires
                || verified_public_params.deltas[j].len() != expected_wires
            {
                return Err(SolderingCheckError::ShapeMismatch(
                    "per-instance wire count",
                ));
            }
        }

        info!(
            base = base_idx,
            extra = soldered_instances_indexes.len(),
            wires = expected_wires,
            "verifying soldering commits against local commits"
        );

        // Compare base instance per-wire commitments
        let base_local = &first_commits[base_idx];
        for (wire_idx, base_pair) in base_local.input_commitments().iter().enumerate() {
            let (exp0, exp1) = verified_public_params.base_commitment[wire_idx];

            if base_pair.commit_label0 != exp0 {
                return Err(SolderingCheckError::BaseCommitMismatch {
                    wire_index: wire_idx,
                    which: "label0",
                    expected: exp0,
                    actual: base_pair.commit_label0,
                });
            }

            if base_pair.commit_label1 != exp1 {
                return Err(SolderingCheckError::BaseCommitMismatch {
                    wire_index: wire_idx,
                    which: "label1",
                    expected: exp1,
                    actual: base_pair.commit_label1,
                });
            }
        }

        // Verify nonce commitments for base instance
        // The second commit for base instance should have the nonce applied
        let base_second = &second_commits[base_idx];

        for (wire_idx, (nonce_commit, nonce_local_commit)) in verified_public_params
            .base_nonce_commitment
            .iter()
            .zip(base_second.input_commitments().iter())
            .enumerate()
        {
            // Verify label0 with nonce
            if nonce_commit.0 != nonce_local_commit.commit_label0 {
                return Err(SolderingCheckError::BaseNonceCommitMismatch {
                    wire_index: wire_idx,
                    which: "label0_with_nonce",
                    expected: nonce_local_commit.commit_label0,
                    actual: nonce_commit.0,
                });
            }

            // Verify label1 with nonce
            if nonce_commit.1 != nonce_local_commit.commit_label1 {
                return Err(SolderingCheckError::BaseNonceCommitMismatch {
                    wire_index: wire_idx,
                    which: "label1_with_nonce",
                    expected: nonce_local_commit.commit_label1,
                    actual: nonce_commit.1,
                });
            }
        }

        // Compare additional instances per-wire commitments
        for (j, &inst_idx) in soldered_instances_indexes.iter().enumerate() {
            let local = &first_commits[inst_idx];

            for (wire_idx, local_pair) in local.input_commitments().iter().enumerate() {
                let (exp0, exp1) = verified_public_params.commitments[j][wire_idx];

                if local_pair.commit_label0 != exp0 {
                    return Err(SolderingCheckError::InstanceCommitMismatch {
                        instance_index: inst_idx,
                        wire_index: wire_idx,
                        which: "label0",
                        expected: exp0,
                        actual: local_pair.commit_label0,
                    });
                }

                if local_pair.commit_label1 != exp1 {
                    return Err(SolderingCheckError::InstanceCommitMismatch {
                        instance_index: inst_idx,
                        wire_index: wire_idx,
                        which: "label1",
                        expected: exp1,
                        actual: local_pair.commit_label1,
                    });
                }
            }
        }

        // Convert deltas from u128 to S and persist for later evaluate step
        let soldering_deltas_s: Vec<Vec<(S, S)>> = verified_public_params
            .deltas
            .iter()
            .map(|instance_deltas| {
                instance_deltas
                    .iter()
                    .map(|(d0, d1)| (S::from_u128(*d0), S::from_u128(*d1)))
                    .collect()
            })
            .collect();

        self.stage = Stage::Soldered {
            first: first_commits,
            second: second_commits,
            soldering_deltas: soldering_deltas_s,
        };

        Ok(verified_public_params)
    }
}

#[cfg(feature = "sp1-soldering")]
impl<I, GH> Evaluator<I, GH, Sha256LabelCommitHasher>
where
    I: CircuitInput + Clone + Send + Sync + Serialize + DeserializeOwned,
    GH: GateHasher,
{
    #[allow(clippy::result_large_err)]
    pub fn evaluate_with_soldered_instances_from<E, F, CR>(
        &self,
        ciphertext_repo: &CR,
        base_case: EvaluatorCaseInput<E>,
        capacity: usize,
        builder: F,
    ) -> Result<Vec<(usize, EvaluatedWire)>, ConsistencyError<Sha256LabelCommitHasher>>
    where
        E: CircuitInput + Send + EncodeInput<EvaluateMode<GH, CR::Source>> + SolderInput,
        CR: 'static + CiphertextSourceProvider + Send + Sync,
        <CR::Source as CiphertextSource>::Result: Into<CiphertextCommit>,
        F: Fn(&mut StreamingMode<EvaluateMode<GH, CR::Source>>, &E::WireRepr) -> WireId
            + Send
            + Sync
            + Copy,
    {
        let finalized = self.to_finalize.clone();
        assert!(
            !finalized.is_empty(),
            "no finalized instances; evaluator not initialized?"
        );

        // Ensure base case index matches our base finalized index
        let base_index = finalized[0];
        assert_eq!(
            base_case.index, base_index,
            "base_case.index must equal first finalized index"
        );

        let Stage::Soldered {
            soldering_deltas: deltas,
            ..
        } = &self.stage
        else {
            panic!()
        };

        // Build input cases: base + derived for each additional finalized index
        let mut cases: Vec<EvaluatorCaseInput<E>> = Vec::with_capacity(finalized.len());
        cases.push(base_case);

        for (j, &inst_idx) in finalized.iter().enumerate().skip(1) {
            let per_wire = &deltas[j - 1];
            let derived_input = cases[0].input.solder(per_wire);

            cases.push(EvaluatorCaseInput {
                index: inst_idx,
                input: derived_input,
            });
        }

        self.evaluate_from(ciphertext_repo, cases, capacity, builder)
    }

    /// Returns verified base instance input commitments after successful soldering verification.
    ///
    /// Only available in Soldered stage after `verify_soldering_against_commits` has been called.
    /// Returns the input wire label commitments for the base instance (first finalized index).
    ///
    /// Returns `None` if not in Soldered stage.
    pub fn verified_soldered_base_commitment(&self) -> Option<Vec<LabelCommit<Sha256Commit>>> {
        let Stage::Soldered { first, .. } = &self.stage else {
            return None;
        };

        let base_idx = *self.to_finalize.first()?;
        Some(first[base_idx].input_commitments().to_vec())
    }

    /// Returns output label commitments (true, false) for all finalized instances.
    ///
    /// Available after Filled stage (with regarbled=true) or Soldered stage.
    /// Returns a vector of tuples where each tuple contains:
    /// - First element: commitment to the label when output is true
    /// - Second element: commitment to the label when output is false
    ///
    /// Returns `None` if not in appropriate stage.
    pub fn finalized_output_label_commitment(&self) -> Option<Vec<(Sha256Commit, Sha256Commit)>> {
        let first_commits = match &self.stage {
            Stage::Filled { first, .. } if self.regarbled => first,
            Stage::Soldered { first, .. } => first,
            _ => return None,
        };

        Some(
            self.to_finalize
                .iter()
                .map(|&idx| {
                    let commit = &first_commits[idx];
                    (commit.output_commit_true(), commit.output_commit_false())
                })
                .collect(),
        )
    }
}
