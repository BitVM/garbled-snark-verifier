use std::{
    borrow::Cow,
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};

use ark_secp256k1::Projective;
use rayon::prelude::*;

use super::vsss::{PolynomialCommits, ShareCommits};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionMode {
    Sequential,
    Parallel,
}

#[derive(Clone, Debug)]
pub struct BatchCheckOptions {
    pub mode: ExecutionMode,
    pub expected_share_count: Option<usize>,
    pub verify_opened_shares: bool,
    pub min_parallel_chunk: usize,
}

impl Default for BatchCheckOptions {
    fn default() -> Self {
        Self {
            mode: ExecutionMode::Parallel,
            expected_share_count: None,
            verify_opened_shares: true,
            min_parallel_chunk: 32,
        }
    }
}

#[derive(Clone)]
pub struct LabelRecord<'a> {
    pub module: Cow<'a, str>,
    pub label_id: Cow<'a, str>,
    pub polynomial_commits: &'a PolynomialCommits,
    pub share_commits: &'a ShareCommits,
    pub opened_shares: Option<&'a [(usize, ark_secp256k1::Fr)]>,
    pub expected_share_count: Option<usize>,
}

pub trait ShareCommitVerifier: Send + Sync {
    fn verify_share_commit(
        &self,
        commits: &PolynomialCommits,
        share_index: usize,
        share_commit: &Projective,
    ) -> bool;
}

#[derive(Clone, Default)]
pub struct ScalarShareCommitVerifier;

impl ShareCommitVerifier for ScalarShareCommitVerifier {
    fn verify_share_commit(
        &self,
        commits: &PolynomialCommits,
        share_index: usize,
        share_commit: &Projective,
    ) -> bool {
        let x = ark_secp256k1::Fr::from((share_index + 1) as u64);
        commits.evaluate_at(x) == *share_commit
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleStats {
    pub labels: usize,
    pub failed: usize,
}

impl Default for ModuleStats {
    fn default() -> Self {
        Self {
            labels: 0,
            failed: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FailureKind {
    ShareCount { expected: usize, actual: usize },
    ShareCommit { share_index: usize },
    ShareValue { reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LabelCheckFailure {
    pub module: String,
    pub label_id: String,
    pub kind: FailureKind,
}

impl LabelCheckFailure {
    fn from_record(record: &LabelRecord<'_>, kind: FailureKind) -> Self {
        Self {
            module: record.module.to_string(),
            label_id: record.label_id.to_string(),
            kind,
        }
    }
}

#[derive(Clone, Debug)]
pub struct BatchCheckReport {
    pub total_labels: usize,
    pub total_shares_checked: usize,
    pub module_stats: BTreeMap<String, ModuleStats>,
    pub failures: Vec<LabelCheckFailure>,
    pub duration: Duration,
    pub mode: ExecutionMode,
}

pub struct BatchChecker {
    options: BatchCheckOptions,
    verifier: Arc<dyn ShareCommitVerifier>,
}

impl BatchChecker {
    pub fn new(options: BatchCheckOptions) -> Self {
        Self::with_verifier(options, Arc::new(ScalarShareCommitVerifier::default()))
    }

    pub fn with_verifier(
        options: BatchCheckOptions,
        verifier: Arc<dyn ShareCommitVerifier>,
    ) -> Self {
        Self { options, verifier }
    }

    pub fn options(&self) -> &BatchCheckOptions {
        &self.options
    }

    pub fn run<'a, I>(&self, records: I) -> BatchCheckReport
    where
        I: IntoIterator<Item = LabelRecord<'a>>,
    {
        let records: Vec<_> = records.into_iter().collect();
        let mut module_stats = BTreeMap::<String, ModuleStats>::new();
        for record in &records {
            module_stats
                .entry(record.module.to_string())
                .or_default()
                .labels += 1;
        }

        let total_shares_checked: usize = records
            .iter()
            .map(|record| record.share_commits.len())
            .sum();

        let verifier = Arc::clone(&self.verifier);
        let options = self.options.clone();

        let start = Instant::now();
        let outcomes: Vec<Result<(), FailureKind>> = match options.mode {
            ExecutionMode::Sequential => records
                .iter()
                .map(|record| verify_record(record, &options, verifier.as_ref()))
                .collect(),
            ExecutionMode::Parallel => records
                .par_iter()
                .with_min_len(options.min_parallel_chunk)
                .map(|record| verify_record(record, &options, verifier.as_ref()))
                .collect(),
        };
        let duration = start.elapsed();

        let mut failures = Vec::new();
        for (record, outcome) in records.iter().zip(outcomes.into_iter()) {
            if let Err(kind) = outcome {
                if let Some(stats) = module_stats.get_mut(record.module.as_ref()) {
                    stats.failed += 1;
                }
                failures.push(LabelCheckFailure::from_record(record, kind));
            }
        }

        BatchCheckReport {
            total_labels: records.len(),
            total_shares_checked,
            module_stats,
            failures,
            duration,
            mode: options.mode,
        }
    }
}

fn verify_record(
    record: &LabelRecord<'_>,
    options: &BatchCheckOptions,
    verifier: &dyn ShareCommitVerifier,
) -> Result<(), FailureKind> {
    let expected = record.expected_share_count.or(options.expected_share_count);
    if let Some(expected_count) = expected {
        let actual = record.share_commits.len();
        if actual != expected_count {
            return Err(FailureKind::ShareCount {
                expected: expected_count,
                actual,
            });
        }
    }

    for (idx, share_commit) in record.share_commits.as_slice().iter().enumerate() {
        if !verifier.verify_share_commit(record.polynomial_commits, idx, share_commit) {
            return Err(FailureKind::ShareCommit { share_index: idx });
        }
    }

    if options.verify_opened_shares {
        if let Some(opened) = record.opened_shares {
            if let Err(reason) = record.share_commits.verify_shares(opened) {
                return Err(FailureKind::ShareValue { reason });
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::cac::vsss::Polynomial;

    struct LabelTemplate {
        label_id: String,
        commits: PolynomialCommits,
        share_commits: ShareCommits,
        opened_prefix: Vec<(usize, ark_secp256k1::Fr)>,
    }

    fn sample_templates(
        labels_per_instance: usize,
        truth_values: usize,
        degree: usize,
        share_count: usize,
    ) -> Vec<LabelTemplate> {
        let mut rng = ChaCha20Rng::seed_from_u64(2025);
        let mut out = Vec::with_capacity(labels_per_instance * truth_values);
        for label in 0..labels_per_instance {
            for truth in 0..truth_values {
                let polynomial = Polynomial::rand(&mut rng, degree);
                let commits = polynomial.coefficient_commits();
                let shares = polynomial.shares(share_count);
                let share_commits = polynomial.share_commits(share_count);
                out.push(LabelTemplate {
                    label_id: format!("label-{label}-tv-{truth}"),
                    commits,
                    share_commits,
                    opened_prefix: shares[..degree + 1].to_vec(),
                });
            }
        }
        out
    }

    fn build_records<'a>(
        templates: &'a [LabelTemplate],
        instances: usize,
        per_record_expected: Option<usize>,
        attach_opened: bool,
    ) -> Vec<LabelRecord<'_>> {
        let mut records = Vec::with_capacity(instances * templates.len());
        for instance in 0..instances {
            let module = format!("instance-{instance}");
            for template in templates {
                let label_id = format!("{}@{}", template.label_id, module);
                let opened = attach_opened.then_some(template.opened_prefix.as_slice());
                records.push(LabelRecord {
                    module: Cow::Owned(module.clone()),
                    label_id: Cow::Owned(label_id),
                    polynomial_commits: &template.commits,
                    share_commits: &template.share_commits,
                    opened_shares: opened,
                    expected_share_count: per_record_expected,
                });
            }
        }
        records
    }

    #[test]
    // Dataset mirroring 181 circuits × 1273 labels × 2 truth values with k = 174 (open circuits).
    #[ignore = "slow"]
    fn sequential_batch_check_realistic() {
        const INSTANCES: usize = 181;
        const LABELS_PER_INSTANCE: usize = 1273;
        const TRUTH_VALUES: usize = 2;
        const DEGREE: usize = 174; // k = total - finalized (181 - 7)
        const SHARE_COUNT: usize = 181;

        let templates = sample_templates(LABELS_PER_INSTANCE, TRUTH_VALUES, DEGREE, SHARE_COUNT);
        let records = build_records(&templates, INSTANCES, Some(SHARE_COUNT), true);

        let mut opts = BatchCheckOptions::default();
        opts.mode = ExecutionMode::Sequential;

        let report = BatchChecker::new(opts).run(records);
        assert!(report.failures.is_empty());
        assert_eq!(
            report.total_labels,
            INSTANCES * LABELS_PER_INSTANCE * TRUTH_VALUES
        );
        assert_eq!(
            report.total_shares_checked,
            INSTANCES * LABELS_PER_INSTANCE * TRUTH_VALUES * SHARE_COUNT
        );
        assert!(report.duration > Duration::default());
    }

    #[test]
    #[ignore = "slow"]
    fn parallel_batch_check_realistic() {
        const INSTANCES: usize = 181;
        const LABELS_PER_INSTANCE: usize = 1273;
        const TRUTH_VALUES: usize = 2;
        const DEGREE: usize = 174;
        const SHARE_COUNT: usize = 181;

        let templates = sample_templates(LABELS_PER_INSTANCE, TRUTH_VALUES, DEGREE, SHARE_COUNT);
        let records = build_records(&templates, INSTANCES, Some(SHARE_COUNT), true);

        let mut opts = BatchCheckOptions::default();
        opts.mode = ExecutionMode::Parallel;
        opts.min_parallel_chunk = 64;

        let report = BatchChecker::new(opts).run(records);
        assert!(report.failures.is_empty());
        assert_eq!(
            report.total_labels,
            INSTANCES * LABELS_PER_INSTANCE * TRUTH_VALUES
        );
        assert_eq!(
            report.total_shares_checked,
            INSTANCES * LABELS_PER_INSTANCE * TRUTH_VALUES * SHARE_COUNT
        );
        assert!(report.duration > Duration::default());
    }

    #[test]
    fn detects_share_count_mismatch() {
        const DEGREE: usize = 3;
        const SHARE_COUNT: usize = 12;
        let mut templates = sample_templates(2, 1, DEGREE, SHARE_COUNT);
        if let Some(first) = templates.get_mut(0) {
            first.share_commits.0.pop();
        }

        let records = build_records(&templates, 1, Some(SHARE_COUNT), false);

        let mut opts = BatchCheckOptions::default();
        opts.mode = ExecutionMode::Sequential;
        opts.expected_share_count = Some(SHARE_COUNT);
        opts.verify_opened_shares = false;

        let report = BatchChecker::new(opts).run(records);
        assert_eq!(report.failures.len(), 1);
        let failure = &report.failures[0];
        assert!(matches!(failure.kind, FailureKind::ShareCount { .. }));
        assert_eq!(report.module_stats[&failure.module].failed, 1);
    }
}
