//! Soldering API surface
//!
//! This module exposes a thin, feature-gated wrapper over the SP1-based
//! soldering core. The goals for this layer are:
//! - present stable function signatures that use our core types (`S`, `GarbledWire`)
//! - hide SP1/prover internals behind the `sp1-soldering` feature
//! - provide ergonomic conversions and clear public outputs for downstream use
//!
//! The two entry points are:
//! - `prove_soldering`: produce a proof that a set of additional instances are
//!   correctly soldered to a base instance, and return the public parameters
//!   (deltas and commitments) alongside a proof handle.
//! - `verify_soldering`: verify the proof and return the public parameters
//!   bound by the proof for consumer use.

use crate::{GarbledWire, S};

/// SHA-256 commitment used for wire-label commitments.
pub type Sha256Commit = [u8; 32];

/// Public values emitted by the soldering proof.
///
/// These bind all additional instances to the base instance via per-wire
/// commitments and per-instance per-wire deltas.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolderedLabels {
    /// For each additional instance, for each input wire, provide the pair of
    /// deltas that transform the base labels into the instance labels.
    /// Layout: `deltas[instance_idx][wire_idx] = (delta0, delta1)`.
    pub deltas: Vec<Vec<(S, S)>>,
    /// For each input wire of the base instance, commitment to both labels.
    /// The entry is ordered as `[commit(label0), commit(label1)]`.
    pub base_commitment: Vec<[Sha256Commit; 2]>,
    /// Commitment per additional instance, binding all its input wires.
    pub commitments: Vec<Vec<(Sha256Commit, Sha256Commit)>>,
}

/// Error surface for soldering operations.
#[derive(thiserror::Error, Debug)]
pub enum SolderingError {
    #[error("input instances list must not be empty")]
    EmptyInstances,
    #[error("wire count mismatch: base has {base}, instance {instance_idx} has {got}")]
    WireCountMismatch {
        base: usize,
        instance_idx: usize,
        got: usize,
    },
}

/// Opaque handle that carries the proof and verification key needed to verify
/// soldering. The inner representation is SP1-specific and is hidden behind the
/// `sp1-soldering` feature to avoid leaking SDK types into the public surface.
pub struct SolderingProof {
    inner: gsv_soldering_core::host::ProvenSolderedLabelsData,
}

impl core::fmt::Debug for SolderingProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SolderingProof")
            .field("has_inner", &cfg!(feature = "sp1-soldering"))
            .finish()
    }
}

/// Produce a soldering proof and its bound public parameters.
///
/// Input shape:
/// - `base`: the base/core instance input wires (each is a `GarbledWire` with two labels `S`)
/// - `additional`: the list of additional instances to be soldered; each must
///   contain exactly the same number of wires as `base`.
///
/// Returns an opaque `SolderingProof` handle which must be passed to
/// `verify_soldering`. Use the return value of `verify_soldering` as the source
/// of truth for deltas and commitments.
pub fn prove_soldering(
    base: &[GarbledWire],
    additional: &[Vec<GarbledWire>],
) -> Result<SolderingProof, SolderingError> {
    let base_len = base.len();
    if additional.is_empty() {
        return Err(SolderingError::EmptyInstances);
    }
    for (idx, inst) in additional.iter().enumerate() {
        if inst.len() != base_len {
            return Err(SolderingError::WireCountMismatch {
                base: base_len,
                instance_idx: idx,
                got: inst.len(),
            });
        }
    }

    // Build soldering-core input: Vec<InstancesWires>, where a wire is (u128,u128)
    let to_wire = |w: &GarbledWire| (w.label0.to_u128(), w.label1.to_u128());

    let mut instances = Vec::with_capacity(1 + additional.len());

    instances.push(base.iter().map(to_wire).collect());

    for inst in additional {
        instances.push(inst.iter().map(to_wire).collect());
    }

    let input = gsv_soldering_core::types::WiresInput {
        instances_wires: instances,
    };

    let inner = gsv_soldering_core::host::prove(&input);

    Ok(SolderingProof { inner })
}

/// Verify a soldering proof and extract its bound public parameters.
///
/// On success, the returned `SolderedLabels` contains:
/// - per-instance, per-wire deltas in `S` form
/// - base instance per-wire commitments to both labels
/// - per-instance commitments
pub fn verify_soldering(proof: SolderingProof) -> SolderedLabels {
    let data = gsv_soldering_core::host::verify(proof.inner);
    convert_public_values(data)
}

fn convert_public_values(data: gsv_soldering_core::types::SolderedLabelsData) -> SolderedLabels {
    let deltas = data
        .deltas
        .into_iter()
        .map(|per_wire| {
            per_wire
                .into_iter()
                .map(|(d0, d1)| (S::from_u128(d0), S::from_u128(d1)))
                .collect()
        })
        .collect();

    let base_commitment = data
        .base_commitment
        .into_iter()
        .map(|(c0, c1)| [c0, c1])
        .collect();

    SolderedLabels {
        deltas,
        base_commitment,
        commitments: data.commitments,
    }
}

#[cfg(test)]
mod tests {
    use test_log::test;

    use super::*;
    use crate::Delta;

    // This is a slow end-to-end check that exercises the SP1 flow.
    // It is ignored by default and only runs when the `sp1-soldering` feature
    // is enabled and the environment has the required artifacts.
    #[test]
    #[ignore = "slow"]
    fn round_trip_prove_verify() {
        use sha2::Digest;

        let mut rng = rand::thread_rng();
        let delta = Delta::generate(&mut rng);

        let input_wires_count = 64usize;
        let soldered_instances = 3usize;

        let base: Vec<GarbledWire> = (0..input_wires_count)
            .map(|_| GarbledWire::random(&mut rng, &delta))
            .collect();

        let additional: Vec<Vec<GarbledWire>> = (0..soldered_instances)
            .map(|_| {
                (0..input_wires_count)
                    .map(|_| GarbledWire::random(&mut rng, &delta))
                    .collect()
            })
            .collect();

        let proof = prove_soldering(&base, &additional).expect("prove");
        let out = verify_soldering(proof);

        assert_eq!(out.deltas.len(), soldered_instances);
        assert_eq!(out.base_commitment.len(), input_wires_count);
        assert_eq!(out.commitments.len(), soldered_instances);

        // Helper to select bit from a GarbledWire
        let pick = |gw: &GarbledWire, bit: bool| -> S { if bit { gw.label1 } else { gw.label0 } };

        // For every wire, for both bits, verify reconstruction from any known instance
        #[allow(clippy::needless_range_loop)]
        for wire_id in 0..input_wires_count {
            // Helper to get delta for bit b at wire w for instance idx
            let delta_for = |inst_idx: usize, bit: bool| -> S {
                let (d0, d1) = out.deltas[inst_idx][wire_id];
                if bit { d1 } else { d0 }
            };

            for bit in [false, true] {
                // 1) From base to all instances
                let base_label = pick(&base[wire_id], bit);

                for j in 0..soldered_instances {
                    let expected = pick(&additional[j][wire_id], bit);
                    let got = base_label ^ &delta_for(j, bit);
                    assert_eq!(
                        got, expected,
                        "wire {wire_id}, bit {bit}: reconstruct inst {j} from base"
                    );
                }

                // Verify base commitment for this bit
                let digest = sha2::Sha256::digest(base_label.to_u128().to_be_bytes());
                let commit: [u8; 32] = digest.into();
                let idx = if bit { 1 } else { 0 };
                assert_eq!(
                    out.base_commitment[wire_id][idx], commit,
                    "wire {wire_id}, bit {bit}: base commitment"
                );

                // 2) From each instance (one by one) to base and then to all
                for k in 0..soldered_instances {
                    let known = pick(&additional[k][wire_id], bit);
                    let base_rec = known ^ &delta_for(k, bit);
                    let base_expected = base_label;
                    assert_eq!(
                        base_rec, base_expected,
                        "wire {wire_id}, bit {bit}: recover base from inst {k}"
                    );

                    for j in 0..soldered_instances {
                        let got = base_rec ^ &delta_for(j, bit);
                        let expected = pick(&additional[j][wire_id], bit);
                        assert_eq!(
                            got, expected,
                            "wire {wire_id}, bit {bit}: reconstruct inst {j} from inst {k}"
                        );
                    }
                }
            }
        }
    }
}
