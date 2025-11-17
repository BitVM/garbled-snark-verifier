// Example demonstrating SP1 soldering proof generation and verification
//
// Run with:
//   cargo run --example soldering --release --features sp1-soldering -- prove
//   cargo run --example soldering --release --features sp1-soldering -- verify

#[cfg(feature = "sp1-soldering")]
use std::fs;

#[cfg(feature = "sp1-soldering")]
use garbled_snark_verifier::{
    GarbledWire, S,
    sp1_soldering::{Sha256Commit, SolderingProof, hash_label, prove_soldering, verify_soldering},
};
#[cfg(feature = "sp1-soldering")]
use rand::Rng;
#[cfg(feature = "sp1-soldering")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "sp1-soldering")]
#[derive(Serialize, Deserialize)]
struct CommitmentsFile {
    base_commitment: Vec<(Sha256Commit, Sha256Commit)>,
    base_nonce_commitment: Vec<(Sha256Commit, Sha256Commit)>,
    nonce: u128,
    commitments: Vec<Vec<(Sha256Commit, Sha256Commit)>>,
}

#[cfg(feature = "sp1-soldering")]
fn run_prove() {
    println!("Generating 1019 wires × 7 instances...");

    let wires = 1019;
    let total_instances = 7;

    let mut rng = rand::thread_rng();
    let nonce: u128 = rng.r#gen();
    let delta: u128 = rng.r#gen::<u128>() | 1;

    let mut all_instances = Vec::new();
    let mut all_raw_labels = Vec::new();

    for _ in 0..total_instances {
        let mut instance = Vec::new();
        let mut raw_labels = Vec::new();

        for _ in 0..wires {
            let label0: u128 = rng.r#gen();
            let label1: u128 = label0 ^ delta;

            instance.push(GarbledWire {
                label0: S::from_u128(label0),
                label1: S::from_u128(label1),
            });
            raw_labels.push((label0, label1));
        }

        all_instances.push(instance);
        all_raw_labels.push(raw_labels);
    }

    println!("Proving (this takes ~74 minutes)...");
    let soldering_proof = prove_soldering(all_instances, nonce);

    // Build commitments
    let base = &all_raw_labels[0];
    let base_commitment: Vec<_> = base
        .iter()
        .map(|&(l0, l1)| (hash_label(l0), hash_label(l1)))
        .collect();
    let base_nonce_commitment: Vec<_> = base
        .iter()
        .map(|&(l0, l1)| (hash_label(l0 ^ nonce), hash_label(l1 ^ nonce)))
        .collect();
    let commitments: Vec<Vec<_>> = all_raw_labels[1..]
        .iter()
        .map(|inst| {
            inst.iter()
                .map(|&(l0, l1)| (hash_label(l0), hash_label(l1)))
                .collect()
        })
        .collect();

    // Save (serialize proof and deltas separately due to bincode version issues)
    fs::write(
        "proof.json",
        serde_json::to_string_pretty(&soldering_proof.proof).unwrap(),
    )
    .unwrap();
    fs::write(
        "deltas.json",
        serde_json::to_string_pretty(&soldering_proof.deltas).unwrap(),
    )
    .unwrap();
    fs::write(
        "commitments.json",
        serde_json::to_string_pretty(&CommitmentsFile {
            base_commitment,
            base_nonce_commitment,
            nonce,
            commitments,
        })
        .unwrap(),
    )
    .unwrap();

    println!("✓ Saved: proof.json, deltas.json, commitments.json");
}

#[cfg(feature = "sp1-soldering")]
fn run_verify() {
    println!("Loading proof...");

    let groth16_proof = serde_json::from_str(&fs::read_to_string("proof.json").unwrap()).unwrap();
    let deltas = serde_json::from_str(&fs::read_to_string("deltas.json").unwrap()).unwrap();
    let CommitmentsFile {
        base_commitment,
        base_nonce_commitment,
        nonce,
        commitments,
    } = serde_json::from_str(&fs::read_to_string("commitments.json").unwrap()).unwrap();

    let proof = SolderingProof {
        proof: groth16_proof,
        deltas,
    };

    println!("Verifying...");
    let is_valid = verify_soldering(
        proof,
        base_commitment,
        base_nonce_commitment,
        nonce,
        commitments,
    );

    if is_valid {
        println!("✓ Proof verified!");
    } else {
        println!("✗ Verification failed!");
    }
}

#[cfg(not(feature = "sp1-soldering"))]
fn main() {
    eprintln!("Requires: cargo run --example soldering --release --features sp1-soldering");
}

#[cfg(feature = "sp1-soldering")]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("prove") => run_prove(),
        Some("verify") => run_verify(),
        _ => eprintln!(
            "Usage: cargo run --example soldering --release --features sp1-soldering -- [prove|verify]"
        ),
    }
}
