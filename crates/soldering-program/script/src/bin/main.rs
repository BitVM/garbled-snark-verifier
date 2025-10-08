//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use clap::Parser;
use core::ops::BitXor;
use sha2::{Digest, Sha256};
use soldering_types as types;
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const FIBONACCI_ELF: &[u8] = include_elf!("fibonacci-program");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    prove: bool,

    #[arg(long, default_value = "false")]
    dummy: bool,

    #[arg(long, default_value = "false")]
    failed: bool,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    // Setup the prover client.
    let client = ProverClient::from_env();

    // Setup the inputs (encode shared Input type).
    let mut stdin = SP1Stdin::new();
    let input = make_dummy_input(args.failed);
    stdin.write(&input);

    if args.execute {
        // Execute the program
        let (_output, report) = client.execute(FIBONACCI_ELF, &stdin).run().unwrap();
        println!("Program executed successfully.");
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        // Setup the program for proving.
        let (pk, vk) = client.setup(FIBONACCI_ELF);

        // Generate the proof
        let proof = client
            .prove(&pk, &stdin)
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof!");

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
}

fn make_dummy_input(failed: bool) -> types::Input {
    use types::*;

    // Create some test wire labels with different values for testing
    let wires_for_instance: [Wire; INPUT_WIRE_COUNT] = std::array::from_fn(|i| Wire {
        label0: [i as u8; 16],       // Different label0 for each wire
        label1: [(i + 1) as u8; 16], // Different label1 for each wire
    });

    let instances: [InstanceWires; INSTANCE_COUNT] = std::array::from_fn(|_| InstanceWires {
        labels: Box::new(wires_for_instance.clone()),
    });

    let aggregate_instance_commit = |instance: &InstanceWires| -> [u8; 32] {
        let mut hasher = Sha256::new();
        for wire in instance.labels.iter() {
            hasher.update(wire.label0);
            hasher.update(wire.label1);
        }
        hasher.finalize().into()
    };

    // Create SHA256 commitments for the core instance (first instance)
    let mut sha256_commit: [[ShaDigest; 2]; INPUT_WIRE_COUNT] = std::array::from_fn(|i| {
        let wire = &wires_for_instance[i];
        // Create correct SHA256 commitments
        let label0_commit: [u8; 32] = Sha256::digest(wire.label0).into();
        let label1_commit: [u8; 32] = Sha256::digest(wire.label1).into();
        [label0_commit, label1_commit]
    });

    // If failed flag is set, corrupt the last commitment
    if failed {
        let last_idx = INPUT_WIRE_COUNT - 1;
        sha256_commit[last_idx][1] = [0xFF; 32]; // Corrupt the label1 of the last wire
        println!("Corrupted last commitment (wire {} label 1)", last_idx);
    }

    // Create commitments array with Core for first instance, Additional for rest
    let commitments: [InstanceCommitment; INSTANCE_COUNT] = std::array::from_fn(|instance_index| {
        if instance_index == 0 {
            InstanceCommitment::Core {
                sha256_commit: Box::new(sha256_commit.clone()),
            }
        } else {
            let aggregate_commit = aggregate_instance_commit(&instances[instance_index]);
            InstanceCommitment::Additional {
                poseidon_commit: aggregate_commit,
            }
        }
    });

    let make_delta_labels = |label_selector: fn(&Wire) -> &Label| -> [WireLabels; INSTANCE_COUNT] {
        std::array::from_fn(|instance_index| {
            let delta_labels: [Label; INPUT_WIRE_COUNT] = std::array::from_fn(|wire_index| {
                let base_wire = &instances[0].labels[wire_index];
                let candidate_wire = &instances[instance_index].labels[wire_index];
                let base_label = label_selector(base_wire);
                let candidate_label = label_selector(candidate_wire);
                std::array::from_fn(|byte_index| {
                    base_label[byte_index].bitxor(candidate_label[byte_index])
                })
            });
            WireLabels(Box::new(delta_labels))
        })
    };

    let deltas0 = make_delta_labels(|wire| &wire.label0);
    let deltas1 = make_delta_labels(|wire| &wire.label1);

    let public_param = PublicParams {
        commitments: Box::new(commitments),
        deltas0: Box::new(deltas0),
        deltas1: Box::new(deltas1),
    };

    let private_param = PrivateParams {
        input_labels: Box::new(instances),
    };

    Input {
        public_param,
        private_param,
    }
}
