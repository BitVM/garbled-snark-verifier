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
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use soldering_types as types;

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
    let input = make_dummy_input();
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

fn make_dummy_input() -> types::Input {
    use types::*;

    let zero_label: Label = [0u8; 16];
    let zero_commit: Commit = [0u8; 32];
    let zero_sha: ShaDigest = [0u8; 32];

    let wire_zero = Wire { label0: zero_label, label1: zero_label };
    let wires_for_instance: [Wire; INPUT_WIRE_COUNT] = std::array::from_fn(|_| wire_zero.clone());
    let instances: [InstanceWires; INSTANCE_COUNT] =
        std::array::from_fn(|_| InstanceWires { labels: wires_for_instance.clone() });

    let selection: [bool; INSTANCE_COUNT] = [false; INSTANCE_COUNT];
    let commitments: [Commit; INSTANCE_COUNT] = std::array::from_fn(|_| zero_commit);
    let sha0: [ShaDigest; INPUT_WIRE_COUNT] = std::array::from_fn(|_| zero_sha);
    let sha1: [ShaDigest; INPUT_WIRE_COUNT] = std::array::from_fn(|_| zero_sha);
    let zero_wire_labels = WireLabels(std::array::from_fn(|_| zero_label));
    let deltas0: [WireLabels; INSTANCE_COUNT] = std::array::from_fn(|_| zero_wire_labels.clone());
    let deltas1: [WireLabels; INSTANCE_COUNT] = std::array::from_fn(|_| zero_wire_labels.clone());

    let public_param = PublicParams {
        selection,
        commitments,
        sha0,
        sha1,
        deltas0,
        deltas1,
    };

    let private_param = PrivateParams { labels: instances };

    Input { public_param, private_param }
}
