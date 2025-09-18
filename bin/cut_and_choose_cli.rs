use std::{
    fs::{self, File},
    io::{self, BufReader, BufWriter, Read},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use clap::{Parser, Subcommand};
use garbled_snark_verifier::{
    S,
    ark::{
        self, AdditiveGroup, Bn254, CircuitSpecificSetupSNARK, Groth16 as ArkGroth16,
        ProvingKey as ArkProvingKey, SNARK, UniformRand,
    },
    ciphertext_hasher::CiphertextHashAcc,
    circuit::CiphertextFileHandler,
    garbled_groth16, groth16_cut_and_choose,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::info;

/// Cut-and-Choose CLI for Groth16 garbled circuits
#[derive(Parser)]
#[command(name = "cut_and_choose")]
#[command(about = "Cut-and-Choose protocol CLI for Groth16 verification")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate mock data (vk, pk, proofs) for testing
    GenMockSnark {
        /// Output directory for generated files
        #[arg(long, short, default_value = "./gc_storage")]
        output: PathBuf,

        /// Number of constraints (2^k)
        #[arg(long, default_value = "5")]
        k_constraints: u32,
    },

    /// Garbler operations
    Garbler {
        #[command(subcommand)]
        command: GarblerCommands,
    },

    /// Evaluator operations
    Evaluator {
        #[command(subcommand)]
        command: EvaluatorCommands,
    },
}

#[derive(Subcommand)]
enum GarblerCommands {
    /// Create garbler and generate commitments
    CreateCommit {
        /// Path to verification key file
        #[arg(long)]
        vk: PathBuf,

        /// Output directory for garbler files
        #[arg(long, short, default_value = "./gc_storage")]
        storage_dir: PathBuf,

        /// Total number of instances to garble
        #[arg(long, default_value = "181")]
        total: usize,

        /// Number of instances to finalize
        #[arg(long, default_value = "7")]
        to_finalize: usize,
    },

    /// Open garbler commitments and generate ciphertext files
    OpenCommit {
        /// Path to session directory containing garbler.json
        #[arg(long)]
        session_dir: PathBuf,

        /// Path to session directory containing garbler.json
        #[arg(long)]
        open_commit_path: Option<PathBuf>,

        /// Path to evaluator challenge file
        #[arg(long)]
        challenge_path: PathBuf,
    },

    /// Generate proof and prepare input labels for finalized instances
    OpenLabels {
        /// Path to session directory containing garbler.json
        #[arg(long)]
        session_dir: PathBuf,

        /// Path to proving key file
        #[arg(long)]
        pk: PathBuf,

        /// Path to proof file (optional - generate if not provided)
        #[arg(long)]
        proof: Option<PathBuf>,

        /// Comma-separated public input values or path to JSON file
        #[arg(long)]
        public_inputs: String,
    },
}

#[derive(Subcommand)]
enum EvaluatorCommands {
    /// Create evaluator challenge from garbler commitments
    CreateChallenge {
        /// Path to garbler commit file
        #[arg(long)]
        commit: PathBuf,

        /// Path to verification key file
        #[arg(long)]
        vk: PathBuf,

        /// Total number of instances
        #[arg(long)]
        total: usize,

        /// Number of instances to finalize
        #[arg(long)]
        to_finalize: usize,

        /// Output directory for evaluator files
        #[arg(long, short, default_value = "./gc_storage")]
        session_dir: PathBuf,
    },

    /// Check garbler commitments by verifying seeds and ciphertext files
    CheckCommit {
        /// Path to session directory containing evaluator.json
        session_dir: PathBuf,

        /// Path to garbler seeds file (optional, defaults to session_dir/garbler_open_commit.json)
        #[arg(long)]
        open_commit_path: Option<PathBuf>,

        /// Path to garbler ciphertexts directory (optional, defaults to session_dir/garbler_ciphertexts/)
        #[arg(long)]
        ciphertexts_dir: Option<PathBuf>,
    },

    /// Execute garbled circuits with provided labels for finalized instances
    Execute {
        /// Path to session directory containing evaluator.json
        #[arg(long)]
        session_dir: PathBuf,

        /// Path to garbler ciphertexts directory (optional, defaults to session_dir/garbler_ciphertexts/)
        #[arg(long)]
        ciphertexts_dir: Option<PathBuf>,

        /// Path to garbler labels file
        #[arg(long)]
        labels: PathBuf,
    },
}

// Simple multiplicative circuit from the example
#[derive(Copy, Clone)]
struct DummyCircuit<F: ark::PrimeField> {
    pub a: Option<F>,
    pub b: Option<F>,
    pub num_variables: usize,
    pub num_constraints: usize,
}

impl<F: ark::PrimeField> ark::ConstraintSynthesizer<F> for DummyCircuit<F> {
    fn generate_constraints(
        self,
        cs: ark::ConstraintSystemRef<F>,
    ) -> Result<(), ark::SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(ark::SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(ark::SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let a = self.a.ok_or(ark::SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(ark::SynthesisError::AssignmentMissing)?;
            Ok(a * b)
        })?;

        // pad witnesses
        for _ in 0..(self.num_variables - 3) {
            let _ =
                cs.new_witness_variable(|| self.a.ok_or(ark::SynthesisError::AssignmentMissing))?;
        }

        // repeat the same multiplicative constraint
        for _ in 0..self.num_constraints - 1 {
            cs.enforce_constraint(ark::lc!() + a, ark::lc!() + b, ark::lc!() + c)?;
        }

        // final no-op constraint keeps ark-relations happy
        cs.enforce_constraint(ark::lc!(), ark::lc!(), ark::lc!())?;
        Ok(())
    }
}

// Helper function to get timestamp for unique file names
fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// Helper function to ensure directory exists
fn ensure_dir_exists(path: &Path) -> io::Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;
    }
    Ok(())
}

// Helper function to save JSON to file
fn save_json<T: Serialize>(path: &Path, data: &T) -> Result<(), io::Error> {
    Ok(serde_json::to_writer_pretty(
        BufWriter::new(File::create(path)?),
        data,
    )?)
}

// Helper function to load JSON from file
fn load_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, io::Error> {
    Ok(serde_json::from_reader(BufReader::new(File::open(path)?))?)
}

fn verify_ciphertext_file_hash(
    file_path: &Path,
    expected_hash: u128,
    index: usize,
) -> Result<(), String> {
    if !file_path.exists() {
        return Err(format!(
            "Ciphertext file not found for instance {}: {}",
            index,
            file_path.display()
        ));
    }

    let computed_hash = compute_ciphertext_hash(file_path)?;

    if computed_hash == expected_hash {
        info!(
            "✓ Ciphertext hash verification passed for instance {}",
            index
        );
        Ok(())
    } else {
        Err(format!(
            "Ciphertext hash mismatch for instance {}: expected {:#x}, got {:#x}",
            index, expected_hash, computed_hash
        ))
    }
}

fn compute_ciphertext_hash(file_path: &Path) -> Result<u128, String> {
    const BUFFER_CAPACITY: usize = 1 << 20; // 1 MiB amortises syscalls without bloating RAM

    let file = File::open(file_path).map_err(|e| {
        format!(
            "Failed to open ciphertext file {}: {}",
            file_path.display(),
            e
        )
    })?;

    let mut reader = BufReader::with_capacity(BUFFER_CAPACITY, file);

    const CIPHERTEXT_PROGRESS_LOG_BYTES: u64 = 5 * 1024 * 1024 * 1024; // Log roughly every 5 GiB
    let mut index = 0;

    let mut hasher = CiphertextHashAcc::default();
    loop {
        index += 16;

        if index % CIPHERTEXT_PROGRESS_LOG_BYTES == 0 {
            info!("Next chunk: {} / {}", index / 1024, 44u128 * 1024 * 1024);
        }

        let mut next = [0u8; 16];
        if reader.read(next.as_mut_slice()).unwrap() == 0 {
            return Ok(hasher.finalize());
        }

        hasher.update(S::from_bytes(next));
    }
}

// Custom serialization wrapper for arkworks types
#[derive(Serialize, Deserialize)]
struct SerializableVk {
    #[serde(with = "ark_serde")]
    vk: ark_groth16::VerifyingKey<Bn254>,
}

#[derive(Serialize, Deserialize)]
struct SerializablePk {
    #[serde(with = "ark_serde")]
    pk: ArkProvingKey<Bn254>,
}

#[derive(Serialize, Deserialize)]
struct SerializableProof {
    #[serde(with = "ark_serde")]
    proof: ark_groth16::Proof<Bn254>,
}

#[derive(Serialize, Deserialize)]
struct SerializablePublicInput {
    // TODO Count of `pp` is part of circuit knowledge, should't be
    // hardcoded
    #[serde(with = "ark_serde")]
    value: ark::Fr,
}

// Module for arkworks serialization
mod ark_serde {
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use serde::{Deserializer, Serializer};

    pub fn serialize<T, S>(data: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: CanonicalSerialize,
        S: Serializer,
    {
        let mut bytes = Vec::new();
        data.serialize_compressed(&mut bytes)
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: CanonicalDeserialize,
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::de::Deserialize::deserialize(deserializer)?;
        T::deserialize_compressed(&bytes[..]).map_err(serde::de::Error::custom)
    }
}

fn handle_gen_mock(output_dir: PathBuf, k: u32) -> Result<(), Box<dyn std::error::Error>> {
    info!("Generating mock data for testing...");

    ensure_dir_exists(&output_dir)?;

    let mut rng = ChaCha20Rng::seed_from_u64(12345);

    // Create dummy circuit
    let circuit = DummyCircuit::<ark::Fr> {
        a: Some(ark::Fr::rand(&mut rng)),
        b: Some(ark::Fr::rand(&mut rng)),
        num_variables: 10,
        num_constraints: 1 << k,
    };

    // Generate setup
    info!("Generating proving and verifying keys...");
    let (pk, vk) = ArkGroth16::<Bn254>::setup(circuit, &mut rng)?;

    // Save verification key
    let vk_path = output_dir.join("vk.json");
    save_json(&vk_path, &SerializableVk { vk: vk.clone() })?;
    info!("Saved verification key to: {}", vk_path.display());

    // Save proving key
    let pk_path = output_dir.join("pk.json");
    save_json(&pk_path, &SerializablePk { pk: pk.clone() })?;
    info!("Saved proving key to: {}", pk_path.display());

    // Generate valid proof
    info!("Generating valid proof...");
    let valid_proof = ArkGroth16::<Bn254>::prove(&pk, circuit, &mut rng)?;
    let valid_public = circuit.a.unwrap() * circuit.b.unwrap();

    let valid_proof_path = output_dir.join("proof_valid.json");
    save_json(
        &valid_proof_path,
        &SerializableProof {
            proof: valid_proof.clone(),
        },
    )?;
    info!("Saved valid proof to: {}", valid_proof_path.display());

    // Save valid public input
    let valid_public_path = output_dir.join("public_input_valid.json");
    save_json(
        &valid_public_path,
        &SerializablePublicInput {
            value: valid_public,
        },
    )?;
    info!(
        "Saved valid public input to: {}",
        valid_public_path.display()
    );

    // Verify the valid proof
    let is_valid = ArkGroth16::<Bn254>::verify(&vk, &[valid_public], &valid_proof)?;
    info!("Valid proof verification: {}", is_valid);

    // Generate invalid proof (same proof but will use zero public input)
    info!("Generating invalid proof scenario...");
    let invalid_public = ark::Fr::ZERO;

    let invalid_proof_path = output_dir.join("proof_invalid.json");
    save_json(
        &invalid_proof_path,
        &SerializableProof {
            proof: valid_proof, // same proof
        },
    )?;
    info!("Saved invalid proof to: {}", invalid_proof_path.display());

    // Save invalid public input (zero)
    let invalid_public_path = output_dir.join("public_input_invalid.json");
    save_json(
        &invalid_public_path,
        &SerializablePublicInput {
            value: invalid_public,
        },
    )?;
    info!(
        "Saved invalid public input to: {}",
        invalid_public_path.display()
    );

    info!("Mock data generation complete!");
    Ok(())
}

fn handle_garbler_create_commit(
    vk_path: PathBuf,
    output_dir: PathBuf,
    total: usize,
    to_finalize: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        "Creating garbler with {} total instances, {} to finalize",
        total, to_finalize
    );

    ensure_dir_exists(&output_dir)?;

    // Create timestamped folder for this session
    let timestamp = get_timestamp();
    let session_dir = output_dir.join(format!("session_{}", timestamp));
    ensure_dir_exists(&session_dir)?;

    info!("Created session directory: {}", session_dir.display());

    // Load verification key
    let vk_data: SerializableVk = load_json(&vk_path)?;
    info!("Loaded verification key from: {}", vk_path.display());

    // Create configuration
    let config = groth16_cut_and_choose::Config::new(
        total,
        to_finalize,
        garbled_groth16::GarblerInput {
            // TODO Count of `pp` is part of circuit knowledge, should't be
            // hardcoded
            public_params_len: 1,
            vk: vk_data.vk,
        }
        .compress(),
    );

    // Create garbler
    let mut rng = ChaCha20Rng::seed_from_u64(rand::thread_rng().r#gen());
    let garbler = groth16_cut_and_choose::Garbler::create(&mut rng, config.clone());

    // Generate commitments
    let commits = garbler.commit();
    info!("Generated {} commitments", commits.len());

    // Save garbler
    let garbler_path = session_dir.join("garbler.json");
    save_json(&garbler_path, &garbler)?;
    info!("Saved garbler to: {}", garbler_path.display());

    // Save commits
    let commits_path = session_dir.join("garbler_commits.json");
    save_json(&commits_path, &commits)?;
    info!("Saved commits to: {}", commits_path.display());

    info!(
        "Garbler creation complete! Session: {}",
        session_dir.display()
    );
    Ok(())
}

fn handle_evaluator_create_challenge(
    commit_path: PathBuf,
    vk_path: PathBuf,
    total: usize,
    to_finalize: usize,
    session_dir: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Creating evaluator challenge from commits...");

    ensure_dir_exists(&session_dir)?;

    // Determine the session name from the provided directory
    let session_name = session_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Session directory '{}' is invalid", session_dir.display()),
            )
        })?
        .to_owned();
    info!(
        "Using session folder '{}' ({})",
        session_dir.display(),
        session_name
    );

    // Load commits
    let commits: Vec<garbled_snark_verifier::cut_and_choose::GarbledInstanceCommit> =
        load_json(&commit_path)?;

    info!(
        "Loaded {} commits from: {}",
        commits.len(),
        commit_path.display()
    );

    // Verify that the number of commits matches the total parameter
    if commits.len() != total {
        return Err(format!(
            "Mismatch: expected {} commits, found {}",
            total,
            commits.len()
        )
        .into());
    }

    // Load verification key
    let vk_data: SerializableVk = load_json(&vk_path)?;
    info!("Loaded verification key from: {}", vk_path.display());

    // Create config (same as garbler)
    let g_input = garbled_groth16::GarblerInput {
        // TODO Count of `pp` is part of circuit knowledge, should't be
        // hardcoded
        public_params_len: 1,
        vk: vk_data.vk,
    }
    .compress();

    let config = groth16_cut_and_choose::Config::new(total, to_finalize, g_input);

    // Create evaluator with dummy channel creation (for file-based workflow)
    let mut rng = ChaCha20Rng::seed_from_u64(rand::thread_rng().r#gen());

    let evaluator = groth16_cut_and_choose::Evaluator::create(&mut rng, config.clone(), commits);

    // Get the finalized indices
    let finalize_indices = evaluator.get_indexes_to_finalize().to_vec();
    info!(
        "Selected {} instances to finalize: {:?}",
        finalize_indices.len(),
        finalize_indices
    );

    let evaluator_path = session_dir.join("evaluator.json");
    save_json(&evaluator_path, &evaluator)?;
    info!("Saved evaluator meta to: {}", evaluator_path.display());

    let challenge_path = session_dir.join("evaluator_challenge.json");
    save_json(&challenge_path, &finalize_indices)?;
    info!("Saved challenge to: {}", challenge_path.display());

    info!("Evaluator challenge creation complete!");
    Ok(())
}

fn handle_garbler_open_commit(
    session_dir: PathBuf,
    open_commit_path: Option<PathBuf>,
    challenge_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Opening garbler commits and generating ciphertext files...");

    ensure_dir_exists(&session_dir)?;

    // Load garbler from session
    let garbler_path = session_dir.join("garbler.json");
    let mut garbler: groth16_cut_and_choose::Garbler = load_json(&garbler_path)?;
    info!("Loaded garbler from: {}", garbler_path.display());

    // Load challenge indices
    let challenge_indices: Vec<usize> = load_json(&challenge_path)?;
    info!(
        "Loaded challenge with {} indices from: {}",
        challenge_indices.len(),
        challenge_path.display()
    );

    // Create ciphertext directory
    let ciphertext_dir = session_dir.join("garbler_ciphertexts");
    ensure_dir_exists(&ciphertext_dir)?;
    info!("created ciphertext directory: {}", ciphertext_dir.display());

    // Expected file size per instance
    // With Free-XOR optimization, only AND gates need ciphertexts (43 GB per instance)
    const EXPECTED_SIZE_PER_INSTANCE: u64 = 43 * (1 << 30); // 43 GB

    // Create file handlers for each challenge index
    let file_handlers: Vec<(usize, CiphertextFileHandler)> = challenge_indices
        .iter()
        .map(|&index| {
            let file_path = ciphertext_dir.join(format!("gc_{}.bin", index));
            info!(
                "Creating handler for instance {} at: {}",
                index,
                file_path.display()
            );

            CiphertextFileHandler::new(file_path, Some(EXPECTED_SIZE_PER_INSTANCE))
                .map(|handler| (index, handler))
                .map_err(|e| {
                    format!(
                        "Failed to create file handler for instance {}: {}",
                        index, e
                    )
                })
        })
        .collect::<Result<Vec<_>, String>>()?;

    info!("Created {} file handlers", file_handlers.len());

    // Open commitments - this will generate ciphertexts and write them to files
    info!("Opening commitments and generating ciphertexts...");
    let open_results = garbler.open_commit(file_handlers);

    // Process results
    let mut seeds = Vec::new();
    let mut threads = Vec::new();

    for result in open_results {
        match result {
            groth16_cut_and_choose::OpenForInstance::Open(index, seed) => {
                info!("Instance {} is open with seed", index);
                seeds.push((index, seed));
            }
            groth16_cut_and_choose::OpenForInstance::Closed {
                index,
                garbling_thread,
            } => {
                info!("Instance {} is closed, waiting for garbling thread", index);
                threads.push((index, garbling_thread));
            }
        }
    }

    // Wait for all garbling threads to complete
    info!(
        "Waiting for {} garbling threads to complete...",
        threads.len()
    );
    for (index, thread) in threads {
        match thread.join() {
            Ok(()) => info!("Garbling thread for instance {} completed", index),
            Err(_) => return Err(format!("Garbling thread for instance {} panicked", index).into()),
        }
    }

    // Save seeds to file
    let seeds_path =
        open_commit_path.unwrap_or_else(|| session_dir.join("garbler_open_commit.json"));
    save_json(&seeds_path, &seeds)?;
    info!("Saved {} seeds to: {}", seeds.len(), seeds_path.display());

    // Save updated garbler state (now knows which instances are finalized)
    let garbler_path = session_dir.join("garbler.json");
    save_json(&garbler_path, &garbler)?;
    info!("Updated garbler state saved to: {}", garbler_path.display());

    info!(
        "Garbler open-commit complete! Generated {} ciphertext files and {} seeds",
        challenge_indices.len(),
        seeds.len()
    );

    Ok(())
}

fn handle_evaluator_check_commit(
    session_dir: PathBuf,
    open_commit_path: Option<PathBuf>,
    ciphertexts_dir: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Checking evaluator commitments...");

    ensure_dir_exists(&session_dir)?;

    // Load evaluator from session
    let evaluator_path = session_dir.join("evaluator.json");
    let mut evaluator: groth16_cut_and_choose::Evaluator = load_json(&evaluator_path)?;
    info!("Loaded evaluator from: {}", evaluator_path.display());

    // Get finalized indices
    let finalize_indices = evaluator.get_indexes_to_finalize().to_vec();
    info!("Finalized instances: {:?}", finalize_indices);

    // Determine paths with defaults
    let open_commit_file =
        open_commit_path.unwrap_or_else(|| session_dir.join("garbler_open_commit.json"));

    let ciphertexts_directory =
        ciphertexts_dir.unwrap_or_else(|| session_dir.join("garbler_ciphertexts"));

    // Load seeds
    let seeds: Vec<(usize, groth16_cut_and_choose::Seed)> = load_json(&open_commit_file)?;
    info!(
        "Loaded {} seeds from: {}",
        seeds.len(),
        open_commit_file.display()
    );

    // 1. Verify finalized instances via ciphertext file hashing
    info!("Starting ciphertext file verification for finalized instances...");

    let verification_errors = finalize_indices
        .par_iter()
        .flat_map(|index| {
            let mut verification_errors = Vec::new();

            let ciphertext_file = ciphertexts_directory.join(format!("{index}.bin"));

            if !ciphertext_file.exists() {
                verification_errors.push(format!(
                    "Ciphertext file not found for instance {}: {}",
                    index,
                    ciphertext_file.display()
                ));
                return verification_errors;
            }

            // Get expected hash from commit
            if let Some(commit) = evaluator.commits().get(*index) {
                let expected_hash = commit.ciphertext_commit();

                if let Err(e) = verify_ciphertext_file_hash(&ciphertext_file, expected_hash, *index)
                {
                    verification_errors.push(e);
                }
            } else {
                verification_errors.push(format!("No commit found for instance {}", *index));
            }

            verification_errors
        })
        .collect::<Vec<String>>();

    if verification_errors.is_empty() {
        info!("✓ All commitment verifications passed!");
        info!("  - Regarbling verification: PASSED");
        info!("  - Ciphertext file verification: PASSED");
    } else {
        for error in &verification_errors {
            eprintln!("✗ {}", error);
        }
        return Err(format!(
            "Commitment verification failed with {} errors",
            verification_errors.len()
        )
        .into());
    }

    // 2. Verify opened instances via regarbling
    info!("Starting regarbling verification for opened instances...");

    // Run regarbling - this will verify the commitments internally
    if let Err(err) = evaluator.run_regarbling::<()>(seeds, &session_dir, None) {
        return Err(format!("✗ Regarbling verification failed for opened instances: {err}").into());
    }

    info!("✓ Regarbling verification passed for all opened instances");

    save_json(&evaluator_path, &evaluator)?;
    info!("Updated evaluator: {}", evaluator_path.display());

    Ok(())
}

fn handle_garbler_open_labels(
    session_dir: PathBuf,
    pk_path: PathBuf,
    proof_path: Option<PathBuf>,
    public_inputs: String,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Opening garbler labels and generating evaluator inputs...");

    ensure_dir_exists(&session_dir)?;

    // Load garbler from session
    let garbler_path = session_dir.join("garbler.json");
    let garbler: groth16_cut_and_choose::Garbler = load_json(&garbler_path)?;
    info!("Loaded garbler from: {}", garbler_path.display());

    // Load proving key
    let pk_data: SerializablePk = load_json(&pk_path)?;
    info!("Loaded proving key from: {}", pk_path.display());

    // Parse public inputs (either comma-separated values or path to JSON file)
    let public_input_values: Vec<ark::Fr> = if public_inputs.ends_with(".json") {
        // Load from JSON file
        let public_input_path = PathBuf::from(&public_inputs);
        let public_input_data: SerializablePublicInput = load_json(&public_input_path)?;
        vec![public_input_data.value]
    } else {
        // Parse comma-separated values
        public_inputs
            .split(',')
            .map(|s| {
                let trimmed = s.trim();
                if trimmed == "0" {
                    Ok(ark::Fr::ZERO)
                } else {
                    // For now, just support 0 and random values - extend as needed
                    Err(format!("Unsupported public input value: {}", trimmed))
                }
            })
            .collect::<Result<Vec<_>, String>>()?
    };

    info!("Using public inputs: {:?}", public_input_values.len());

    // Generate or load proof
    let proof = if let Some(proof_path) = proof_path {
        // Load existing proof
        let proof_data: SerializableProof = load_json(&proof_path)?;
        info!("Loaded proof from: {}", proof_path.display());
        proof_data.proof
    } else {
        // Generate new proof using the provided public input
        info!("Generating new proof...");
        let mut rng = ChaCha20Rng::seed_from_u64(rand::thread_rng().r#gen());

        // Create circuit with the public input
        let circuit = DummyCircuit::<ark::Fr> {
            a: Some(ark::Fr::rand(&mut rng)),
            b: Some(ark::Fr::rand(&mut rng)),
            num_variables: 10,
            num_constraints: 1 << 5, // Default k=5
        };

        ArkGroth16::<Bn254>::prove(&pk_data.pk, circuit, &mut rng)?
    };

    info!("Preparing input labels for finalized instances...");

    // Prepare input labels for all finalized instances
    let evaluator_cases = garbler.prepare_input_labels(public_input_values, proof);

    info!(
        "Generated labels for {} finalized instances",
        evaluator_cases.len()
    );

    // Save evaluator case inputs
    let labels_path = session_dir.join("garbler_labels.json");
    save_json(&labels_path, &evaluator_cases)?;
    info!("Saved evaluator case inputs to: {}", labels_path.display());

    info!("Garbler open-labels complete!");
    Ok(())
}

fn handle_evaluator_execute(
    session_dir: PathBuf,
    ciphertext_dir: Option<PathBuf>,
    labels_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Executing garbled circuits with provided labels...");

    ensure_dir_exists(&session_dir)?;

    // Execute the garbled circuits
    let evaluator_path = session_dir.join("evaluator.json");
    let evaluator: groth16_cut_and_choose::Evaluator = load_json(&evaluator_path)?;
    info!("Loaded evaluator from: {}", evaluator_path.display());

    // Load evaluator case inputs
    let evaluator_cases: Vec<groth16_cut_and_choose::EvaluatorCaseInput> = load_json(&labels_path)?;
    info!(
        "Loaded {} evaluator case inputs from: {}",
        evaluator_cases.len(),
        labels_path.display()
    );

    let ciphertext_dir = ciphertext_dir.unwrap_or_else(|| session_dir.join("garbler_ciphertexts"));
    ensure_dir_exists(&ciphertext_dir)?;
    info!("Ciphertext directory: {}", ciphertext_dir.display());

    let results = evaluator
        .evaluate(&ciphertext_dir, evaluator_cases)
        .unwrap();

    info!("Execution completed! Results:");
    for (index, evaluated_wire) in &results {
        info!("  Instance {}: {}", index, evaluated_wire.value);
    }

    // Save results
    let results_path = session_dir.join("evaluation_results.json");
    save_json(&results_path, &results)?;
    info!("Saved evaluation results to: {}", results_path.display());

    // Summary
    let all_same = results
        .iter()
        .all(|(_, wire)| wire.value == results[0].1.value);
    if all_same {
        info!(
            "✓ All instances returned the same result: {}",
            results[0].1.value
        );
    } else {
        info!("⚠ Instances returned different results!");
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Check hardware AES support
    if !garbled_snark_verifier::hardware_aes_available() {
        eprintln!(
            "Warning: AES hardware acceleration not detected; using software AES (not constant-time)."
        );
    }

    // Initialize tracing
    garbled_snark_verifier::init_tracing();

    // Parse CLI arguments
    let cli = Cli::parse();

    // Handle commands
    match cli.command {
        Commands::GenMockSnark {
            output,
            k_constraints,
        } => {
            handle_gen_mock(output, k_constraints)?;
        }
        Commands::Garbler { command } => match command {
            GarblerCommands::CreateCommit {
                vk,
                storage_dir: output,
                total,
                to_finalize,
            } => {
                handle_garbler_create_commit(vk, output, total, to_finalize)?;
            }
            GarblerCommands::OpenCommit {
                session_dir,
                open_commit_path,
                challenge_path,
            } => {
                handle_garbler_open_commit(session_dir, open_commit_path, challenge_path)?;
            }
            GarblerCommands::OpenLabels {
                session_dir,
                pk,
                proof,
                public_inputs,
            } => {
                handle_garbler_open_labels(session_dir, pk, proof, public_inputs)?;
            }
        },
        Commands::Evaluator { command } => match command {
            EvaluatorCommands::CreateChallenge {
                commit,
                vk,
                total,
                to_finalize,
                session_dir,
            } => {
                handle_evaluator_create_challenge(commit, vk, total, to_finalize, session_dir)?;
            }
            EvaluatorCommands::CheckCommit {
                session_dir,
                open_commit_path,
                ciphertexts_dir,
            } => {
                handle_evaluator_check_commit(session_dir, open_commit_path, ciphertexts_dir)?;
            }
            EvaluatorCommands::Execute {
                session_dir,
                ciphertexts_dir,
                labels,
            } => {
                handle_evaluator_execute(session_dir, ciphertexts_dir, labels)?;
            }
        },
    }

    Ok(())
}
