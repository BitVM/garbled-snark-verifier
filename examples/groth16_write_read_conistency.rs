use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufReader, Read, Write},
    path::{Path, PathBuf},
};

use crossbeam::channel;
use garbled_snark_verifier::{
    self as gsv, GarbledWire, S,
    ark::{self, CircuitSpecificSetupSNARK, SNARK, UniformRand, VerifyingKey},
    cut_and_choose::EvaluatorCaseInput,
    garbled_groth16::{self, PublicParams},
    groth16_cut_and_choose as ccn,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tracing::info;

// Simple multiplicative circuit reused from the main example
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

        // final no-op
        cs.enforce_constraint(ark::lc!(), ark::lc!(), ark::lc!())?;
        Ok(())
    }
}

fn read_consts(path: PathBuf) -> (u128, u128) {
    let mut r = BufReader::new(File::open(path).expect("open consts"));
    let mut buf = [0u8; 32];
    r.read_exact(&mut buf).expect("read consts");
    let t = S::from_bytes(buf[0..16].try_into().unwrap()).to_u128();
    let f = S::from_bytes(buf[16..32].try_into().unwrap()).to_u128();
    (t, f)
}

fn read_labels(path: PathBuf) -> Vec<GarbledWire> {
    let mut r = BufReader::new(File::open(path).expect("open labels"));
    let mut hdr = [0u8; 8];
    r.read_exact(&mut hdr).expect("read labels count");
    let count = u64::from_le_bytes(hdr) as usize;
    let mut v = Vec::with_capacity(count);
    let mut rec = [0u8; 32];
    for _ in 0..count {
        r.read_exact(&mut rec).expect("read label rec");
        let l0 = S::from_bytes(rec[0..16].try_into().unwrap());
        let l1 = S::from_bytes(rec[16..32].try_into().unwrap());
        v.push(GarbledWire {
            label0: l0,
            label1: l1,
        });
    }
    v
}

fn write_consts(path: &Path, true_const: S, false_const: S) {
    let mut file = File::create(path).expect("create consts file");
    file.write_all(&true_const.to_bytes())
        .expect("write true const");
    file.write_all(&false_const.to_bytes())
        .expect("write false const");
}

fn write_labels(path: &Path, labels: &[GarbledWire]) {
    let mut file = File::create(path).expect("create labels file");
    file.write_all(&(labels.len() as u64).to_le_bytes())
        .expect("write labels count");
    for label in labels {
        file.write_all(&label.label0.to_bytes())
            .expect("write label0");
        file.write_all(&label.label1.to_bytes())
            .expect("write label1");
    }
}

#[derive(Clone)]
struct SnarkMaterial {
    public_params: PublicParams,
    proof: garbled_groth16::SnarkProof,
    vk: VerifyingKey<ark::Bn254>,
    garbler_input: garbled_groth16::GarblerCompressedInput,
}

fn build_snark_material() -> SnarkMaterial {
    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    let circuit = DummyCircuit::<ark::Fr> {
        a: Some(ark::Fr::rand(&mut rng)),
        b: Some(ark::Fr::rand(&mut rng)),
        num_variables: 10,
        num_constraints: 1 << 6,
    };
    let (pk, vk) = ark::Groth16::<ark::Bn254>::setup(circuit, &mut rng).expect("setup");
    let public_inputs = vec![circuit.a.unwrap() * circuit.b.unwrap()];

    let proof = ark::Groth16::<ark::Bn254>::prove(&pk, circuit, &mut rng).expect("prove");

    let garbler_input = garbled_groth16::GarblerInput {
        public_params_len: public_inputs.len(),
        vk: vk.clone(),
    }
    .compress();

    SnarkMaterial {
        public_params: public_inputs,
        proof,
        vk,
        garbler_input,
    }
}

fn parse_artifact(name: &str) -> Option<(usize, &'static str)> {
    let rest = name.strip_prefix("gc_")?;
    if let Some(idx) = rest.strip_suffix("_commit.json") {
        return idx.parse().ok().map(|i| (i, "commit"));
    }
    if let Some(idx) = rest.strip_suffix(".consts.bin") {
        return idx.parse().ok().map(|i| (i, "consts"));
    }
    if let Some(idx) = rest.strip_suffix(".labels.bin") {
        return idx.parse().ok().map(|i| (i, "labels"));
    }
    if let Some(idx) = rest.strip_suffix(".bin")
        && !idx.contains('.')
    {
        return idx.parse().ok().map(|i| (i, "cipher"));
    }

    None
}

fn find_complete_instance(folder: &Path) -> Option<usize> {
    let mut map: BTreeMap<usize, u8> = BTreeMap::new();
    if let Ok(entries) = std::fs::read_dir(folder) {
        for entry in entries.flatten() {
            if let Ok(file_type) = entry.file_type()
                && !file_type.is_file()
            {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some((idx, kind)) = parse_artifact(&name) {
                let bit = match kind {
                    "cipher" => 1u8 << 0,
                    "commit" => 1u8 << 1,
                    "consts" => 1u8 << 2,
                    "labels" => 1u8 << 3,
                    _ => 0,
                };
                let entry = map.entry(idx).or_default();
                *entry |= bit;
            }
        }
    }

    map.iter()
        .find_map(|(idx, mask)| if *mask == 0b1111 { Some(*idx) } else { None })
}

fn generate_instance(folder: &Path, material: &SnarkMaterial) {
    const TOTAL: usize = 1;
    const FINALIZE: usize = 1;

    info!("Generating fresh cut-and-choose artifacts");
    std::fs::create_dir_all(folder).expect("create output folder");

    let garbler_cfg = ccn::Config::new(TOTAL, FINALIZE, material.garbler_input.clone());
    let evaluator_cfg = ccn::Config::new(TOTAL, FINALIZE, material.garbler_input.clone());

    let mut garbler_rng = ChaCha20Rng::seed_from_u64(0xC0DEC0DE);
    let mut garbler = ccn::Garbler::create(&mut garbler_rng, garbler_cfg);
    let commits = garbler.commit();

    let mut senders = Vec::with_capacity(FINALIZE);
    let mut receiver_fn = |index| {
        let (tx, rx) = channel::unbounded();
        senders.push((index, tx));
        rx
    };

    let mut evaluator_rng = ChaCha20Rng::seed_from_u64(0xDEADBEEF);
    let evaluator =
        ccn::Evaluator::create(&mut evaluator_rng, evaluator_cfg, commits, &mut receiver_fn);

    let finalize_indices: Vec<usize> = evaluator.get_indexes_to_finalize().to_vec();
    let open_info = garbler.open_commit(senders);

    let mut seeds = Vec::new();
    let mut join_handles = Vec::new();
    for item in open_info {
        match item {
            ccn::OpenForInstance::Open(idx, seed) => seeds.push((idx, seed)),
            ccn::OpenForInstance::Closed {
                index,
                garbling_thread,
            } => join_handles.push((index, garbling_thread)),
        }
    }

    evaluator
        .run_regarbling(seeds, folder)
        .map_err(|_| "regarbling failed")
        .expect("regarbling to succeed");

    for (_idx, handle) in join_handles {
        handle.join().expect("garbling sender to finish");
    }

    for idx in finalize_indices {
        let true_const = garbler.true_wire_constant_for(idx);
        let false_const = garbler.false_wire_constant_for(idx);

        write_consts(
            &folder.join(format!("gc_{}.consts.bin", idx)),
            S::from_u128(true_const),
            S::from_u128(false_const),
        );

        let labels = garbler.input_labels_for(idx);
        write_labels(&folder.join(format!("gc_{}.labels.bin", idx)), &labels);
    }
}

fn ensure_instance(folder: &Path, material: &SnarkMaterial) -> usize {
    if let Some(idx) = find_complete_instance(folder) {
        return idx;
    }

    generate_instance(folder, material);

    find_complete_instance(folder).expect("instance generation should create files")
}

fn main() {
    if !gsv::hardware_aes_available() {
        eprintln!("Warning: AES-NI unavailable; falling back to software AES (slow).");
    }
    gsv::init_tracing();

    // Locate or generate saved ciphertext artifacts
    let folder: PathBuf = ["target", "cut_and_choose"].iter().collect();
    let material = build_snark_material();
    let index = ensure_instance(&folder, &material);

    info!("Evaluating saved instance index {}", index);

    // Load persisted constants and labels for this instance
    let consts_path = folder.join(format!("gc_{}.consts.bin", index));
    let labels_path = folder.join(format!("gc_{}.labels.bin", index));
    let (t_const, f_const) = read_consts(consts_path);
    let labels = read_labels(labels_path);

    // Build evaluator input
    let input = garbled_groth16::EvaluatorCompressedInput::new(
        material.public_params.clone(),
        material.proof.clone(),
        material.vk.clone(),
        labels,
    );

    // Evaluate via helper that streams from saved file
    let results = ccn::Evaluator::evaluate_from(
        &folder,
        vec![EvaluatorCaseInput {
            index,
            input,
            true_constant_wire: t_const,
            false_constant_wire: f_const,
        }],
    )
    .unwrap();

    let (_, out) = results.into_iter().next().unwrap();
    println!("Saved instance {} result: {}", index, out.value);
}
