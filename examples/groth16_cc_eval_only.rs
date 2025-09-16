use std::{
    fs::File,
    io::{BufReader, Read},
    path::PathBuf,
};

use garbled_snark_verifier as gsv;
use gsv::{
    GarbledWire, S,
    ark::{self, CircuitSpecificSetupSNARK, SNARK, UniformRand},
    garbled_groth16, groth16_cut_and_choose as ccn,
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

fn main() {
    if !gsv::hardware_aes_available() {
        eprintln!("Warning: AES-NI unavailable; falling back to software AES (slow).");
    }
    gsv::init_tracing();

    // Locate the first saved ciphertext file
    let folder: PathBuf = ["target", "cut_and_choose"].iter().collect();
    let mut entries: Vec<_> = std::fs::read_dir(&folder)
        .expect("read dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .filter_map(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if let Some(idx_str) = name.strip_prefix("gc_") {
                if let Some(idx_str) = idx_str.strip_suffix(".bin") {
                    if let Ok(idx) = idx_str.parse::<usize>() {
                        return Some((idx, e.path()));
                    }
                }
            }
            None
        })
        .collect();

    entries.sort_by_key(|(idx, _)| *idx);
    let (index, _path) = entries.first().expect("no saved gc_*.bin files found");

    info!("Evaluating saved instance index {}", index);

    // Rebuild the same circuit + SNARK (deterministically)
    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    let circuit = DummyCircuit::<ark::Fr> {
        a: Some(ark::Fr::rand(&mut rng)),
        b: Some(ark::Fr::rand(&mut rng)),
        num_variables: 10,
        num_constraints: 1 << 6,
    };
    let (pk, vk) = ark::Groth16::<ark::Bn254>::setup(circuit, &mut rng).expect("setup");
    let c_val = circuit.a.unwrap() * circuit.b.unwrap();

    let eval_proof = garbled_groth16::Proof::new(
        ark::Groth16::<ark::Bn254>::prove(&pk, circuit, &mut rng).expect("prove"),
        vec![c_val],
    );

    // Load persisted constants and labels for this instance
    let consts_path = folder.join(format!("gc_{}.consts.bin", index));
    let labels_path = folder.join(format!("gc_{}.labels.bin", index));
    let (t_const, f_const) = read_consts(consts_path);
    let labels = read_labels(labels_path);

    // Build evaluator input
    let input = garbled_groth16::EvaluatorCompressedInput::new(eval_proof, vk, labels);

    // Evaluate via helper that streams from saved file
    let results = ccn::Evaluator::evaluate_from_saved_all(
        vec![(*index, input, (t_const, f_const))],
        160_000,
        &folder,
        garbled_groth16::verify_compressed,
    );

    let (_, out) = results.into_iter().next().unwrap();
    println!("Saved instance {} result: {}", index, out.value);
}
