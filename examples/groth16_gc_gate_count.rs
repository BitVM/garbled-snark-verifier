// Groth16-based gate-count example emitting the JSON schema used by CI badges.
// Modeled after examples/groth16_mpc.rs, but focused on counting and JSON output.

use std::env;

use ark_ec::AffineRepr;
use garbled_snark_verifier::{
    ark,
    ark::{CircuitSpecificSetupSNARK, SNARK, UniformRand},
    circuit::{CircuitBuilder, StreamingResult},
    garbled_groth16,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

// Human-readable number formatter
fn format_number(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.1}B", n as f64 / 1_000_000_000.0)
    } else if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

/// Circuit size parameter k, where constraints = 2^k
const K: usize = 6; // match main branch default

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

        for _ in 0..(self.num_variables - 3) {
            let _ =
                cs.new_witness_variable(|| self.a.ok_or(ark::SynthesisError::AssignmentMissing))?;
        }
        for _ in 0..self.num_constraints - 1 {
            cs.enforce_constraint(ark::lc!() + a, ark::lc!() + b, ark::lc!() + c)?;
        }
        cs.enforce_constraint(ark::lc!(), ark::lc!(), ark::lc!())?;
        Ok(())
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let json_output = args.iter().any(|a| a == "--json");
    let is_compressed = args.iter().any(|a| a == "--compressed");
    if !json_output {
        println!(
            "Running Groth16 gate-count example: k={}, constraints={}, mode={}",
            K,
            1 << K,
            if is_compressed {
                "compressed"
            } else {
                "uncompressed"
            }
        );
    }

    // Deterministic RNG for reproducibility
    let mut rng = ChaCha20Rng::seed_from_u64(12345);

    // Build a tiny multiplicative circuit and produce a valid Groth16 proof
    let circuit = DummyCircuit::<ark::Fr> {
        a: Some(ark::Fr::rand(&mut rng)),
        b: Some(ark::Fr::rand(&mut rng)),
        num_variables: 10,
        num_constraints: 1 << K,
    };

    let (pk, vk) = ark::Groth16::<ark::Bn254>::setup(circuit, &mut rng).unwrap();
    let c_val = circuit.a.unwrap() * circuit.b.unwrap();
    let proof = ark::Groth16::<ark::Bn254>::prove(&pk, circuit, &mut rng).unwrap();

    // Construct input once, then choose uncompressed vs compressed execution
    let verify = garbled_groth16::VerifierInput {
        public: vec![c_val],
        a: proof.a.into_group(),
        b: proof.b.into_group(),
        c: proof.c.into_group(),
        vk: vk.clone(),
    };

    let (verified, gate_count) = if is_compressed {
        // Compressed path includes decompression gadgets; allocate more gates
        let result: StreamingResult<_, _, bool> = CircuitBuilder::streaming_execute(
            verify.compress(),
            160_000,
            garbled_groth16::verify_compressed,
        );

        (result.output_value, result.gate_count)
    } else {
        let result: StreamingResult<_, _, bool> =
            CircuitBuilder::streaming_execute(verify, 160_000, garbled_groth16::verify);

        (result.output_value, result.gate_count)
    };

    let total_gates = gate_count.total_gate_count();
    let nonfree_gates = gate_count.nonfree_gate_count();
    let free_gates = total_gates.saturating_sub(nonfree_gates);

    if json_output {
        let output = serde_json::json!({
            "circuit_size": { "k": K, "constraints": 1 << K },
            "gate_count": {
                "nonfree": nonfree_gates,
                "nonfree_formatted": format_number(nonfree_gates),
                "free": free_gates,
                "free_formatted": format_number(free_gates),
                "total": total_gates,
                "total_formatted": format_number(total_gates),
                "breakdown": gate_count.0
            },
            "verification_result": verified,
            "compressed": is_compressed
        });
        println!("{}", serde_json::to_string_pretty(&output).expect("json"));
    } else {
        println!("\n=== GATE COUNT (Groth16) ===");
        println!("non-free: {}", nonfree_gates);
        println!("free:     {}", free_gates);
        println!("total:    {}", total_gates);
        println!("verified: {}", verified);
        println!(
            "mode:     {}",
            if is_compressed {
                "compressed"
            } else {
                "uncompressed"
            }
        );
    }
}
