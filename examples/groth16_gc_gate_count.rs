// Groth16-based gate-count example emitting the JSON schema used by CI badges.
// Modeled after examples/groth16_mpc.rs, but focused on counting and JSON output.

use std::env;

use ark_ec::AffineRepr;
use ark_ff::UniformRand;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use garbled_snark_verifier as gsv;
use gsv::{
    Groth16ExecInput,
    circuit::streaming::{CircuitBuilder, StreamingResult},
    groth16_verify,
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
struct DummyCircuit<F: ark_ff::PrimeField> {
    pub a: Option<F>,
    pub b: Option<F>,
    pub num_variables: usize,
    pub num_constraints: usize,
}

impl<F: ark_ff::PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(a * b)
        })?;

        for _ in 0..(self.num_variables - 3) {
            let _ = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        }
        for _ in 0..self.num_constraints - 1 {
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        }
        cs.enforce_constraint(lc!(), lc!(), lc!())?;
        Ok(())
    }
}

fn main() {
    let json_output = env::args().any(|a| a == "--json");
    if !json_output {
        println!(
            "Running Groth16 gate-count example: k={}, constraints={}",
            K,
            1 << K
        );
    }

    // Deterministic RNG for reproducibility
    let mut rng = ChaCha20Rng::seed_from_u64(12345);

    // Build a tiny multiplicative circuit and produce a valid Groth16 proof
    let circuit = DummyCircuit::<ark_bn254::Fr> {
        a: Some(ark_bn254::Fr::rand(&mut rng)),
        b: Some(ark_bn254::Fr::rand(&mut rng)),
        num_variables: 10,
        num_constraints: 1 << K,
    };

    let (pk, vk) = ark_groth16::Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();
    let c_val = circuit.a.unwrap() * circuit.b.unwrap();
    let proof = ark_groth16::Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();

    // Prepare input wires and run streaming execute to count gates
    let inputs = Groth16ExecInput {
        public: vec![c_val],
        a: proof.a.into_group(),
        b: proof.b.into_group(),
        c: proof.c.into_group(),
    };

    let result: StreamingResult<_, _, Vec<bool>> =
        CircuitBuilder::streaming_execute(inputs, 40_000, |ctx, wires| {
            let ok = groth16_verify(ctx, &wires.public, &wires.a, &wires.b, &wires.c, &vk);
            vec![ok]
        });

    let verified = result.output_wires[0];
    let total_gates = result.gate_count.total_gate_count();
    let nonfree_gates = result.gate_count.nonfree_gate_count();
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
                "breakdown": result.gate_count.0
            },
            "verification_result": verified
        });
        println!("{}", serde_json::to_string_pretty(&output).expect("json"));
    } else {
        println!("\n=== GATE COUNT (Groth16) ===");
        println!("non-free: {}", nonfree_gates);
        println!("free:     {}", free_gates);
        println!("total:    {}", total_gates);
        println!("verified: {}", verified);
    }
}
