// An isolated example that creates a Groth16 proof (BN254),
// then verifies it via the streaming MPC-style executor with logs enabled.
// Run with: `RUST_LOG=info cargo run --example groth16_mpc --release`

use garbled_snark_verifier::{
    ark::{self, AffineRepr, CircuitSpecificSetupSNARK, SNARK, UniformRand},
    circuit::{CircuitBuilder, StreamingResult},
    garbled_groth16, groth16_verify,
    test_utils::DummyCircuit,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn main() {
    if !garbled_snark_verifier::hardware_aes_available() {
        eprintln!(
            "Warning: AES hardware acceleration not detected; using software AES (not constant-time)."
        );
    }
    // Initialize tracing (default to info if RUST_LOG not set)
    garbled_snark_verifier::init_tracing();

    // 1) Build and prove a tiny multiplicative circuit
    let k = 6; // 2^k constraints
    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    let circuit = DummyCircuit::<ark::Fr> {
        a: Some(ark::Fr::rand(&mut rng)),
        b: Some(ark::Fr::rand(&mut rng)),
        num_variables: 10,
        num_constraints: 1 << k,
    };
    let (pk, vk) = ark::Groth16::<ark::Bn254>::setup(circuit, &mut rng).expect("setup");
    let c_val = circuit.a.unwrap() * circuit.b.unwrap();
    let proof = ark::Groth16::<ark::Bn254>::prove(&pk, circuit, &mut rng).expect("prove");

    // 2) Prepare inputs for the streaming gadget execution
    let inputs = garbled_groth16::VerifierInput {
        public: vec![c_val],
        a: proof.a.into_group(),
        b: proof.b.into_group(),
        c: proof.c.into_group(),
        vk: vk.clone(),
    };

    let result: StreamingResult<_, _, bool> =
        CircuitBuilder::streaming_execute(inputs, 150_000, groth16_verify);

    println!("verification_result={}", result.output_value);
    println!("gate count is {}", result.gate_count);
}
