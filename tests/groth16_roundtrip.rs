//! Round-trip consistency test for EvaluatorCompressedInput
//!
//! Tests that proof -> EvaluatorCompressedInput -> proof preserves the original proof

#![cfg(feature = "test-utils")]

use garbled_snark_verifier::{
    ark::SNARK,
    circuit::modes::GarbleMode,
    garbled_groth16::{EvaluatorCompressedInput, GarblerInput},
    hashers::AesCcrGateHasher,
    test_utils::dummy_vk_with_public_inputs,
};

#[test]
fn test_evaluator_compressed_input_roundtrip() {
    // Use the existing test utility to generate a simple proof
    let (pk, vk, a, b, c) = dummy_vk_with_public_inputs();

    let circuit = garbled_snark_verifier::test_utils::DummyCircuit {
        a: Some(a),
        b: Some(b),
        num_variables: 10,
        num_constraints: 64,
    };

    // Generate proof
    let mut rng = garbled_snark_verifier::test_utils::trng();
    let proof = garbled_snark_verifier::ark::Groth16::<garbled_snark_verifier::ark::Bn254>::prove(
        &pk, circuit, &mut rng,
    )
    .expect("Prove failed");

    let public_params = vec![c];

    // Verify original proof is valid
    let is_valid =
        garbled_snark_verifier::ark::Groth16::<garbled_snark_verifier::ark::Bn254>::verify(
            &vk,
            &public_params,
            &proof,
        )
        .expect("Verification failed");
    assert!(is_valid, "Original proof should be valid");

    // Preallocate garbled wires
    let inputs = GarblerInput {
        public_params_len: public_params.len(),
        vk: vk.clone(),
    }
    .compress();

    let mut garbled_wires = GarbleMode::<AesCcrGateHasher, ()>::preallocate_input(42, &inputs);
    garbled_wires.remove(0); // Remove FALSE_WIRE
    garbled_wires.remove(0); // Remove TRUE_WIRE

    // Convert: proof -> EvaluatorCompressedInput
    let evaluator_input = EvaluatorCompressedInput::new(
        public_params.clone(),
        proof.clone(),
        vk.clone(),
        garbled_wires,
    );

    // Convert: EvaluatorCompressedInput -> proof
    let reconstructed_proof = evaluator_input.to_proof();
    let reconstructed_public = evaluator_input.to_public_inputs();

    // Verify reconstruction matches original
    assert_eq!(proof.a, reconstructed_proof.a, "Point A mismatch");
    assert_eq!(proof.b, reconstructed_proof.b, "Point B mismatch");
    assert_eq!(proof.c, reconstructed_proof.c, "Point C mismatch");
    assert_eq!(
        public_params, reconstructed_public,
        "Public inputs mismatch"
    );

    // Verify reconstructed proof is valid
    let is_valid =
        garbled_snark_verifier::ark::Groth16::<garbled_snark_verifier::ark::Bn254>::verify(
            &vk,
            &reconstructed_public,
            &reconstructed_proof,
        )
        .expect("Verification failed");
    assert!(is_valid, "Reconstructed proof should be valid");

    // Also test the convenient verify() method
    assert!(
        evaluator_input.verify(),
        "Direct verify() method should return true"
    );

    println!("✓ Round-trip test passed");
}

#[test]
fn test_evaluator_compressed_input_verify() {
    // Test the convenient verify() method
    let (pk, vk, a, b, c) = dummy_vk_with_public_inputs();

    let circuit = garbled_snark_verifier::test_utils::DummyCircuit {
        a: Some(a),
        b: Some(b),
        num_variables: 10,
        num_constraints: 64,
    };

    let mut rng = garbled_snark_verifier::test_utils::trng();
    let proof = garbled_snark_verifier::ark::Groth16::<garbled_snark_verifier::ark::Bn254>::prove(
        &pk, circuit, &mut rng,
    )
    .expect("Prove failed");

    let public_params = vec![c];

    // Create EvaluatorCompressedInput
    let inputs = GarblerInput {
        public_params_len: public_params.len(),
        vk: vk.clone(),
    }
    .compress();

    let mut garbled_wires = GarbleMode::<AesCcrGateHasher, ()>::preallocate_input(42, &inputs);
    garbled_wires.remove(0); // Remove FALSE_WIRE
    garbled_wires.remove(0); // Remove TRUE_WIRE

    let evaluator_input = EvaluatorCompressedInput::new(
        public_params.clone(),
        proof.clone(),
        vk.clone(),
        garbled_wires,
    );

    // Test verify() method
    assert!(
        evaluator_input.verify(),
        "Valid proof should verify successfully"
    );

    println!("✓ Direct verify() test passed");
}
