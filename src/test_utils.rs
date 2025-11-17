use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::ark::{
    Bn254, CircuitSpecificSetupSNARK, ConstraintSynthesizer, ConstraintSystemRef, Fr, Groth16,
    PrimeField, ProvingKey, SynthesisError, UniformRand, VerifyingKey, lc,
};

pub fn trng() -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(0)
}

// Dummy circuit with public inputs for testing
#[derive(Copy, Clone)]
pub struct DummyCircuit<F: PrimeField> {
    pub a: Option<F>,
    pub b: Option<F>,
    pub num_variables: usize,
    pub num_constraints: usize,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
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

// Dummy circuit with no public inputs - only private witnesses
#[derive(Copy, Clone)]
pub struct DummyCircuitNoPublicInputs<F: PrimeField> {
    pub a: Option<F>,
    pub b: Option<F>,
    pub num_variables: usize,
    pub num_constraints: usize,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for DummyCircuitNoPublicInputs<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_witness_variable(|| {
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

/// Generate a dummy verification key with public inputs for testing.
/// Uses fixed k=6 (64 constraints) and 10 variables.
/// Returns: (proving_key, verifying_key, a_value, b_value, c_value_public)
pub fn dummy_vk_with_public_inputs() -> (ProvingKey<Bn254>, VerifyingKey<Bn254>, Fr, Fr, Fr) {
    let k = 6;
    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    let a = Fr::rand(&mut rng);
    let b = Fr::rand(&mut rng);
    let c = a * b;

    let circuit = DummyCircuit::<Fr> {
        a: Some(a),
        b: Some(b),
        num_variables: 10,
        num_constraints: 1 << k,
    };

    let (pk, vk) = Groth16::<Bn254>::setup(circuit, &mut rng).unwrap();
    (pk, vk, a, b, c)
}

/// Generate a dummy verification key without public inputs for testing.
/// Uses fixed k=6 (64 constraints) and 10 variables.
/// Returns: (proving_key, verifying_key, a_value, b_value, c_value_private)
pub fn dummy_vk_no_public_inputs() -> (ProvingKey<Bn254>, VerifyingKey<Bn254>, Fr, Fr, Fr) {
    let k = 6;
    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    let a = Fr::rand(&mut rng);
    let b = Fr::rand(&mut rng);
    let c = a * b;

    let circuit = DummyCircuitNoPublicInputs::<Fr> {
        a: Some(a),
        b: Some(b),
        num_variables: 10,
        num_constraints: 1 << k,
    };

    let (pk, vk) = Groth16::<Bn254>::setup(circuit, &mut rng).unwrap();
    (pk, vk, a, b, c)
}
