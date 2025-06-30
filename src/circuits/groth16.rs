use crate::bag::*;
use crate::circuits::bn254::finalexp::{
    final_exponentiation_evaluate_fast, final_exponentiation_evaluate_montgomery_fast,
};
use crate::circuits::bn254::fq12::Fq12;
use crate::circuits::bn254::fr::Fr;
use crate::circuits::bn254::g1::{
    G1Projective, projective_to_affine_evaluate, projective_to_affine_evaluate_montgomery,
};
use crate::circuits::bn254::pairing::{
    multi_miller_loop_groth16_evaluate_fast, multi_miller_loop_groth16_evaluate_montgomery_fast,
};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, VariableBaseMSM};
use ark_ff::Field;

pub fn groth16_verifier(
    public: Vec<ark_bn254::Fr>,
    proof: ark_groth16::Proof<ark_bn254::Bn254>,
    vk: ark_groth16::VerifyingKey<ark_bn254::Bn254>,
) -> bool {
    let scalars = [vec![ark_bn254::Fr::ONE], public.clone()].concat();
    let msm = ark_bn254::G1Projective::msm(&vk.gamma_abc_g1, &scalars).unwrap();
    let qap = ark_bn254::Bn254::multi_miller_loop(
        [msm, proof.c.into_group(), proof.a.into_group()],
        [-vk.gamma_g2, -vk.delta_g2, proof.b],
    );
    let alpha_beta = ark_bn254::Bn254::final_exponentiation(ark_bn254::Bn254::multi_miller_loop(
        [vk.alpha_g1.into_group()],
        [-vk.beta_g2],
    ))
    .unwrap()
    .0
    .inverse()
    .unwrap();
    let f = ark_bn254::Bn254::final_exponentiation(qap).unwrap().0;
    f == alpha_beta
}

pub fn groth16_verifier_evaluate(
    public: Wires,
    proof_a: Wires,
    proof_b: Wires,
    proof_c: Wires,
    vk: ark_groth16::VerifyingKey<ark_bn254::Bn254>,
) -> (Wirex, GateCount) {
    let mut gate_count = GateCount::zero();
    let (msm_temp, gc) = (
        G1Projective::wires_set(
            ark_bn254::G1Projective::msm(&[vk.gamma_abc_g1[1]], &[Fr::from_wires(public.clone())])
                .unwrap(),
        ),
        GateCount::msm(),
    );
    // let (msm_temp, gc) = G1Projective::msm_with_constant_bases_evaluate::<10>(vec![public], vec![vk.gamma_abc_g1[1].into_group()]);
    gate_count += gc;
    let (msm, gc) = G1Projective::add_evaluate(
        msm_temp,
        G1Projective::wires_set(vk.gamma_abc_g1[0].into_group()),
    );
    gate_count += gc;

    let (msm_affine, gc) = projective_to_affine_evaluate(msm);
    gate_count += gc;

    let (f, gc) = multi_miller_loop_groth16_evaluate_fast(
        msm_affine,
        proof_c,
        proof_a,
        -vk.gamma_g2,
        -vk.delta_g2,
        proof_b,
    );
    gate_count += gc;

    let alpha_beta = ark_bn254::Bn254::final_exponentiation(ark_bn254::Bn254::multi_miller_loop(
        [vk.alpha_g1.into_group()],
        [-vk.beta_g2],
    ))
    .unwrap()
    .0
    .inverse()
    .unwrap();
    let (f, gc) = final_exponentiation_evaluate_fast(f); // Fq12::wires_set(ark_bn254::Bn254::final_exponentiation(MillerLoopOutput(Fq12::from_wires(f))).unwrap().0);
    gate_count += gc;

    let (result, gc) = Fq12::equal_constant_evaluate(f, alpha_beta);
    gate_count += gc;
    (result[0].clone(), gate_count)
}

pub fn groth16_verifier_evaluate_montgomery(
    public: Wires,
    proof_a: Wires,
    proof_b: Wires,
    proof_c: Wires,
    vk: ark_groth16::VerifyingKey<ark_bn254::Bn254>,
) -> (Wirex, GateCount) {
    let mut gate_count = GateCount::zero();
    let (msm_temp, gc) = (
        G1Projective::wires_set_montgomery(
            ark_bn254::G1Projective::msm(&[vk.gamma_abc_g1[1]], &[Fr::from_wires(public.clone())])
                .unwrap(),
        ),
        GateCount::msm_montgomery(),
    );
    // let (msm_temp, gc) = G1Projective::msm_with_constant_bases_evaluate_montgomery::<10>(vec![public], vec![vk.gamma_abc_g1[1].into_group()]);
    gate_count += gc;
    let (msm, gc) = G1Projective::add_evaluate_montgomery(
        msm_temp,
        G1Projective::wires_set_montgomery(vk.gamma_abc_g1[0].into_group()),
    );
    gate_count += gc;

    let (msm_affine, gc) = projective_to_affine_evaluate_montgomery(msm);
    gate_count += gc;

    let (f, gc) = multi_miller_loop_groth16_evaluate_montgomery_fast(
        msm_affine,
        proof_c,
        proof_a,
        -vk.gamma_g2,
        -vk.delta_g2,
        proof_b,
    );
    gate_count += gc;

    let alpha_beta = ark_bn254::Bn254::final_exponentiation(ark_bn254::Bn254::multi_miller_loop(
        [vk.alpha_g1.into_group()],
        [-vk.beta_g2],
    ))
    .unwrap()
    .0
    .inverse()
    .unwrap();
    let (f, gc) = final_exponentiation_evaluate_montgomery_fast(f); // Fq12::wires_set(ark_bn254::Bn254::final_exponentiation(MillerLoopOutput(Fq12::from_wires(f))).unwrap().0);
    gate_count += gc;

    let (result, gc) = Fq12::equal_constant_evaluate(f, Fq12::as_montgomery(alpha_beta));
    gate_count += gc;
    (result[0].clone(), gate_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::bn254::g1::G1Affine;
    use crate::circuits::bn254::g2::G2Affine;
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_ff::{PrimeField, UniformRand};
    use ark_groth16::Groth16;
    use ark_relations::lc;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_std::{
        rand::{RngCore, SeedableRng},
        test_rng,
    };

    #[derive(Copy, Clone)]
    struct DummyCircuit<F: PrimeField> {
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
                let _ =
                    cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
            }

            for _ in 0..self.num_constraints - 1 {
                cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
            }

            cs.enforce_constraint(lc!(), lc!(), lc!())?;

            Ok(())
        }
    }

    #[test]
    fn test_groth16_verifier() {
        let k = 6;
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let circuit = DummyCircuit::<<ark_bn254::Bn254 as Pairing>::ScalarField> {
            a: Some(<ark_bn254::Bn254 as Pairing>::ScalarField::rand(&mut rng)),
            b: Some(<ark_bn254::Bn254 as Pairing>::ScalarField::rand(&mut rng)),
            num_variables: 10,
            num_constraints: 1 << k,
        };
        let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();

        let c = circuit.a.unwrap() * circuit.b.unwrap();

        let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();
        assert!(groth16_verifier(vec![c], proof, vk));
    }

    #[test]
    fn test_groth16_verifier_evaluate() {
        let k = 6;
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let circuit = DummyCircuit::<<ark_bn254::Bn254 as Pairing>::ScalarField> {
            a: Some(<ark_bn254::Bn254 as Pairing>::ScalarField::rand(&mut rng)),
            b: Some(<ark_bn254::Bn254 as Pairing>::ScalarField::rand(&mut rng)),
            num_variables: 10,
            num_constraints: 1 << k,
        };
        let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();

        let c = circuit.a.unwrap() * circuit.b.unwrap();

        let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();
        assert!(groth16_verifier(vec![c], proof.clone(), vk.clone()));

        println!("proof is correct in rust");

        let public = Fr::wires_set(c);
        let proof_a = G1Affine::wires_set(proof.a);
        let proof_b = G2Affine::wires_set(proof.b);
        let proof_c = G1Affine::wires_set(proof.c);

        let (result, gate_count) = groth16_verifier_evaluate(public, proof_a, proof_b, proof_c, vk);
        gate_count.print();
        assert!(result.borrow().get_value());
    }

    #[test]
    fn test_groth16_verifier_evaluate_montgomery() {
        let k = 6;
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let circuit = DummyCircuit::<<ark_bn254::Bn254 as Pairing>::ScalarField> {
            a: Some(<ark_bn254::Bn254 as Pairing>::ScalarField::rand(&mut rng)),
            b: Some(<ark_bn254::Bn254 as Pairing>::ScalarField::rand(&mut rng)),
            num_variables: 10,
            num_constraints: 1 << k,
        };
        let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();

        let c = circuit.a.unwrap() * circuit.b.unwrap();

        let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();
        assert!(groth16_verifier(vec![c], proof.clone(), vk.clone()));

        println!("proof is correct in rust");

        let public = Fr::wires_set(c);
        let proof_a = G1Affine::wires_set_montgomery(proof.a);
        let proof_b = G2Affine::wires_set_montgomery(proof.b);
        let proof_c = G1Affine::wires_set_montgomery(proof.c);

        let (result, gate_count) =
            groth16_verifier_evaluate_montgomery(public, proof_a, proof_b, proof_c, vk);
        gate_count.print();
        assert!(result.borrow().get_value());
    }
}
