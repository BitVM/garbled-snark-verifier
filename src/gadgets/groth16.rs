//! Groth16 verifier gadget for BN254 using the streaming-circuit API.
//!
//! Implements the standard Groth16 verification equation with gadgets:
//! e(A, B) * e(C, -delta) * e(msm, -gamma) == e(alpha, beta)
//! where `msm = vk.gamma_abc_g1[0] + sum_i(public[i] * vk.gamma_abc_g1[i+1])`.

use ark_ec::{AffineRepr, models::short_weierstrass::SWCurveConfig, pairing::Pairing};
use ark_ff::Field;
use circuit_component_macro::component;

use crate::{
    CircuitContext, WireId,
    circuit::{
        CircuitInput,
        streaming::{CircuitMode, EncodeInput, WiresObject},
    },
    gadgets::bn254::{
        final_exponentiation::final_exponentiation, fq::Fq, fq12::Fq12, fr::Fr, g1::G1Projective,
        pairing::multi_miller_loop_const_q,
    },
};

/// Verify Groth16 proof for BN254 using streaming gadgets.
///
/// - `public`: public inputs as Fr wires (bit-wires, Montgomery ops inside gadgets).
/// - `proof_a`, `proof_c`: proof G1 points as wires (Montgomery).
/// - `proof_b`: proof G2 point as host constant (affine).
/// - `vk`: verifying key with constant elements (host-provided arkworks types).
///
/// Returns a boolean wire that is 1 iff the proof verifies.
#[component(offcircuit_args = "proof_b, vk")]
pub fn groth16_verify<C: CircuitContext>(
    circuit: &mut C,
    public: &[Fr],
    proof_a: &G1Projective,
    proof_b: &ark_bn254::G2Affine,
    proof_c: &G1Projective,
    vk: &ark_groth16::VerifyingKey<ark_bn254::Bn254>,
) -> WireId {
    // Compute MSM over vk.gamma_abc_g1 with scalars [1] ++ public
    let mut scalars: Vec<Fr> = Vec::with_capacity(public.len() + 1);
    scalars.push(Fr::new_constant(&ark_bn254::Fr::ONE).expect("const one"));
    scalars.extend_from_slice(public);

    let bases: Vec<_> = vk
        .gamma_abc_g1
        .iter()
        .take(scalars.len())
        .map(|g| g.into_group())
        .collect();

    // Windowed MSM with constant bases
    let msm = G1Projective::msm_with_constant_bases_montgomery::<10, _>(circuit, &scalars, &bases);

    // Miller loop accumulators for the three terms
    let gamma_neg = -vk.gamma_g2;
    let delta_neg = -vk.delta_g2;

    // Mix optimized paths:
    // - Fuse Miller loop for the two affine points (A, C) to avoid two inversions.
    // - Use standard Miller loop for MSM (projective), then multiply once.
    let a_aff = proof_a.clone();
    let c_aff = proof_c.clone();
    let f_aff = crate::gadgets::bn254::pairing::multi_miller_loop_const_q_affine(
        circuit,
        &[c_aff, a_aff],
        &[delta_neg, *proof_b],
    );
    let f_msm = multi_miller_loop_const_q(circuit, &[msm], &[gamma_neg]);
    let f_all = Fq12::mul_montgomery(circuit, &f_aff, &f_msm);

    // Final exponentiation and equality check against e(alpha, beta)
    let f_final = final_exponentiation(circuit, &f_all);
    let expected = {
        let pairing = <ark_bn254::Bn254 as Pairing>::pairing(vk.alpha_g1, vk.beta_g2).0;
        Fq12::as_montgomery(pairing)
    };
    Fq12::equal_constant(circuit, &f_final, &expected)
}

/// Decompress a compressed G1 point (x, sign bit) into projective wires with z = 1 (Montgomery domain).
/// - `x_m`: x-coordinate in Montgomery form wires
/// - `y_flag`: boolean wire selecting the correct sqrt branch for y
#[component]
pub fn decompress_g1_from_compressed<C: CircuitContext>(
    circuit: &mut C,
    x_m: &Fq,
    y_flag: crate::WireId,
) -> G1Projective {
    use crate::gadgets::bigint::select;
    // rhs = x^3 + b (Montgomery domain)
    let x2 = Fq::square_montgomery(circuit, x_m);
    let x3 = Fq::mul_montgomery(circuit, &x2, x_m);
    let b_m = Fq::as_montgomery(ark_bn254::g1::Config::COEFF_B);
    let rhs = Fq::add_constant(circuit, &x3, &b_m);

    // sy = sqrt(rhs) in Montgomery domain
    let sy = Fq::sqrt_montgomery(circuit, &rhs);
    let sy_neg = Fq::neg(circuit, &sy);
    let y_bits = select(circuit, &sy.0, &sy_neg.0, y_flag);
    let y = Fq(y_bits);

    // z = 1 in Montgomery
    let one_m = Fq::as_montgomery(ark_bn254::Fq::ONE);
    let z = Fq::new_constant(&one_m).expect("const one mont");

    G1Projective {
        x: (*x_m).clone(),
        y,
        z,
    }
}

/// Convenience wrapper: verify using compressed A and C (x, y_flag). B remains host-provided `G2Affine`.
#[allow(clippy::too_many_arguments)]
#[component(offcircuit_args = "proof_b, vk")]
pub fn groth16_verify_compressed<C: CircuitContext>(
    circuit: &mut C,
    public: &[Fr],
    a_x: &Fq,
    a_y_flag: crate::WireId,
    proof_b: &ark_bn254::G2Affine,
    c_x: &Fq,
    c_y_flag: crate::WireId,
    vk: &ark_groth16::VerifyingKey<ark_bn254::Bn254>,
) -> crate::WireId {
    let a = decompress_g1_from_compressed(circuit, a_x, a_y_flag);
    let c = decompress_g1_from_compressed(circuit, c_x, c_y_flag);
    groth16_verify(circuit, public, &a, proof_b, &c, vk)
}

#[derive(Debug, Clone)]
pub struct Groth16ExecInput {
    pub public: Vec<ark_bn254::Fr>,
    pub a: ark_bn254::G1Projective,
    pub c: ark_bn254::G1Projective,
}

#[derive(Debug)]
pub struct Groth16ExecInputWires {
    pub public: Vec<Fr>,
    pub a: G1Projective,
    pub c: G1Projective,
}

impl CircuitInput for Groth16ExecInput {
    type WireRepr = Groth16ExecInputWires;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        Groth16ExecInputWires {
            public: self.public.iter().map(|_| Fr::new(&mut issue)).collect(),
            a: G1Projective::new(&mut issue),
            c: G1Projective::new(issue),
        }
    }
    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<crate::WireId> {
        let mut ids = Vec::new();
        for s in &repr.public {
            ids.extend(s.to_wires_vec());
        }
        ids.extend(repr.a.to_wires_vec());
        ids.extend(repr.c.to_wires_vec());
        ids
    }
}

impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for Groth16ExecInput {
    fn encode(&self, repr: &Groth16ExecInputWires, cache: &mut M) {
        // Encode public scalars
        for (w, v) in repr.public.iter().zip(self.public.iter()) {
            let fr_fn = Fr::get_wire_bits_fn(w, v).unwrap();

            for &wire in w.iter() {
                if let Some(bit) = fr_fn(wire) {
                    cache.feed_wire(wire, bit);
                }
            }
        }

        // Encode G1 points (Montgomery coordinates)
        let a_m = G1Projective::as_montgomery(self.a);
        let c_m = G1Projective::as_montgomery(self.c);

        let a_fn = G1Projective::get_wire_bits_fn(&repr.a, &a_m).unwrap();
        for &wire_id in repr
            .a
            .x
            .iter()
            .chain(repr.a.y.iter())
            .chain(repr.a.z.iter())
        {
            if let Some(bit) = a_fn(wire_id) {
                cache.feed_wire(wire_id, bit);
            }
        }
        let c_fn = G1Projective::get_wire_bits_fn(&repr.c, &c_m).unwrap();
        for &wire_id in repr
            .c
            .x
            .iter()
            .chain(repr.c.y.iter())
            .chain(repr.c.z.iter())
        {
            if let Some(bit) = c_fn(wire_id) {
                cache.feed_wire(wire_id, bit);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
    use ark_ff::UniformRand;
    use ark_groth16::Groth16;
    use ark_relations::{
        lc,
        r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    };
    use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::circuit::streaming::CircuitBuilder;

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
    fn test_groth16_verify_true() {
        let k = 6;
        let mut rng = ChaCha20Rng::seed_from_u64(12345);
        let circuit = DummyCircuit::<ark_bn254::Fr> {
            a: Some(ark_bn254::Fr::rand(&mut rng)),
            b: Some(ark_bn254::Fr::rand(&mut rng)),
            num_variables: 10,
            num_constraints: 1 << k,
        };
        let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();
        let c_val = circuit.a.unwrap() * circuit.b.unwrap();
        let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        // Build inputs for gadget (convert A,C to projective for wire encoding)
        let inputs = Groth16ExecInput {
            public: vec![c_val],
            a: proof.a.into_group(),
            c: proof.c.into_group(),
        };

        let out: crate::circuit::streaming::StreamingResult<_, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 40_000, |ctx, wires| {
                let ok = groth16_verify(ctx, &wires.public, &wires.a, &proof.b, &wires.c, &vk);
                vec![ok]
            });

        assert!(out.output_wires[0]);
    }

    #[test]
    fn test_groth16_verify_false_bitflip() {
        let k = 6;
        let mut rng = ChaCha20Rng::seed_from_u64(54321);
        let circuit = DummyCircuit::<ark_bn254::Fr> {
            a: Some(ark_bn254::Fr::rand(&mut rng)),
            b: Some(ark_bn254::Fr::rand(&mut rng)),
            num_variables: 10,
            num_constraints: 1 << k,
        };
        let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();
        let c_val = circuit.a.unwrap() * circuit.b.unwrap();
        let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        // Corrupt A by flipping the least significant bit of x (via +1)
        let mut a_bad = proof.a.into_group();
        a_bad.x += ark_bn254::Fq::ONE;

        let inputs = Groth16ExecInput {
            public: vec![c_val],
            a: a_bad,
            c: proof.c.into_group(),
        };

        let out: crate::circuit::streaming::StreamingResult<_, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 10_000, |ctx, wires| {
                let ok = groth16_verify(ctx, &wires.public, &wires.a, &proof.b, &wires.c, &vk);
                vec![ok]
            });

        assert!(!out.output_wires[0]);
    }

    #[test]
    fn test_groth16_verify_false_random() {
        use rand::{Rng, SeedableRng};
        use rand_chacha::ChaCha20Rng;

        fn rnd_fr<R: Rng>(rng: &mut R) -> ark_bn254::Fr {
            let mut prng = ChaCha20Rng::seed_from_u64(rng.r#gen());
            ark_bn254::Fr::rand(&mut prng)
        }
        fn random_g2_affine<R: Rng>(rng: &mut R) -> ark_bn254::G2Affine {
            (ark_bn254::G2Projective::generator() * rnd_fr(rng)).into_affine()
        }

        // Create a valid vk from a small circuit
        let k = 4;
        let mut rng = ChaCha20Rng::seed_from_u64(777);
        let circuit = DummyCircuit::<ark_bn254::Fr> {
            a: Some(ark_bn254::Fr::rand(&mut rng)),
            b: Some(ark_bn254::Fr::rand(&mut rng)),
            num_variables: 8,
            num_constraints: 1 << k,
        };
        let (_pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();

        // Random, unrelated inputs instead of a valid proof
        let inputs = Groth16ExecInput {
            public: vec![ark_bn254::Fr::rand(&mut rng)],
            a: (ark_bn254::G1Projective::generator() * ark_bn254::Fr::rand(&mut rng)),
            c: (ark_bn254::G1Projective::generator() * ark_bn254::Fr::rand(&mut rng)),
        };
        let b_rand = random_g2_affine(&mut rng);

        let out: crate::circuit::streaming::StreamingResult<_, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 10_000, |ctx, wires| {
                let ok = groth16_verify(ctx, &wires.public, &wires.a, &b_rand, &wires.c, &vk);
                vec![ok]
            });

        assert!(!out.output_wires[0]);
    }
}
