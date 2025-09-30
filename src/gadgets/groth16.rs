//! Groth16 verifier gadget for BN254 using the streaming-circuit API.
//!
//! Implements the standard Groth16 verification equation with gadgets:
//! e(A, B) * e(C, -delta) * e(msm, -gamma) == e(alpha, beta)
//! where `msm = vk.gamma_abc_g1[0] + sum_i(public[i] * vk.gamma_abc_g1[i+1])`.

use ark_bn254::Bn254;
use ark_ec::{AffineRepr, CurveGroup, models::short_weierstrass::SWCurveConfig, pairing::Pairing};
use ark_ff::{AdditiveGroup, Field};
use ark_groth16::VerifyingKey;
use circuit_component_macro::component;

use crate::{
    CircuitContext, Fq2Wire, WireId,
    circuit::{CircuitInput, CircuitMode, EncodeInput, WiresObject},
    gadgets::{
        bigint,
        bn254::{
            G2Projective, final_exponentiation::final_exponentiation_montgomery, fq::Fq,
            fq12::Fq12, fr::Fr, g1::G1Projective,
            pairing::multi_miller_loop_groth16_evaluate_montgomery_fast,
        },
    },
};

#[component]
pub fn projective_to_affine_montgomery<C: CircuitContext>(
    circuit: &mut C,
    p: &G1Projective,
) -> G1Projective {
    let x = &p.x;
    let y = &p.y;
    let z = &p.z;

    let z_inverse = Fq::inverse_montgomery(circuit, z);
    let z_inverse_square = Fq::square_montgomery(circuit, &z_inverse);
    let z_inverse_cube = Fq::mul_montgomery(circuit, &z_inverse, &z_inverse_square);
    let new_x = Fq::mul_montgomery(circuit, x, &z_inverse_square);
    let new_y = Fq::mul_montgomery(circuit, y, &z_inverse_cube);

    G1Projective {
        x: new_x,
        y: new_y,
        // Set z = 1 in Montgomery form to stay in-domain
        z: Fq::new_constant(&Fq::as_montgomery(ark_bn254::Fq::ONE)).unwrap(),
    }
}

/// Verify Groth16 proof for BN254 using streaming gadgets.
///
/// - `public`: public inputs as Fr wires (bit-wires, Montgomery ops inside gadgets).
/// - `proof_a`, `proof_c`: proof G1 points as wires (Montgomery).
/// - `proof_b`: proof G2 point as host constant (affine).
/// - `vk`: verifying key with constant elements (host-provided arkworks types).
///
/// Returns a boolean wire that is 1 iff the proof verifies.
pub fn groth16_verify<C: CircuitContext>(
    circuit: &mut C,
    input: &Groth16VerifyInputWires,
) -> WireId {
    let Groth16VerifyInputWires {
        public,
        a,
        b,
        c,
        vk,
    } = input;

    // Standard verification with public inputs
    // MSM: sum_i public[i] * gamma_abc_g1[i+1]
    let bases: Vec<ark_bn254::G1Projective> = vk
        .gamma_abc_g1
        .iter()
        .skip(1)
        .take(public.len())
        .map(|a| a.into_group())
        .collect();
    let msm_temp =
        G1Projective::msm_with_constant_bases_montgomery::<10, _>(circuit, public, &bases);

    // Add the constant term gamma_abc_g1[0] in Montgomery form
    let gamma0_m = G1Projective::as_montgomery(vk.gamma_abc_g1[0].into_group());
    let msm =
        G1Projective::add_montgomery(circuit, &msm_temp, &G1Projective::new_constant(&gamma0_m));

    let msm_affine = projective_to_affine_montgomery(circuit, &msm);

    let f = multi_miller_loop_groth16_evaluate_montgomery_fast(
        circuit,
        &msm_affine,  // p1
        c,            // p2
        a,            // p3
        -vk.gamma_g2, // q1
        -vk.delta_g2, // q2
        b,            // q3
    );

    let alpha_beta = ark_bn254::Bn254::final_exponentiation(ark_bn254::Bn254::multi_miller_loop(
        [vk.alpha_g1.into_group()],
        [-vk.beta_g2],
    ))
    .unwrap()
    .0
    .inverse()
    .unwrap();

    let f = final_exponentiation_montgomery(circuit, &f);

    Fq12::equal_constant(circuit, &f, &Fq12::as_montgomery(alpha_beta))
}

/// Decompress a compressed G1 point (x, sign bit) into projective wires with z = 1 (Montgomery domain).
/// - `x_m`: x-coordinate in Montgomery form wires
/// - `y_flag`: boolean wire selecting the correct sqrt branch for y
#[component]
pub fn decompress_g1_from_compressed<C: CircuitContext>(
    circuit: &mut C,
    compressed: &CompressedG1Wires,
) -> G1Projective {
    let CompressedG1Wires { x_m, y_flag } = compressed.clone();

    // rhs = x^3 + b (Montgomery domain)
    let x2 = Fq::square_montgomery(circuit, &x_m);
    let x3 = Fq::mul_montgomery(circuit, &x2, &x_m);
    let b_m = Fq::as_montgomery(ark_bn254::g1::Config::COEFF_B);
    let rhs = Fq::add_constant(circuit, &x3, &b_m);

    // sy = sqrt(rhs) in Montgomery domain
    let sy = Fq::sqrt_montgomery(circuit, &rhs);
    let sy_neg = Fq::neg(circuit, &sy);
    let y_bits = bigint::select(circuit, &sy.0, &sy_neg.0, y_flag);
    let y = Fq(y_bits);

    // z = 1 in Montgomery
    let one_m = Fq::as_montgomery(ark_bn254::Fq::ONE);
    let z = Fq::new_constant(&one_m).expect("const one mont");

    G1Projective {
        x: x_m.clone(),
        y,
        z,
    }
}

#[component]
pub fn decompress_g2_from_compressed<C: CircuitContext>(
    circuit: &mut C,
    compressed: &CompressedG2Wires,
) -> G2Projective {
    let CompressedG2Wires { p: x, y_flag } = compressed;

    let x2 = Fq2Wire::square_montgomery(circuit, x);

    let x3 = Fq2Wire::mul_montgomery(circuit, &x2, x);

    let y2 = Fq2Wire::add_constant(
        circuit,
        &x3,
        &Fq2Wire::as_montgomery(ark_bn254::g2::Config::COEFF_B),
    );

    let y = Fq2Wire::sqrt_general_montgomery(circuit, &y2);

    let neg_y = Fq2Wire::neg(circuit, y.clone());

    let final_y_0 = bigint::select(circuit, y.c0(), neg_y.c0(), *y_flag);
    let final_y_1 = bigint::select(circuit, y.c1(), neg_y.c1(), *y_flag);

    // z = 1 in Montgomery
    let one_m = Fq::as_montgomery(ark_bn254::Fq::ONE);
    let zero_m = Fq::as_montgomery(ark_bn254::Fq::ZERO);

    G2Projective {
        x: x.clone(),
        y: Fq2Wire([Fq(final_y_0), Fq(final_y_1)]),
        // In Fq2, ONE is (c0=1, c1=0). Use Montgomery representation.
        z: Fq2Wire([
            Fq::new_constant(&one_m).unwrap(),
            Fq::new_constant(&zero_m).unwrap(),
        ]),
    }
}

#[derive(Clone, Debug)]
pub struct CompressedG1Wires {
    pub x_m: Fq,
    pub y_flag: WireId,
}

impl CompressedG1Wires {
    pub fn new(mut issue: impl FnMut() -> WireId) -> Self {
        Self {
            x_m: Fq::new(&mut issue),
            y_flag: issue(),
        }
    }
}

impl WiresObject for CompressedG1Wires {
    fn to_wires_vec(&self) -> Vec<WireId> {
        let Self { x_m: p, y_flag } = self;

        let mut v = p.to_wires_vec();
        v.push(*y_flag);
        v
    }

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        Self {
            x_m: self.x_m.clone_from(wire_gen),
            y_flag: self.y_flag.clone_from(wire_gen),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompressedG2Wires {
    pub p: Fq2Wire,
    pub y_flag: WireId,
}

impl CompressedG2Wires {
    pub fn new(mut issue: impl FnMut() -> WireId) -> Self {
        Self {
            p: Fq2Wire::new(&mut issue),
            y_flag: issue(),
        }
    }
}

impl WiresObject for CompressedG2Wires {
    fn to_wires_vec(&self) -> Vec<WireId> {
        let Self { p, y_flag } = self;

        let mut v = p.to_wires_vec();
        v.push(*y_flag);
        v
    }

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        Self {
            p: self.p.clone_from(wire_gen),
            y_flag: self.y_flag.clone_from(wire_gen),
        }
    }
}

/// Convenience wrapper: verify using compressed A and C (x, y_flag). B remains host-provided `G2Affine`.
/// Includes optimization for empty public inputs to avoid unnecessary MSM computation.
pub fn groth16_verify_compressed<C: CircuitContext>(
    circuit: &mut C,
    input: &Groth16VerifyCompressedInputWires,
) -> crate::WireId {
    let a = decompress_g1_from_compressed(circuit, &input.a);
    let b = decompress_g2_from_compressed(circuit, &input.b);
    let c = decompress_g1_from_compressed(circuit, &input.c);

    groth16_verify(
        circuit,
        &Groth16VerifyInputWires {
            public: input.public.clone(),
            a,
            b,
            c,
            vk: input.vk.clone(),
        },
    )
}

#[derive(Debug, Clone)]
pub struct Groth16VerifyInput {
    pub public: Vec<ark_bn254::Fr>,
    pub a: ark_bn254::G1Projective,
    pub b: ark_bn254::G2Projective,
    pub c: ark_bn254::G1Projective,
    pub vk: VerifyingKey<Bn254>,
}

#[derive(Debug)]
pub struct Groth16VerifyInputWires {
    pub public: Vec<Fr>,
    pub a: G1Projective,
    pub b: G2Projective,
    pub c: G1Projective,
    pub vk: VerifyingKey<Bn254>,
}

impl CircuitInput for Groth16VerifyInput {
    type WireRepr = Groth16VerifyInputWires;

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        Groth16VerifyInputWires {
            public: self.public.iter().map(|_| Fr::new(&mut issue)).collect(),
            a: G1Projective::new(&mut issue),
            b: G2Projective::new(&mut issue),
            c: G1Projective::new(issue),
            vk: self.vk.clone(),
        }
    }
    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<crate::WireId> {
        let mut ids = Vec::new();
        for s in &repr.public {
            ids.extend(s.to_wires_vec());
        }
        ids.extend(repr.a.to_wires_vec());
        ids.extend(repr.b.to_wires_vec());
        ids.extend(repr.c.to_wires_vec());
        ids
    }
}

impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for Groth16VerifyInput {
    fn encode(&self, repr: &Groth16VerifyInputWires, cache: &mut M) {
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
        let b_m = G2Projective::as_montgomery(self.b);
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

        let b_fn = G2Projective::get_wire_bits_fn(&repr.b, &b_m).unwrap();
        for &wire_id in repr
            .b
            .x
            .iter()
            .chain(repr.b.y.iter())
            .chain(repr.b.z.iter())
        {
            if let Some(bit) = b_fn(wire_id) {
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

impl Groth16VerifyInput {
    pub fn compress(self) -> Groth16VerifyCompressedInput {
        Groth16VerifyCompressedInput(self)
    }
}

pub struct Groth16VerifyCompressedInput(pub Groth16VerifyInput);

#[derive(Debug)]
pub struct Groth16VerifyCompressedInputWires {
    pub public: Vec<Fr>,
    pub a: CompressedG1Wires,
    pub b: CompressedG2Wires,
    pub c: CompressedG1Wires,
    pub vk: VerifyingKey<Bn254>,
}

impl WiresObject for Groth16VerifyCompressedInputWires {
    fn to_wires_vec(&self) -> Vec<WireId> {
        Groth16VerifyCompressedInput::collect_wire_ids(self)
    }

    fn clone_from(&self, mut issue: &mut impl FnMut() -> WireId) -> Self {
        Groth16VerifyCompressedInputWires {
            public: self.public.iter().map(|_| Fr::new(&mut issue)).collect(),
            a: CompressedG1Wires::new(&mut issue),
            b: CompressedG2Wires::new(&mut issue),
            c: CompressedG1Wires::new(&mut issue),
            vk: self.vk.clone(),
        }
    }
}

impl CircuitInput for Groth16VerifyCompressedInput {
    type WireRepr = Groth16VerifyCompressedInputWires;

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        Groth16VerifyCompressedInputWires {
            public: self.0.public.iter().map(|_| Fr::new(&mut issue)).collect(),
            a: CompressedG1Wires::new(&mut issue),
            b: CompressedG2Wires::new(&mut issue),
            c: CompressedG1Wires::new(&mut issue),
            vk: self.0.vk.clone(),
        }
    }
    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<crate::WireId> {
        let mut ids = Vec::new();
        for s in &repr.public {
            ids.extend(s.to_wires_vec());
        }
        ids.extend(repr.a.to_wires_vec());
        ids.extend(repr.b.to_wires_vec());
        ids.extend(repr.c.to_wires_vec());
        ids
    }
}

impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for Groth16VerifyCompressedInput {
    fn encode(&self, repr: &Groth16VerifyCompressedInputWires, cache: &mut M) {
        // Encode public scalars
        for (w, v) in repr.public.iter().zip(self.0.public.iter()) {
            let fr_fn = Fr::get_wire_bits_fn(w, v).unwrap();

            for &wire in w.iter() {
                if let Some(bit) = fr_fn(wire) {
                    cache.feed_wire(wire, bit);
                }
            }
        }

        // Compute compression from standard affine coords; feed Montgomery x + flag
        let a_aff_std = self.0.a.into_affine();
        let b_aff_std = self.0.b.into_affine();
        let c_aff_std = self.0.c.into_affine();

        let a_flag = (a_aff_std.y.square())
            .sqrt()
            .expect("y^2 must be QR")
            .eq(&a_aff_std.y);
        let b_flag = (b_aff_std.y.square())
            .sqrt()
            .expect("y^2 must be QR in Fq2")
            .eq(&b_aff_std.y);
        let c_flag = (c_aff_std.y.square())
            .sqrt()
            .expect("y^2 must be QR")
            .eq(&c_aff_std.y);

        let a_x_m = Fq::as_montgomery(a_aff_std.x);
        let b_x_m = Fq2Wire::as_montgomery(b_aff_std.x);
        let c_x_m = Fq::as_montgomery(c_aff_std.x);

        // Feed A.x (Montgomery) bits and flag
        let a_x_fn = Fq::get_wire_bits_fn(&repr.a.x_m, &a_x_m).unwrap();
        for &wire_id in repr.a.x_m.iter() {
            if let Some(bit) = a_x_fn(wire_id) {
                cache.feed_wire(wire_id, bit);
            }
        }
        cache.feed_wire(repr.a.y_flag, a_flag);

        // Feed B.x (Montgomery) bits and flag (Fq2 as c0||c1)
        let b_x_fn = Fq2Wire::get_wire_bits_fn(&repr.b.p, &b_x_m).unwrap();
        for &wire_id in repr.b.p.iter() {
            if let Some(bit) = b_x_fn(wire_id) {
                cache.feed_wire(wire_id, bit);
            }
        }
        cache.feed_wire(repr.b.y_flag, b_flag);

        // Feed C.x (Montgomery) bits and flag
        let c_x_fn = Fq::get_wire_bits_fn(&repr.c.x_m, &c_x_m).unwrap();
        for &wire_id in repr.c.x_m.iter() {
            if let Some(bit) = c_x_fn(wire_id) {
                cache.feed_wire(wire_id, bit);
            }
        }
        cache.feed_wire(repr.c.y_flag, c_flag);
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
    use test_log::test;

    use super::*;
    use crate::circuit::{CircuitBuilder, CircuitMode, EncodeInput, StreamingResult};

    // Helper to reduce duplication across bitflip tests for A, B, and C
    fn run_false_bitflip_test(seed: u64, mutate: impl FnOnce(&mut Groth16VerifyInput)) {
        let k = 6;
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let circuit = DummyCircuit::<ark_bn254::Fr> {
            a: Some(ark_bn254::Fr::rand(&mut rng)),
            b: Some(ark_bn254::Fr::rand(&mut rng)),
            num_variables: 10,
            num_constraints: 1 << k,
        };
        let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();
        let c_val = circuit.a.unwrap() * circuit.b.unwrap();
        let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        let mut inputs = Groth16VerifyInput {
            public: vec![c_val],
            a: proof.a.into_group(),
            b: proof.b.into_group(),
            c: proof.c.into_group(),
            vk,
        };

        // Apply caller-provided mutation to corrupt a component
        mutate(&mut inputs);

        let out: StreamingResult<_, _, bool> =
            CircuitBuilder::streaming_execute(inputs, 10_000, groth16_verify);

        assert!(!out.output_value);
    }

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

    // Circuit with no public inputs - only private witnesses
    #[derive(Copy, Clone)]
    struct DummyCircuitNoPublicInputs<F: ark_ff::PrimeField> {
        pub a: Option<F>,
        pub b: Option<F>,
        pub num_variables: usize,
        pub num_constraints: usize,
    }

    impl<F: ark_ff::PrimeField> ConstraintSynthesizer<F> for DummyCircuitNoPublicInputs<F> {
        fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
            let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
            let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
            let c = cs.new_witness_variable(|| {
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
        let inputs = Groth16VerifyInput {
            public: vec![c_val],
            a: proof.a.into_group(),
            b: proof.b.into_group(),
            c: proof.c.into_group(),
            vk,
        };

        let out: StreamingResult<_, _, bool> =
            CircuitBuilder::streaming_execute(inputs, 40_000, groth16_verify);

        assert!(out.output_value);
    }

    #[test]
    fn test_groth16_verify_false_bitflip_a() {
        run_false_bitflip_test(54321, |inputs| {
            inputs.a.x += ark_bn254::Fq::ONE;
        });
    }

    #[test]
    fn test_groth16_verify_false_bitflip_b() {
        run_false_bitflip_test(98765, |inputs| {
            // Flip one limb by adding ONE to c0 of x
            inputs.b.x.c0 += ark_bn254::Fq::ONE;
        });
    }

    #[test]
    fn test_groth16_verify_false_bitflip_c() {
        run_false_bitflip_test(19283, |inputs| {
            inputs.c.x += ark_bn254::Fq::ONE;
        });
    }

    #[test]
    fn test_groth16_verify_no_public_inputs_true() {
        // Test successful verification with empty public inputs
        let k = 6;
        let mut rng = ChaCha20Rng::seed_from_u64(99999);
        let circuit = DummyCircuitNoPublicInputs::<ark_bn254::Fr> {
            a: Some(ark_bn254::Fr::rand(&mut rng)),
            b: Some(ark_bn254::Fr::rand(&mut rng)),
            num_variables: 10,
            num_constraints: 1 << k,
        };

        let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();
        let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        let inputs = Groth16VerifyInput {
            public: vec![], // Empty public inputs
            a: proof.a.into_group(),
            b: proof.b.into_group(),
            c: proof.c.into_group(),
            vk,
        };

        let out: StreamingResult<_, _, bool> =
            CircuitBuilder::streaming_execute(inputs, 10_000, groth16_verify);

        assert!(
            out.output_value,
            "Valid proof with empty public inputs should verify"
        );
    }

    #[test]
    fn test_groth16_verify_no_public_inputs_false_bitflip_a() {
        // Test unsuccessful verification with empty public inputs - corrupt proof.a
        let k = 6;
        let mut rng = ChaCha20Rng::seed_from_u64(88888);
        let circuit = DummyCircuitNoPublicInputs::<ark_bn254::Fr> {
            a: Some(ark_bn254::Fr::rand(&mut rng)),
            b: Some(ark_bn254::Fr::rand(&mut rng)),
            num_variables: 10,
            num_constraints: 1 << k,
        };

        let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();
        let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        let mut inputs = Groth16VerifyInput {
            public: vec![], // Empty public inputs
            a: proof.a.into_group(),
            b: proof.b.into_group(),
            c: proof.c.into_group(),
            vk,
        };

        // Corrupt proof.a by using a different random point
        inputs.a = ark_bn254::G1Projective::rand(&mut rng);

        let out: StreamingResult<_, _, bool> =
            CircuitBuilder::streaming_execute(inputs, 10_000, groth16_verify);

        assert!(
            !out.output_value,
            "Corrupted proof with empty public inputs should not verify"
        );
    }

    #[test]
    fn test_groth16_verify_no_public_inputs_false_bitflip_b() {
        // Test unsuccessful verification with empty public inputs - corrupt proof.b
        let k = 6;
        let mut rng = ChaCha20Rng::seed_from_u64(77777);
        let circuit = DummyCircuitNoPublicInputs::<ark_bn254::Fr> {
            a: Some(ark_bn254::Fr::rand(&mut rng)),
            b: Some(ark_bn254::Fr::rand(&mut rng)),
            num_variables: 10,
            num_constraints: 1 << k,
        };

        let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();
        let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        let mut inputs = Groth16VerifyInput {
            public: vec![], // Empty public inputs
            a: proof.a.into_group(),
            b: proof.b.into_group(),
            c: proof.c.into_group(),
            vk,
        };

        // Corrupt proof.b by using a different random point
        inputs.b = ark_bn254::G2Projective::rand(&mut rng);

        let out: StreamingResult<_, _, bool> =
            CircuitBuilder::streaming_execute(inputs, 10_000, groth16_verify);

        assert!(
            !out.output_value,
            "Corrupted proof with empty public inputs should not verify"
        );
    }

    #[test]
    fn test_groth16_verify_no_public_inputs_false_bitflip_c() {
        // Test unsuccessful verification with empty public inputs - corrupt proof.c
        let k = 6;
        let mut rng = ChaCha20Rng::seed_from_u64(66666);
        let circuit = DummyCircuitNoPublicInputs::<ark_bn254::Fr> {
            a: Some(ark_bn254::Fr::rand(&mut rng)),
            b: Some(ark_bn254::Fr::rand(&mut rng)),
            num_variables: 10,
            num_constraints: 1 << k,
        };

        let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();
        let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        let mut inputs = Groth16VerifyInput {
            public: vec![], // Empty public inputs
            a: proof.a.into_group(),
            b: proof.b.into_group(),
            c: proof.c.into_group(),
            vk,
        };

        // Corrupt proof.c by using a different random point
        inputs.c = ark_bn254::G1Projective::rand(&mut rng);

        let out: StreamingResult<_, _, bool> =
            CircuitBuilder::streaming_execute(inputs, 10_000, groth16_verify);

        assert!(
            !out.output_value,
            "Corrupted proof with empty public inputs should not verify"
        );
    }

    #[test]
    fn test_groth16_verify_false_random() {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

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
        let inputs = Groth16VerifyInput {
            public: vec![ark_bn254::Fr::rand(&mut rng)],
            a: (ark_bn254::G1Projective::generator() * ark_bn254::Fr::rand(&mut rng)),
            b: (ark_bn254::G2Projective::generator() * ark_bn254::Fr::rand(&mut rng)),
            c: (ark_bn254::G1Projective::generator() * ark_bn254::Fr::rand(&mut rng)),
            vk,
        };

        let out: crate::circuit::StreamingResult<_, _, bool> =
            CircuitBuilder::streaming_execute(inputs, 10_000, groth16_verify);

        assert!(!out.output_value);
    }

    // Minimal harnesses that allocate compressed wires and feed them directly
    struct OnlyCompressedG1Input(ark_bn254::G1Affine);
    impl crate::circuit::CircuitInput for OnlyCompressedG1Input {
        type WireRepr = CompressedG1Wires;
        fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
            CompressedG1Wires::new(&mut issue)
        }
        fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
            repr.to_wires_vec()
        }
    }
    impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for OnlyCompressedG1Input {
        fn encode(&self, repr: &CompressedG1Wires, cache: &mut M) {
            let p = self.0;
            let x_m = Fq::as_montgomery(p.x);
            let s = (p.y.square()).sqrt().expect("y^2 must be QR");
            let y_flag = s == p.y;

            let x_fn = Fq::get_wire_bits_fn(&repr.x_m, &x_m).unwrap();
            for &w in repr.x_m.iter() {
                if let Some(bit) = x_fn(w) {
                    cache.feed_wire(w, bit);
                }
            }
            cache.feed_wire(repr.y_flag, y_flag);
        }
    }

    struct OnlyCompressedG2Input(ark_bn254::G2Affine);
    impl crate::circuit::CircuitInput for OnlyCompressedG2Input {
        type WireRepr = CompressedG2Wires;
        fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
            CompressedG2Wires::new(&mut issue)
        }
        fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
            repr.to_wires_vec()
        }
    }
    impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for OnlyCompressedG2Input {
        fn encode(&self, repr: &CompressedG2Wires, cache: &mut M) {
            let p = self.0;
            let x_m = Fq2Wire::as_montgomery(p.x);
            // Simple off-circuit compression flag: sqrt(y^2) == y
            let s = (p.y.square()).sqrt().expect("y^2 must be QR in Fq2");
            let y_flag = s == p.y;

            let x_fn = Fq2Wire::get_wire_bits_fn(&repr.p, &x_m).unwrap();
            for &w in repr.p.iter() {
                if let Some(bit) = x_fn(w) {
                    cache.feed_wire(w, bit);
                }
            }
            cache.feed_wire(repr.y_flag, y_flag);
        }
    }

    #[test]
    fn test_g1_compress_decompress_matches() {
        let mut rng = ChaCha20Rng::seed_from_u64(111);
        let r = ark_bn254::Fr::rand(&mut rng);
        let p = (ark_bn254::G1Projective::generator() * r).into_affine();

        let input = OnlyCompressedG1Input(p);

        let out: crate::circuit::StreamingResult<_, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(input, 10_000, |ctx, wires| {
                let dec = decompress_g1_from_compressed(ctx, wires);

                let exp = G1Projective::as_montgomery(p.into_group());
                let x_ok = Fq::equal_constant(ctx, &dec.x, &exp.x);
                let z_ok = Fq::equal_constant(ctx, &dec.z, &exp.z);
                // Compare y up to sign by checking y^2 equality
                let y_sq = Fq::square_montgomery(ctx, &dec.y);
                let exp_y_std = Fq::from_montgomery(exp.y);
                let exp_y_sq_m = Fq::as_montgomery(exp_y_std.square());
                let y_ok = Fq::equal_constant(ctx, &y_sq, &exp_y_sq_m);
                vec![x_ok, y_ok, z_ok]
            });

        assert!(out.output_value.iter().all(|&b| b));
    }

    #[test]
    fn test_g2_compress_decompress_matches() {
        let mut rng = ChaCha20Rng::seed_from_u64(222);
        let r = ark_bn254::Fr::rand(&mut rng);
        let p = (ark_bn254::G2Projective::generator() * r).into_affine();

        let input = OnlyCompressedG2Input(p);

        let out: crate::circuit::StreamingResult<_, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(input, 20_000, |ctx, wires| {
                let dec = decompress_g2_from_compressed(ctx, wires);

                let exp = G2Projective::as_montgomery(p.into_group());
                let x_ok = Fq2Wire::equal_constant(ctx, &dec.x, &exp.x);
                let z_ok = Fq2Wire::equal_constant(ctx, &dec.z, &exp.z);
                // Compare y up to sign by checking y^2 equality
                let y_sq = Fq2Wire::square_montgomery(ctx, &dec.y);
                let exp_y_std = Fq2Wire::from_montgomery(exp.y);
                let exp_y_sq_m = Fq2Wire::as_montgomery(exp_y_std.square());
                let y_ok = Fq2Wire::equal_constant(ctx, &y_sq, &exp_y_sq_m);
                vec![x_ok, y_ok, z_ok]
            });

        assert!(out.output_value.iter().all(|&b| b));
    }

    #[test]
    fn test_groth16_compressed_decompress_matches_proof_points() {
        let k = 4; // keep it small
        let mut rng = ChaCha20Rng::seed_from_u64(33333);
        let circuit = DummyCircuit::<ark_bn254::Fr> {
            a: Some(ark_bn254::Fr::rand(&mut rng)),
            b: Some(ark_bn254::Fr::rand(&mut rng)),
            num_variables: 8,
            num_constraints: 1 << k,
        };
        let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();
        let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        let inputs = Groth16VerifyCompressedInput(Groth16VerifyInput {
            public: vec![ark_bn254::Fr::from(0u64)], // unused here
            a: proof.a.into_group(),
            b: proof.b.into_group(),
            c: proof.c.into_group(),
            vk,
        });

        let out: crate::circuit::StreamingResult<_, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 80_000, |ctx, wires| {
                let a_dec = decompress_g1_from_compressed(ctx, &wires.a);
                let b_dec = decompress_g2_from_compressed(ctx, &wires.b);
                let c_dec = decompress_g1_from_compressed(ctx, &wires.c);

                let a_exp = G1Projective::as_montgomery(proof.a.into_group());
                let b_exp = G2Projective::as_montgomery(proof.b.into_group());
                let c_exp = G1Projective::as_montgomery(proof.c.into_group());

                let a_x_ok = Fq::equal_constant(ctx, &a_dec.x, &a_exp.x);
                let a_y_ok = Fq::equal_constant(ctx, &a_dec.y, &a_exp.y);
                let a_z_ok = Fq::equal_constant(ctx, &a_dec.z, &a_exp.z);

                let b_x_ok = Fq2Wire::equal_constant(ctx, &b_dec.x, &b_exp.x);
                let b_y_ok = Fq2Wire::equal_constant(ctx, &b_dec.y, &b_exp.y);
                let b_z_ok = Fq2Wire::equal_constant(ctx, &b_dec.z, &b_exp.z);

                let c_x_ok = Fq::equal_constant(ctx, &c_dec.x, &c_exp.x);
                let c_y_ok = Fq::equal_constant(ctx, &c_dec.y, &c_exp.y);
                let c_z_ok = Fq::equal_constant(ctx, &c_dec.z, &c_exp.z);

                vec![
                    a_x_ok, a_y_ok, a_z_ok, b_x_ok, b_y_ok, b_z_ok, c_x_ok, c_y_ok, c_z_ok,
                ]
            });

        assert!(out.output_value.iter().all(|&b| b));
    }

    // Full end-to-end compressed Groth16 verification. This is heavy because it
    // runs Miller loop + final exponentiation in-circuit. Kept for completeness
    // but ignored by default; run explicitly when needed.
    #[test]
    fn test_groth16_verify_compressed_true_small() {
        let k = 4; // circuit size; pairing cost dominates anyway
        let mut rng = ChaCha20Rng::seed_from_u64(33333);
        let circuit = DummyCircuit::<ark_bn254::Fr> {
            a: Some(ark_bn254::Fr::rand(&mut rng)),
            b: Some(ark_bn254::Fr::rand(&mut rng)),
            num_variables: 8,
            num_constraints: 1 << k,
        };
        let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();
        let c_val = circuit.a.unwrap() * circuit.b.unwrap();
        let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        let inputs = Groth16VerifyInput {
            public: vec![c_val],
            a: proof.a.into_group(),
            b: proof.b.into_group(),
            c: proof.c.into_group(),
            vk,
        }
        .compress();

        let out: crate::circuit::StreamingResult<_, _, bool> =
            CircuitBuilder::streaming_execute(inputs, 80_000, groth16_verify_compressed);

        assert!(out.output_value);
    }

    // Unified small verifier runner to avoid duplication across flows and bitflips
    #[derive(Copy, Clone)]
    enum VerifyFlow {
        Uncompressed,
        Compressed,
    }

    fn run_small_verify(
        flow: VerifyFlow,
        seed: u64,
        mutate: impl FnOnce(&mut Groth16VerifyInput),
    ) -> bool {
        let k = 4; // small circuit to keep test fast
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let circuit = DummyCircuit::<ark_bn254::Fr> {
            a: Some(ark_bn254::Fr::rand(&mut rng)),
            b: Some(ark_bn254::Fr::rand(&mut rng)),
            num_variables: 8,
            num_constraints: 1 << k,
        };
        let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();
        let c_val = circuit.a.unwrap() * circuit.b.unwrap();
        let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        let mut inputs = Groth16VerifyInput {
            public: vec![c_val],
            a: proof.a.into_group(),
            b: proof.b.into_group(),
            c: proof.c.into_group(),
            vk,
        };
        mutate(&mut inputs);

        match flow {
            VerifyFlow::Uncompressed => {
                let out: StreamingResult<_, _, bool> =
                    CircuitBuilder::streaming_execute(inputs, 40_000, groth16_verify);

                out.output_value
            }
            VerifyFlow::Compressed => {
                let out: StreamingResult<_, _, bool> = CircuitBuilder::streaming_execute(
                    inputs.compress(),
                    80_000,
                    groth16_verify_compressed,
                );

                out.output_value
            }
        }
    }

    // Unified small verifier tests across flows
    #[test]
    fn test_small_verify_true_uncompressed() {
        assert!(run_small_verify(VerifyFlow::Uncompressed, 10101, |_| {}));
    }
    #[test]
    fn test_small_verify_true_compressed() {
        assert!(run_small_verify(VerifyFlow::Compressed, 20202, |_| {}));
    }
    #[test]
    fn test_small_verify_false_bitflip_a_uncompressed() {
        assert!(!run_small_verify(
            VerifyFlow::Uncompressed,
            30303,
            |inputs| {
                inputs.a.x += ark_bn254::Fq::ONE;
            }
        ));
    }
    #[test]
    fn test_small_verify_false_bitflip_a_compressed() {
        assert!(!run_small_verify(VerifyFlow::Compressed, 40404, |inputs| {
            inputs.a.x += ark_bn254::Fq::ONE;
        }));
    }
    #[test]
    fn test_small_verify_false_bitflip_b_uncompressed() {
        assert!(!run_small_verify(
            VerifyFlow::Uncompressed,
            50505,
            |inputs| {
                inputs.b.x.c0 += ark_bn254::Fq::ONE;
            }
        ));
    }
    #[test]
    fn test_small_verify_false_bitflip_b_compressed() {
        assert!(!run_small_verify(VerifyFlow::Compressed, 60606, |inputs| {
            inputs.b.x.c0 += ark_bn254::Fq::ONE;
        }));
    }
    #[test]
    fn test_small_verify_false_bitflip_c_uncompressed() {
        assert!(!run_small_verify(
            VerifyFlow::Uncompressed,
            70707,
            |inputs| {
                inputs.c.x += ark_bn254::Fq::ONE;
            }
        ));
    }
    #[test]
    fn test_small_verify_false_bitflip_c_compressed() {
        assert!(!run_small_verify(VerifyFlow::Compressed, 80808, |inputs| {
            inputs.c.x += ark_bn254::Fq::ONE;
        }));
    }
}
