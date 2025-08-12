//! BN254 pairing helpers (off-circuit)
//!
//! Implements precomputation of G2 line coefficients for the ATE/Miller loop.
//! This operates on arkworks types and returns constants to be used by
//! on-circuit gadgets that evaluate the lines against G1 inputs.

/// Line coefficient triple used during Miller loop line evaluations.
/// Matches arkworks' internal representation order for BN254.
pub type EllCoeff = (ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2);

use ark_ec::bn::BnConfig;
use ark_ff::Field;
use circuit_component_macro::component;

use crate::{
    CircuitContext,
    gadgets::bn254::{fq::Fq, fq2::Fq2, fq6::Fq6, fq12::Fq12, g1::G1Projective},
};

/// Compute BN254 G2 line coefficients for the ATE loop given a constant `Q`.
///
/// This is an off-circuit helper intended to be used alongside circuit
/// gadgets that evaluate the lines against variable G1 points.
pub fn ell_coeffs(q: ark_bn254::G2Affine) -> Vec<EllCoeff> {
    // Rely on arkworks' precomputation to ensure shape and values match
    // the reference implementation, using the Pairing engine's associated type.
    use ark_ec::pairing::Pairing;
    type G2Prep = <ark_bn254::Bn254 as Pairing>::G2Prepared;
    let prepared: G2Prep = q.into();
    prepared.ell_coeffs
}

/// Evaluate a BN254 line (with constant G2 coefficients) at a variable G1 point and
/// multiply into `f` in Montgomery form.
///
/// Given coefficients `(c0, c1, c2)` for a single Miller step and a G1 point `p`,
/// this computes `f * (c0 * p.y + c1 * p.x * w^3 + c2 * w^4)` using the specialized
/// sparse Fq12 multiplication path with indices 0,3,4.
pub fn ell_eval_const<C: CircuitContext>(
    circuit: &mut C,
    f: &Fq12,
    coeffs: &EllCoeff,
    p: &G1Projective,
) -> Fq12 {
    // c0' = coeffs.0 * p.y (in Fq2) as wires
    let c0_fq2 = Fq2::mul_constant_by_fq_montgomery(circuit, &coeffs.0, &p.y);
    // c1' = coeffs.1 * p.x (in Fq2) as wires
    let c3_fq2 = Fq2::mul_constant_by_fq_montgomery(circuit, &coeffs.1, &p.x);
    // c2 is a constant (Fq2); for mul_by_constant_montgomery/add_constant paths
    // we pass it in Montgomery form to match other Montgomery-form wires.
    let c4_const = Fq2::as_montgomery(coeffs.2);

    Fq12::mul_by_034_constant4_montgomery(circuit, f, &c0_fq2, &c3_fq2, &c4_const)
}

fn new_fq12_constant_montgomery(v: ark_bn254::Fq12) -> Fq12 {
    // Convert to Montgomery form before creating constants
    let v_mont = Fq12::as_montgomery(v);
    let c0 = v_mont.c0;
    let c1 = v_mont.c1;
    let c0_0 = Fq2::from_components(
        Fq::new_constant(&c0.c0.c0).unwrap(),
        Fq::new_constant(&c0.c0.c1).unwrap(),
    );
    let c0_1 = Fq2::from_components(
        Fq::new_constant(&c0.c1.c0).unwrap(),
        Fq::new_constant(&c0.c1.c1).unwrap(),
    );
    let c0_2 = Fq2::from_components(
        Fq::new_constant(&c0.c2.c0).unwrap(),
        Fq::new_constant(&c0.c2.c1).unwrap(),
    );
    let w0 = Fq6::from_components(c0_0, c0_1, c0_2);

    let c1_0 = Fq2::from_components(
        Fq::new_constant(&c1.c0.c0).unwrap(),
        Fq::new_constant(&c1.c0.c1).unwrap(),
    );
    let c1_1 = Fq2::from_components(
        Fq::new_constant(&c1.c1.c0).unwrap(),
        Fq::new_constant(&c1.c1.c1).unwrap(),
    );
    let c1_2 = Fq2::from_components(
        Fq::new_constant(&c1.c2.c0).unwrap(),
        Fq::new_constant(&c1.c2.c1).unwrap(),
    );
    let w1 = Fq6::from_components(c1_0, c1_1, c1_2);

    Fq12::from_components(w0, w1)
}

/// Miller loop over BN254 with constant Q and variable G1 wires.
#[component(ignore = "q")]
pub fn miller_loop_const_q<C: CircuitContext>(
    circuit: &mut C,
    p: &G1Projective,
    q: &ark_bn254::G2Affine,
) -> Fq12 {
    let coeffs = ell_coeffs(*q);
    let mut coeff_iter = coeffs.iter();

    let mut f = new_fq12_constant_montgomery(ark_bn254::Fq12::ONE);

    for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
        if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
            f = Fq12::square_montgomery(circuit, &f);
        }

        let c = coeff_iter.next().expect("coeff present");
        f = ell_eval_const(circuit, &f, c, p);

        let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];
        if bit == 1 || bit == -1 {
            let c2 = coeff_iter.next().expect("coeff present");
            f = ell_eval_const(circuit, &f, c2, p);
        }
    }

    // Final two additions outside the loop
    let c_last = coeff_iter.next().expect("coeff present");
    f = ell_eval_const(circuit, &f, c_last, p);
    let c_last2 = coeff_iter.next().expect("coeff present");
    f = ell_eval_const(circuit, &f, c_last2, p);

    f
}

/// Multi Miller loop with constant Qs and variable G1 wires.
#[component(ignore = "qs")]
pub fn multi_miller_loop_const_q<C: CircuitContext>(
    circuit: &mut C,
    ps: &[G1Projective],
    qs: &[ark_bn254::G2Affine],
) -> Fq12 {
    assert_eq!(ps.len(), qs.len());
    let n = ps.len();
    if n == 0 {
        return new_fq12_constant_montgomery(Fq12::as_montgomery(ark_bn254::Fq12::ONE));
    }

    // Precompute coeffs per Q
    let qells: Vec<Vec<EllCoeff>> = qs.iter().copied().map(ell_coeffs).collect();
    // Transpose by step index
    let steps = qells[0].len();
    let mut per_step: Vec<Vec<&EllCoeff>> = Vec::with_capacity(steps);
    for i in 0..steps {
        let mut v = Vec::with_capacity(n);
        for qell in &qells {
            v.push(&qell[i]);
        }
        per_step.push(v);
    }

    let mut f = new_fq12_constant_montgomery(ark_bn254::Fq12::ONE);
    let mut per_step_iter = per_step.into_iter();

    for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
        if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
            f = Fq12::square_montgomery(circuit, &f);
        }

        let coeffs_now = per_step_iter.next().expect("coeffs present");
        for (c, p) in coeffs_now.into_iter().zip(ps.iter()) {
            f = ell_eval_const(circuit, &f, c, p);
        }

        let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];
        if bit == 1 || bit == -1 {
            let coeffs_now = per_step_iter.next().expect("coeffs present");
            for (c, p) in coeffs_now.into_iter().zip(ps.iter()) {
                f = ell_eval_const(circuit, &f, c, p);
            }
        }
    }

    // Final two steps
    for _ in 0..2 {
        let coeffs_now = per_step_iter.next().expect("coeffs present");
        for (c, p) in coeffs_now.into_iter().zip(ps.iter()) {
            f = ell_eval_const(circuit, &f, c, p);
        }
    }

    f
}

// Final exponentiation logic has moved to gadgets::bn254::final_exponentiation

#[cfg(test)]
mod tests {
    use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
    use ark_ff::{Field, PrimeField, UniformRand};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::{
        circuit::streaming::{
            CircuitBuilder, CircuitInput, CircuitOutput, EncodeInput, Execute, IntoWireList,
            modes::CircuitMode,
        },
        gadgets::{
            bigint::{BigUint as BigUintOutput, bits_from_biguint_with_len},
            bn254::{final_exponentiation, fp254impl::Fp254Impl},
        },
    };

    fn rnd_fr(rng: &mut impl Rng) -> ark_bn254::Fr {
        let mut prng = ChaCha20Rng::seed_from_u64(rng.r#gen());
        ark_bn254::Fr::rand(&mut prng)
    }

    fn random_g2_affine(rng: &mut impl Rng) -> ark_bn254::G2Affine {
        (ark_bn254::G2Projective::generator() * rnd_fr(rng)).into_affine()
    }

    #[test]
    fn test_ell_coeffs_matches_arkworks() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let q = random_g2_affine(&mut rng);

        let ours = ell_coeffs(q);
        let ark = {
            use ark_ec::pairing::Pairing;
            type G2Prep = <ark_bn254::Bn254 as Pairing>::G2Prepared;
            let prepared: G2Prep = q.into();
            prepared.ell_coeffs
        };

        assert_eq!(ours.len(), ark.len(), "coeff vector length mismatch");
        for (i, (a, b)) in ours.iter().zip(ark.iter()).enumerate() {
            assert_eq!(a.0, b.0, "c0 mismatch at idx {i}");
            assert_eq!(a.1, b.1, "c1 mismatch at idx {i}");
            assert_eq!(a.2, b.2, "c2 mismatch at idx {i}");
        }
    }

    // Helper to encode Fq6 into wires (Montgomery form expected)
    fn encode_fq6_to_wires(
        val: &ark_bn254::Fq6,
        wires: &crate::gadgets::bn254::fq6::Fq6,
        cache: &mut Execute,
    ) {
        use crate::gadgets::bn254::fq::Fq as FqWire;
        let c0_c0_bits = bits_from_biguint_with_len(
            &BigUintOutput::from(val.c0.c0.into_bigint()),
            FqWire::N_BITS,
        )
        .unwrap();
        let c0_c1_bits = bits_from_biguint_with_len(
            &BigUintOutput::from(val.c0.c1.into_bigint()),
            FqWire::N_BITS,
        )
        .unwrap();
        wires.0[0].0[0]
            .0
            .iter()
            .zip(c0_c0_bits)
            .for_each(|(w, b)| cache.feed_wire(*w, b));
        wires.0[0].0[1]
            .0
            .iter()
            .zip(c0_c1_bits)
            .for_each(|(w, b)| cache.feed_wire(*w, b));

        let c1_c0_bits = bits_from_biguint_with_len(
            &BigUintOutput::from(val.c1.c0.into_bigint()),
            FqWire::N_BITS,
        )
        .unwrap();
        let c1_c1_bits = bits_from_biguint_with_len(
            &BigUintOutput::from(val.c1.c1.into_bigint()),
            FqWire::N_BITS,
        )
        .unwrap();
        wires.0[1].0[0]
            .0
            .iter()
            .zip(c1_c0_bits)
            .for_each(|(w, b)| cache.feed_wire(*w, b));
        wires.0[1].0[1]
            .0
            .iter()
            .zip(c1_c1_bits)
            .for_each(|(w, b)| cache.feed_wire(*w, b));

        let c2_c0_bits = bits_from_biguint_with_len(
            &BigUintOutput::from(val.c2.c0.into_bigint()),
            FqWire::N_BITS,
        )
        .unwrap();
        let c2_c1_bits = bits_from_biguint_with_len(
            &BigUintOutput::from(val.c2.c1.into_bigint()),
            FqWire::N_BITS,
        )
        .unwrap();
        wires.0[2].0[0]
            .0
            .iter()
            .zip(c2_c0_bits)
            .for_each(|(w, b)| cache.feed_wire(*w, b));
        wires.0[2].0[1]
            .0
            .iter()
            .zip(c2_c1_bits)
            .for_each(|(w, b)| cache.feed_wire(*w, b));
    }

    #[test]
    fn test_final_exponentiation_matches_arkworks() {
        use ark_ec::pairing::Pairing;
        // Deterministic inputs
        let mut rng = ChaCha20Rng::seed_from_u64(12345);
        let p = (ark_bn254::G1Projective::generator() * rnd_fr(&mut rng)).into_affine();
        let q = random_g2_affine(&mut rng);

        // Miller loop off-circuit (arkworks)
        let f_ml = ark_bn254::Bn254::multi_miller_loop([p], [q]).0;
        let expected = ark_bn254::Bn254::pairing(p, q);
        let expected_m = Fq12::as_montgomery(expected.0);

        // Encode f_ml as input (Montgomery) and apply final exponentiation in-circuit
        struct FEInput {
            f: ark_bn254::Fq12,
        }
        struct FEWires {
            f: Fq12,
        }

        #[allow(clippy::upper_case_acronyms)]
        struct FEO {
            value: ark_bn254::Fq12,
        }
        impl CircuitInput for FEInput {
            type WireRepr = FEWires;
            fn allocate<C: CircuitContext>(&self, ctx: &mut C) -> Self::WireRepr {
                FEWires { f: Fq12::new(ctx) }
            }
            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<crate::WireId> {
                (&repr.f).into_wire_list()
            }
        }
        impl EncodeInput<Execute> for FEInput {
            fn encode(self, repr: &FEWires, cache: &mut Execute) {
                let f_m = Fq12::as_montgomery(self.f);
                encode_fq6_to_wires(&f_m.c0, &repr.f.0[0], cache);
                encode_fq6_to_wires(&f_m.c1, &repr.f.0[1], cache);
            }
        }
        impl CircuitOutput<Execute> for FEO {
            type WireRepr = Fq12;
            fn decode(wires: Self::WireRepr, cache: &Execute) -> Self {
                // Reuse local decoder helpers
                fn decode_fq6_from_wires(
                    wires: &crate::gadgets::bn254::fq6::Fq6,
                    cache: &Execute,
                ) -> ark_bn254::Fq6 {
                    let c0_c0 = <BigUintOutput as CircuitOutput<Execute>>::decode(
                        wires.0[0].0[0].0.clone(),
                        cache,
                    );
                    let c0_c1 = <BigUintOutput as CircuitOutput<Execute>>::decode(
                        wires.0[0].0[1].0.clone(),
                        cache,
                    );
                    let c1_c0 = <BigUintOutput as CircuitOutput<Execute>>::decode(
                        wires.0[1].0[0].0.clone(),
                        cache,
                    );
                    let c1_c1 = <BigUintOutput as CircuitOutput<Execute>>::decode(
                        wires.0[1].0[1].0.clone(),
                        cache,
                    );
                    let c2_c0 = <BigUintOutput as CircuitOutput<Execute>>::decode(
                        wires.0[2].0[0].0.clone(),
                        cache,
                    );
                    let c2_c1 = <BigUintOutput as CircuitOutput<Execute>>::decode(
                        wires.0[2].0[1].0.clone(),
                        cache,
                    );
                    let c0 =
                        ark_bn254::Fq2::new(ark_bn254::Fq::from(c0_c0), ark_bn254::Fq::from(c0_c1));
                    let c1 =
                        ark_bn254::Fq2::new(ark_bn254::Fq::from(c1_c0), ark_bn254::Fq::from(c1_c1));
                    let c2 =
                        ark_bn254::Fq2::new(ark_bn254::Fq::from(c2_c0), ark_bn254::Fq::from(c2_c1));
                    ark_bn254::Fq6::new(c0, c1, c2)
                }
                let c0 = decode_fq6_from_wires(&wires.0[0], cache);
                let c1 = decode_fq6_from_wires(&wires.0[1], cache);
                Self {
                    value: ark_bn254::Fq12::new(c0, c1),
                }
            }
        }

        let input = FEInput { f: f_ml };
        let result = CircuitBuilder::<Execute>::streaming_process::<_, _, FEO>(
            input,
            Execute::default(),
            |ctx, input| final_exponentiation(ctx, &input.f),
        );

        assert_eq!(result.output_wires.value, expected_m);
    }
    // Local decoder helpers for Fq12 output
    fn decode_fq6_from_wires(
        wires: &crate::gadgets::bn254::fq6::Fq6,
        cache: &Execute,
    ) -> ark_bn254::Fq6 {
        let c0_c0 =
            <BigUintOutput as CircuitOutput<Execute>>::decode(wires.0[0].0[0].0.clone(), cache);
        let c0_c1 =
            <BigUintOutput as CircuitOutput<Execute>>::decode(wires.0[0].0[1].0.clone(), cache);
        let c1_c0 =
            <BigUintOutput as CircuitOutput<Execute>>::decode(wires.0[1].0[0].0.clone(), cache);
        let c1_c1 =
            <BigUintOutput as CircuitOutput<Execute>>::decode(wires.0[1].0[1].0.clone(), cache);
        let c2_c0 =
            <BigUintOutput as CircuitOutput<Execute>>::decode(wires.0[2].0[0].0.clone(), cache);
        let c2_c1 =
            <BigUintOutput as CircuitOutput<Execute>>::decode(wires.0[2].0[1].0.clone(), cache);

        let c0 = ark_bn254::Fq2::new(ark_bn254::Fq::from(c0_c0), ark_bn254::Fq::from(c0_c1));
        let c1 = ark_bn254::Fq2::new(ark_bn254::Fq::from(c1_c0), ark_bn254::Fq::from(c1_c1));
        let c2 = ark_bn254::Fq2::new(ark_bn254::Fq::from(c2_c0), ark_bn254::Fq::from(c2_c1));
        ark_bn254::Fq6::new(c0, c1, c2)
    }

    struct Fq12Output {
        value: ark_bn254::Fq12,
    }
    impl CircuitOutput<Execute> for Fq12Output {
        type WireRepr = Fq12;
        fn decode(wires: Self::WireRepr, cache: &Execute) -> Self {
            let c0 = decode_fq6_from_wires(&wires.0[0], cache);
            let c1 = decode_fq6_from_wires(&wires.0[1], cache);
            Self {
                value: ark_bn254::Fq12::new(c0, c1),
            }
        }
    }

    struct EllEvalInput {
        f: ark_bn254::Fq12,
        p: ark_bn254::G1Projective,
    }
    struct EllEvalWires {
        f: Fq12,
        p: G1Projective,
    }
    impl CircuitInput for EllEvalInput {
        type WireRepr = EllEvalWires;
        fn allocate<C: CircuitContext>(&self, ctx: &mut C) -> Self::WireRepr {
            EllEvalWires {
                f: Fq12::new(ctx),
                p: G1Projective::new(ctx),
            }
        }
        fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<crate::WireId> {
            let mut ids = (&repr.f).into_wire_list();
            ids.extend((&repr.p).into_wire_list());
            ids
        }
    }
    impl EncodeInput<Execute> for EllEvalInput {
        fn encode(self, repr: &EllEvalWires, cache: &mut Execute) {
            // Encode f (Fq12) in Montgomery form
            let f_m = Fq12::as_montgomery(self.f);
            encode_fq6_to_wires(&f_m.c0, &repr.f.0[0], cache);
            encode_fq6_to_wires(&f_m.c1, &repr.f.0[1], cache);

            // Encode p (G1Projective) in Montgomery form
            let p_m = G1Projective::as_montgomery(self.p);
            let bits_x =
                bits_from_biguint_with_len(&BigUintOutput::from(p_m.x.into_bigint()), Fq::N_BITS)
                    .unwrap();
            let bits_y =
                bits_from_biguint_with_len(&BigUintOutput::from(p_m.y.into_bigint()), Fq::N_BITS)
                    .unwrap();
            let bits_z =
                bits_from_biguint_with_len(&BigUintOutput::from(p_m.z.into_bigint()), Fq::N_BITS)
                    .unwrap();
            repr.p
                .x
                .0
                .iter()
                .zip(bits_x)
                .for_each(|(w, b)| cache.feed_wire(*w, b));
            repr.p
                .y
                .0
                .iter()
                .zip(bits_y)
                .for_each(|(w, b)| cache.feed_wire(*w, b));
            repr.p
                .z
                .0
                .iter()
                .zip(bits_z)
                .for_each(|(w, b)| cache.feed_wire(*w, b));
        }
    }

    #[test]
    fn test_ell_eval_const_matches_ark_step() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let q = random_g2_affine(&mut rng);
        let coeffs = ell_coeffs(q);
        // choose first step coeffs
        let coeff = coeffs[0];

        // random G1 point and initial f=1
        let p = (ark_bn254::G1Projective::generator() * rnd_fr(&mut rng))
            .into_affine()
            .into_group();

        // Expected off-circuit using arkworks API
        let mut exp_c0 = coeff.0;
        let mut exp_c1 = coeff.1;
        let exp_c2 = coeff.2;
        let p_affine = p.into_affine();
        exp_c0.mul_assign_by_fp(&p_affine.y);
        exp_c1.mul_assign_by_fp(&p_affine.x);
        let mut expected = ark_bn254::Fq12::ONE;
        expected.mul_by_034(&exp_c0, &exp_c1, &exp_c2);
        let expected_m = Fq12::as_montgomery(expected);

        // Circuit computation
        let input = EllEvalInput {
            f: ark_bn254::Fq12::ONE,
            p,
        };
        let result = CircuitBuilder::<Execute>::streaming_process::<_, _, Fq12Output>(
            input,
            Execute::default(),
            |ctx, input| ell_eval_const(ctx, &input.f, &coeff, &input.p),
        );

        assert_eq!(result.output_wires.value, expected_m);
    }
}
