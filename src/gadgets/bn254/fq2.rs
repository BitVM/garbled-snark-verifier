use ark_ff::{Field, Fp2Config, PrimeField, UniformRand};
use num_traits::Zero;
use rand::{rng, Rng};

use crate::{
    gadgets::{
        bigint::{self, select, BigIntWires},
        bn254::{fp254impl::Fp254Impl, fq::Fq},
    },
    Circuit, WireId,
};

pub type Pair<T> = (T, T);

pub struct Fq2;

impl Fq2 {
    pub const N_BITS: usize = 2 * Fq::N_BITS;

    pub fn as_montgomery(a: ark_bn254::Fq2) -> ark_bn254::Fq2 {
        ark_bn254::Fq2::new(Fq::as_montgomery(a.c0), Fq::as_montgomery(a.c1))
    }

    pub fn from_montgomery(a: ark_bn254::Fq2) -> ark_bn254::Fq2 {
        ark_bn254::Fq2::new(Fq::from_montgomery(a.c0), Fq::from_montgomery(a.c1))
    }

    pub fn to_bits(u: ark_bn254::Fq2) -> Pair<Vec<bool>> {
        (Fq::to_bits(u.c0), Fq::to_bits(u.c1))
    }

    pub fn add(
        circuit: &mut Circuit,
        a: Pair<BigIntWires>,
        b: Pair<BigIntWires>,
    ) -> Pair<BigIntWires> {
        assert_eq!(a.0.len(), Self::N_BITS / 2);
        assert_eq!(b.0.len(), Self::N_BITS / 2);

        let c0 = Fq::add(circuit, &a.0, &b.0);
        let c1 = Fq::add(circuit, &a.1, &b.1);

        (c0, c1)
    }

    pub fn add_constant(
        circuit: &mut Circuit,
        a: &Pair<BigIntWires>,
        b: &ark_bn254::Fq2,
    ) -> Pair<BigIntWires> {
        assert_eq!(a.0.len(), Self::N_BITS / 2);
        assert_eq!(a.1.len(), Self::N_BITS / 2);

        (
            Fq::add_constant(circuit, &a.0, &b.c0),
            Fq::add_constant(circuit, &a.1, &b.c1),
        )
    }

    pub fn random() -> ark_bn254::Fq2 {
        loop {
            let c0_bytes: [u8; 32] = rng().random();
            let c1_bytes: [u8; 32] = rng().random();

            if let (Some(c0), Some(c1)) = (
                ark_bn254::Fq::from_random_bytes(&c0_bytes),
                ark_bn254::Fq::from_random_bytes(&c1_bytes),
            ) {
                return ark_bn254::Fq2::new(c0, c1);
            }
        }
    }

    pub fn from_bits(bits: Pair<Vec<bool>>) -> ark_bn254::Fq2 {
        ark_bn254::Fq2::new(Fq::from_bits(bits.0), Fq::from_bits(bits.1))
    }

    pub fn new_bn(circuit: &mut Circuit, is_input: bool, is_output: bool) -> Pair<BigIntWires> {
        (
            BigIntWires::new(circuit, Fq::N_BITS, is_input, is_output),
            BigIntWires::new(circuit, Fq::N_BITS, is_input, is_output),
        )
    }

    pub fn wires_set(_u: ark_bn254::Fq2) -> Pair<Vec<WireId>> {
        // This is a stub - in the old API, this would create wires with values
        // In the new API, we use get_wire_bits_fn instead
        todo!("Use new_bn and get_wire_bits_fn instead")
    }

    pub fn wires_set_montgomery(u: ark_bn254::Fq2) -> Pair<Vec<WireId>> {
        Self::wires_set(Self::as_montgomery(u))
    }

    pub fn from_wires(_wires: Pair<Vec<WireId>>) -> ark_bn254::Fq2 {
        // This is a stub - in the old API, this would read wire values
        // In the new API, wire values are handled differently
        todo!("Use proper wire value extraction")
    }

    pub fn from_montgomery_wires(wires: Pair<Vec<WireId>>) -> ark_bn254::Fq2 {
        Self::from_montgomery(Self::from_wires(wires))
    }

    pub fn get_wire_bits_fn(
        wires: &Pair<BigIntWires>,
        value: &ark_bn254::Fq2,
    ) -> Result<impl Fn(WireId) -> Option<bool> + use<>, crate::gadgets::bigint::Error> {
        let (_c0_bits, _c1_bits) = Self::to_bits(*value);

        let c0_fn = wires
            .0
            .get_wire_bits_fn(&num_bigint::BigUint::from(value.c0.into_bigint()))?;
        let c1_fn = wires
            .1
            .get_wire_bits_fn(&num_bigint::BigUint::from(value.c1.into_bigint()))?;

        Ok(move |wire_id| c0_fn(wire_id).or_else(|| c1_fn(wire_id)))
    }

    pub fn to_bitmask(wires: &Pair<BigIntWires>, get_val: impl Fn(WireId) -> bool) -> String {
        let c0_mask = wires.0.to_bitmask(&get_val);
        let c1_mask = wires.1.to_bitmask(&get_val);
        format!("c0: {c0_mask}, c1: {c1_mask}")
    }

    pub fn neg(circuit: &mut Circuit, a: Pair<BigIntWires>) -> Pair<BigIntWires> {
        assert_eq!(a.0.len(), Self::N_BITS / 2);
        assert_eq!(a.1.len(), Self::N_BITS / 2);

        (Fq::neg(circuit, &a.0), Fq::neg(circuit, &a.1))
    }

    pub fn sub(
        circuit: &mut Circuit,
        a: &Pair<BigIntWires>,
        b: &Pair<BigIntWires>,
    ) -> Pair<BigIntWires> {
        assert_eq!(a.0.len(), Self::N_BITS / 2);
        assert_eq!(a.1.len(), Self::N_BITS / 2);
        assert_eq!(b.0.len(), Self::N_BITS / 2);
        assert_eq!(b.1.len(), Self::N_BITS / 2);

        let c0 = Fq::sub(circuit, &a.0, &b.0);
        let c1 = Fq::sub(circuit, &a.1, &b.1);

        (c0, c1)
    }

    pub fn double(circuit: &mut Circuit, a: &Pair<BigIntWires>) -> Pair<BigIntWires> {
        assert_eq!(a.0.len(), Self::N_BITS / 2);
        assert_eq!(a.1.len(), Self::N_BITS / 2);

        let c0 = Fq::double(circuit, &a.0);
        let c1 = Fq::double(circuit, &a.1);

        (c0, c1)
    }

    pub fn half(circuit: &mut Circuit, a: &Pair<BigIntWires>) -> Pair<BigIntWires> {
        assert_eq!(a.0.len(), Self::N_BITS / 2);
        assert_eq!(a.1.len(), Self::N_BITS / 2);

        let c0 = Fq::half(circuit, &a.0);
        let c1 = Fq::half(circuit, &a.1);

        (c0, c1)
    }

    pub fn triple(circuit: &mut Circuit, a: &Pair<BigIntWires>) -> Pair<BigIntWires> {
        assert_eq!(a.0.len(), Self::N_BITS / 2);
        assert_eq!(a.1.len(), Self::N_BITS / 2);

        let a_2 = Self::double(circuit, a);

        Self::add(circuit, (a.0.clone(), a.1.clone()), a_2)
    }

    pub fn mul_montgomery(
        circuit: &mut Circuit,
        a: &Pair<BigIntWires>,
        b: &Pair<BigIntWires>,
    ) -> Pair<BigIntWires> {
        assert_eq!(a.0.len(), Self::N_BITS / 2);
        assert_eq!(a.1.len(), Self::N_BITS / 2);
        assert_eq!(b.0.len(), Self::N_BITS / 2);
        assert_eq!(b.1.len(), Self::N_BITS / 2);

        // (a0 + a1) and (b0 + b1)
        let a_sum = Fq::add(circuit, &a.0, &a.1);
        let b_sum = Fq::add(circuit, &b.0, &b.1);

        // a0 * b0 and a1 * b1
        let a0_b0 = Fq::mul_montgomery(circuit, &a.0, &b.0);
        let a1_b1 = Fq::mul_montgomery(circuit, &a.1, &b.1);

        // (a0 + a1) * (b0 + b1)
        let sum_prod = Fq::mul_montgomery(circuit, &a_sum, &b_sum);

        // Result c0 = a0*b0 - a1*b1 (subtracting nonresidue multiplication)
        let c0 = Fq::sub(circuit, &a0_b0, &a1_b1);

        // Result c1 = (a0+a1)*(b0+b1) - a0*b0 - a1*b1 = a0*b1 + a1*b0
        let sum_a0b0_a1b1 = Fq::add(circuit, &a0_b0, &a1_b1);
        let c1 = Fq::sub(circuit, &sum_prod, &sum_a0b0_a1b1);

        (c0, c1)
    }

    pub fn mul_by_constant_montgomery(
        circuit: &mut Circuit,
        a: &Pair<BigIntWires>,
        b: &ark_bn254::Fq2,
    ) -> Pair<BigIntWires> {
        assert_eq!(a.0.len(), Self::N_BITS / 2);
        assert_eq!(a.1.len(), Self::N_BITS / 2);

        if *b == ark_bn254::Fq2::ONE {
            return (a.0.clone(), a.1.clone());
        }

        // Fq2 multiplication: (a0 + a1*u) * (b0 + b1*u) = (a0*b0 - a1*b1) + (a0*b1 + a1*b0)*u
        let a_sum = Fq::add(circuit, &a.0, &a.1);
        let a0_b0 = Fq::mul_by_constant_montgomery(circuit, &a.0, &b.c0);
        let a1_b1 = Fq::mul_by_constant_montgomery(circuit, &a.1, &b.c1);
        let sum_mul_sum = Fq::mul_by_constant_montgomery(circuit, &a_sum, &(b.c0 + b.c1));

        let c0 = Fq::sub(circuit, &a0_b0, &a1_b1);
        let a0b0_plus_a1b1 = Fq::add(circuit, &a0_b0, &a1_b1);
        let c1 = Fq::sub(circuit, &sum_mul_sum, &a0b0_plus_a1b1);

        (c0, c1)
    }

    pub fn mul_by_fq_montgomery(
        circuit: &mut Circuit,
        a: &Pair<BigIntWires>,
        b: &BigIntWires,
    ) -> Pair<BigIntWires> {
        assert_eq!(a.0.len(), Self::N_BITS / 2);
        assert_eq!(a.1.len(), Self::N_BITS / 2);
        assert_eq!(b.len(), Fq::N_BITS);

        let c0 = Fq::mul_montgomery(circuit, &a.0, b);
        let c1 = Fq::mul_montgomery(circuit, &a.1, b);

        (c0, c1)
    }

    pub fn mul_by_constant_fq_montgomery(
        circuit: &mut Circuit,
        a: &Pair<BigIntWires>,
        b: &ark_bn254::Fq,
    ) -> Pair<BigIntWires> {
        assert_eq!(a.0.len(), Self::N_BITS / 2);
        assert_eq!(a.1.len(), Self::N_BITS / 2);

        let c0 = Fq::mul_by_constant_montgomery(circuit, &a.0, b);
        let c1 = Fq::mul_by_constant_montgomery(circuit, &a.1, b);

        (c0, c1)
    }

    pub fn mul_constant_by_fq_montgomery(
        circuit: &mut Circuit,
        a: &ark_bn254::Fq2,
        b: &BigIntWires,
    ) -> Pair<BigIntWires> {
        assert_eq!(b.len(), Fq::N_BITS);

        let c0 = Fq::mul_by_constant_montgomery(circuit, b, &a.c0);
        let c1 = Fq::mul_by_constant_montgomery(circuit, b, &a.c1);

        (c0, c1)
    }

    pub fn mul_by_nonresidue(circuit: &mut Circuit, a: &Pair<BigIntWires>) -> Pair<BigIntWires> {
        assert_eq!(a.0.len(), Self::N_BITS / 2);
        assert_eq!(a.1.len(), Self::N_BITS / 2);

        // Nonresidue multiplication for BN254 Fq2: (a0 + a1*u) * (9 + u) = (9*a0 - a1) + (a0 + 9*a1)*u
        let a0_3 = Fq::triple(circuit, &a.0);
        let a0_9 = Fq::triple(circuit, &a0_3);

        let a1_3 = Fq::triple(circuit, &a.1);
        let a1_9 = Fq::triple(circuit, &a1_3);

        let c0 = Fq::sub(circuit, &a0_9, &a.1);
        let c1 = Fq::add(circuit, &a1_9, &a.0);

        (c0, c1)
    }

    pub fn square_montgomery(circuit: &mut Circuit, a: &Pair<BigIntWires>) -> Pair<BigIntWires> {
        assert_eq!(a.0.len(), Self::N_BITS / 2);
        assert_eq!(a.1.len(), Self::N_BITS / 2);

        // (a0 + a1*u)^2 = a0^2 - a1^2 + 2*a0*a1*u
        // Using identity: (a0+a1)*(a0-a1) = a0^2-a1^2
        let a0_plus_a1 = Fq::add(circuit, &a.0, &a.1);
        let a0_minus_a1 = Fq::sub(circuit, &a.0, &a.1);
        let a0_a1 = Fq::mul_montgomery(circuit, &a.0, &a.1);
        let c0 = Fq::mul_montgomery(circuit, &a0_plus_a1, &a0_minus_a1);
        let c1 = Fq::double(circuit, &a0_a1);

        (c0, c1)
    }

    pub fn inverse_montgomery(circuit: &mut Circuit, a: &Pair<BigIntWires>) -> Pair<BigIntWires> {
        assert_eq!(a.0.len(), Self::N_BITS / 2);
        assert_eq!(a.1.len(), Self::N_BITS / 2);

        // For (a0 + a1*u)^-1 = (a0 - a1*u) / (a0^2 + a1^2)
        let a0_square = Fq::square_montgomery(circuit, &a.0);
        let a1_square = Fq::square_montgomery(circuit, &a.1);
        let norm = Fq::add(circuit, &a0_square, &a1_square);
        let inverse_norm = Fq::inverse_montgomery(circuit, &norm);

        let c0 = Fq::mul_montgomery(circuit, &a.0, &inverse_norm);
        let neg_a1 = Fq::neg(circuit, &a.1);
        let c1 = Fq::mul_montgomery(circuit, &neg_a1, &inverse_norm);

        (c0, c1)
    }

    pub fn frobenius_montgomery(
        circuit: &mut Circuit,
        a: &Pair<BigIntWires>,
        i: usize,
    ) -> Pair<BigIntWires> {
        assert_eq!(a.0.len(), Self::N_BITS / 2);
        assert_eq!(a.1.len(), Self::N_BITS / 2);

        let c1 = Fq::mul_by_constant_montgomery(
            circuit,
            &a.1,
            &Fq::as_montgomery(
                ark_bn254::Fq2Config::FROBENIUS_COEFF_FP2_C1
                    [i % ark_bn254::Fq2Config::FROBENIUS_COEFF_FP2_C1.len()],
            ),
        );

        (a.0.clone(), c1)
    }

    pub fn div6(circuit: &mut Circuit, a: &Pair<BigIntWires>) -> Pair<BigIntWires> {
        assert_eq!(a.0.len(), Self::N_BITS / 2);
        assert_eq!(a.1.len(), Self::N_BITS / 2);

        let c0 = Fq::div6(circuit, &a.0);
        let c1 = Fq::div6(circuit, &a.1);

        (c0, c1)
    }

    // Calculate c0² + c1²
    fn norm_montgomery(circuit: &mut Circuit, c0: &BigIntWires, c1: &BigIntWires) -> BigIntWires {
        assert_eq!(c0.len(), Fq::N_BITS);
        assert_eq!(c1.len(), Fq::N_BITS);

        let c0_square = Fq::square_montgomery(circuit, c0);
        let c1_square = Fq::square_montgomery(circuit, c1);

        Fq::add(circuit, &c0_square, &c1_square)
    }

    // Square root based on the complex method. See paper https://eprint.iacr.org/2012/685.pdf (Algorithm 8, page 15).
    // Assume that the square root exists.
    // Special case: c1 == 0, not used in real case, just for testing
    pub fn sqrt_c1_zero_montgomery(
        circuit: &mut Circuit,
        a: &Pair<BigIntWires>,
        is_qr: WireId,
    ) -> Pair<BigIntWires> {
        let c0_sqrt = Fq::sqrt_montgomery(circuit, &a.0);
        let c0_neg = Fq::neg(circuit, &a.0);
        let c1_sqrt = Fq::sqrt_montgomery(circuit, &c0_neg);

        let zero = BigIntWires::new_constant(circuit, Fq::N_BITS, &num_bigint::BigUint::ZERO).unwrap();

        let c0_final = select(circuit, &c0_sqrt, &zero, is_qr);
        let c1_final = select(circuit, &zero, &c1_sqrt, is_qr);

        (c0_final, c1_final)
    }

    // General case: c1 != 0
    // TODO: Update this method to use new API - currently commented out due to missing types
    /*
    pub fn sqrt_general_montgomery(circuit: &mut Circuit, a: &Pair<BigIntWires>) -> Pair<BigIntWires> {
        let alpha = Self::norm_montgomery(circuit, &a.0, &a.1); // c0² + c1²
        let alpha_sqrt = Fq::sqrt_montgomery(circuit, &alpha); // sqrt(norm)

        let delta_plus = Fq::add(circuit, &alpha_sqrt, &a.0); // α + c0
        let delta = Fq::half(circuit, &delta_plus); // (α + c0)/2

        let is_qnr = Fq::is_qnr_montgomery(circuit, &delta); // δ is a qnr

        let delta_alt = Fq::sub(circuit, &delta, &alpha_sqrt); // δ - α

        let delta_final = select(circuit, &delta_alt, &delta, is_qnr);

        let c0_final = Fq::sqrt_montgomery(circuit, &delta_final); // sqrt(δ)
        let c0_inv = Fq::inverse_montgomery(circuit, &c0_final);
        let c1_half = Fq::half(circuit, &a.1);
        let c1_final = Fq::mul_montgomery(circuit, &c0_inv, &c1_half); // c1 / (2 * c0)

        (c0_final, c1_final)
    }
    */
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ark_ff::{AdditiveGroup, Fp6Config};

    //use serial_test::serial;
    use super::*;

    #[test]
    fn test_fq2_random() {
        let u = Fq2::random();
        println!("u: {u:?}");
        let b = Fq2::to_bits(u);
        let v = Fq2::from_bits(b);
        println!("v: {v:?}");
        assert_eq!(u, v);
    }

    #[test]
    fn test_fq2_add() {
        let mut circuit = Circuit::default();
        let a_wires = Fq2::new_bn(&mut circuit, true, false);
        let b_wires = Fq2::new_bn(&mut circuit, true, false);
        let c_wires = Fq2::add(&mut circuit, a_wires.clone(), b_wires.clone());

        c_wires.0.mark_as_output(&mut circuit);
        c_wires.1.mark_as_output(&mut circuit);

        let a_val = Fq2::random();
        let b_val = Fq2::random();
        let expected = a_val + b_val;

        let a_input = Fq2::get_wire_bits_fn(&a_wires, &a_val).unwrap();
        let b_input = Fq2::get_wire_bits_fn(&b_wires, &b_val).unwrap();
        let c_output = Fq2::get_wire_bits_fn(&c_wires, &expected).unwrap();

        circuit
            .simple_evaluate(|wire_id| (a_input)(wire_id).or((b_input)(wire_id)))
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((c_output)(wire_id), Some(value));
            });
    }

    #[test]
    fn test_fq2_neg() {
        let mut circuit = Circuit::default();
        let a_wires = Fq2::new_bn(&mut circuit, true, false);
        let c_wires = Fq2::neg(&mut circuit, a_wires.clone());

        c_wires.0.mark_as_output(&mut circuit);
        c_wires.1.mark_as_output(&mut circuit);

        let a_val = Fq2::random();
        let expected = -a_val;

        let a_input = Fq2::get_wire_bits_fn(&a_wires, &a_val).unwrap();
        let c_output = Fq2::get_wire_bits_fn(&c_wires, &expected).unwrap();

        circuit
            .simple_evaluate(a_input)
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((c_output)(wire_id), Some(value));
            });
    }

    #[test]
    fn test_fq2_sub() {
        let mut circuit = Circuit::default();
        let a_wires = Fq2::new_bn(&mut circuit, true, false);
        let b_wires = Fq2::new_bn(&mut circuit, true, false);
        let c_wires = Fq2::sub(&mut circuit, &a_wires, &b_wires);

        c_wires.0.mark_as_output(&mut circuit);
        c_wires.1.mark_as_output(&mut circuit);

        let a_val = Fq2::random();
        let b_val = Fq2::random();
        let expected = a_val - b_val;

        let a_input = Fq2::get_wire_bits_fn(&a_wires, &a_val).unwrap();
        let b_input = Fq2::get_wire_bits_fn(&b_wires, &b_val).unwrap();
        let c_output = Fq2::get_wire_bits_fn(&c_wires, &expected).unwrap();

        circuit
            .simple_evaluate(|wire_id| (a_input)(wire_id).or((b_input)(wire_id)))
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((c_output)(wire_id), Some(value));
            });
    }

    #[test]
    fn test_fq2_double() {
        let mut circuit = Circuit::default();
        let a_wires = Fq2::new_bn(&mut circuit, true, false);
        let c_wires = Fq2::double(&mut circuit, &a_wires);

        c_wires.0.mark_as_output(&mut circuit);
        c_wires.1.mark_as_output(&mut circuit);

        let a_val = Fq2::random();
        let expected = a_val + a_val;

        let a_input = Fq2::get_wire_bits_fn(&a_wires, &a_val).unwrap();
        let c_output = Fq2::get_wire_bits_fn(&c_wires, &expected).unwrap();

        circuit
            .simple_evaluate(a_input)
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((c_output)(wire_id), Some(value));
            });
    }

    #[test]
    fn test_fq2_triple() {
        let mut circuit = Circuit::default();
        let a_wires = Fq2::new_bn(&mut circuit, true, false);
        let c_wires = Fq2::triple(&mut circuit, &a_wires);

        c_wires.0.mark_as_output(&mut circuit);
        c_wires.1.mark_as_output(&mut circuit);

        let a_val = Fq2::random();
        let expected = a_val + a_val + a_val;

        let a_input = Fq2::get_wire_bits_fn(&a_wires, &a_val).unwrap();
        let c_output = Fq2::get_wire_bits_fn(&c_wires, &expected).unwrap();

        circuit
            .simple_evaluate(a_input)
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((c_output)(wire_id), Some(value));
            });
    }

    #[test]
    fn test_fq2_mul_montgomery() {
        let mut circuit = Circuit::default();
        let a_wires = Fq2::new_bn(&mut circuit, true, false);
        let b_wires = Fq2::new_bn(&mut circuit, true, false);
        let c_wires = Fq2::mul_montgomery(&mut circuit, &a_wires, &b_wires);

        c_wires.0.mark_as_output(&mut circuit);
        c_wires.1.mark_as_output(&mut circuit);

        let a_val = Fq2::random();
        let b_val = Fq2::random();
        let expected = Fq2::as_montgomery(a_val * b_val);

        let a_input = Fq2::get_wire_bits_fn(&a_wires, &Fq2::as_montgomery(a_val)).unwrap();
        let b_input = Fq2::get_wire_bits_fn(&b_wires, &Fq2::as_montgomery(b_val)).unwrap();
        let c_output = Fq2::get_wire_bits_fn(&c_wires, &expected).unwrap();

        circuit
            .simple_evaluate(|wire_id| (a_input)(wire_id).or((b_input)(wire_id)))
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((c_output)(wire_id), Some(value));
            });
    }

    #[test]
    fn test_fq2_mul_by_constant_montgomery() {
        let mut circuit = Circuit::default();
        let a_wires = Fq2::new_bn(&mut circuit, true, false);

        let a_val = Fq2::random();
        let b_val = Fq2::random();
        let c_wires =
            Fq2::mul_by_constant_montgomery(&mut circuit, &a_wires, &Fq2::as_montgomery(b_val));

        c_wires.0.mark_as_output(&mut circuit);
        c_wires.1.mark_as_output(&mut circuit);

        let expected = Fq2::as_montgomery(a_val * b_val);

        let a_input = Fq2::get_wire_bits_fn(&a_wires, &Fq2::as_montgomery(a_val)).unwrap();
        let c_output = Fq2::get_wire_bits_fn(&c_wires, &expected).unwrap();

        circuit
            .simple_evaluate(a_input)
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((c_output)(wire_id), Some(value));
            });
    }

    #[test]
    fn test_fq2_mul_by_fq_montgomery() {
        let mut circuit = Circuit::default();
        let a_wires = Fq2::new_bn(&mut circuit, true, false);
        let b_wires = Fq::new_bn(&mut circuit, true, false);
        let c_wires = Fq2::mul_by_fq_montgomery(&mut circuit, &a_wires, &b_wires);

        c_wires.0.mark_as_output(&mut circuit);
        c_wires.1.mark_as_output(&mut circuit);

        let a_val = Fq2::random();
        let b_val = crate::gadgets::bn254::fq::tests::rnd();
        let expected = Fq2::as_montgomery(a_val * ark_bn254::Fq2::new(b_val, ark_bn254::Fq::ZERO));

        let a_input = Fq2::get_wire_bits_fn(&a_wires, &Fq2::as_montgomery(a_val)).unwrap();
        let b_input = Fq::get_wire_bits_fn(&b_wires, &Fq::as_montgomery(b_val)).unwrap();
        let c_output = Fq2::get_wire_bits_fn(&c_wires, &expected).unwrap();

        circuit
            .simple_evaluate(|wire_id| (a_input)(wire_id).or((b_input)(wire_id)))
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((c_output)(wire_id), Some(value));
            });
    }

    #[test]
    fn test_fq2_mul_by_constant_fq_montgomery() {
        let mut circuit = Circuit::default();
        let a_wires = Fq2::new_bn(&mut circuit, true, false);

        let a_val = Fq2::random();
        let b_val = crate::gadgets::bn254::fq::tests::rnd();
        let c_wires =
            Fq2::mul_by_constant_fq_montgomery(&mut circuit, &a_wires, &Fq::as_montgomery(b_val));

        c_wires.0.mark_as_output(&mut circuit);
        c_wires.1.mark_as_output(&mut circuit);

        let expected = Fq2::as_montgomery(a_val * ark_bn254::Fq2::new(b_val, ark_bn254::Fq::ZERO));

        let a_input = Fq2::get_wire_bits_fn(&a_wires, &Fq2::as_montgomery(a_val)).unwrap();
        let c_output = Fq2::get_wire_bits_fn(&c_wires, &expected).unwrap();

        circuit
            .simple_evaluate(a_input)
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((c_output)(wire_id), Some(value));
            });
    }

    #[test]
    fn test_fq2_mul_by_nonresidue() {
        let mut circuit = Circuit::default();
        let a_wires = Fq2::new_bn(&mut circuit, true, false);
        let c_wires = Fq2::mul_by_nonresidue(&mut circuit, &a_wires);

        c_wires.0.mark_as_output(&mut circuit);
        c_wires.1.mark_as_output(&mut circuit);

        let a_val = Fq2::random();
        let expected = ark_bn254::Fq6Config::mul_fp2_by_nonresidue(a_val);

        let a_input = Fq2::get_wire_bits_fn(&a_wires, &a_val).unwrap();
        let c_output = Fq2::get_wire_bits_fn(&c_wires, &expected).unwrap();

        circuit
            .simple_evaluate(a_input)
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((c_output)(wire_id), Some(value));
            });
    }

    #[test]
    fn test_fq2_square_montgomery() {
        let mut circuit = Circuit::default();
        let a_wires = Fq2::new_bn(&mut circuit, true, false);
        let c_wires = Fq2::square_montgomery(&mut circuit, &a_wires);

        c_wires.0.mark_as_output(&mut circuit);
        c_wires.1.mark_as_output(&mut circuit);

        let a_val = Fq2::random();
        let expected = Fq2::as_montgomery(a_val * a_val);

        let a_input = Fq2::get_wire_bits_fn(&a_wires, &Fq2::as_montgomery(a_val)).unwrap();
        let c_output = Fq2::get_wire_bits_fn(&c_wires, &expected).unwrap();

        circuit
            .simple_evaluate(a_input)
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((c_output)(wire_id), Some(value));
            });
    }

    #[test]
    fn test_fq2_inverse_montgomery() {
        let mut circuit = Circuit::default();
        let a_wires = Fq2::new_bn(&mut circuit, true, false);
        let c_wires = Fq2::inverse_montgomery(&mut circuit, &a_wires);

        c_wires.0.mark_as_output(&mut circuit);
        c_wires.1.mark_as_output(&mut circuit);

        let a_val = Fq2::random();
        let expected = Fq2::as_montgomery(a_val.inverse().unwrap());

        let a_input = Fq2::get_wire_bits_fn(&a_wires, &Fq2::as_montgomery(a_val)).unwrap();
        let c_output = Fq2::get_wire_bits_fn(&c_wires, &expected).unwrap();

        let actual_c = circuit
            .simple_evaluate(a_input)
            .unwrap()
            .collect::<HashMap<WireId, bool>>();

        assert_eq!(
            Fq2::to_bitmask(&c_wires, |wire_id| c_output(wire_id).unwrap()),
            Fq2::to_bitmask(&c_wires, |wire_id| *actual_c.get(&wire_id).unwrap())
        );
    }

    #[test]
    fn test_fq2_frobenius_montgomery() {
        let a_val = Fq2::random();

        // Test frobenius_map(0)
        {
            let mut circuit = Circuit::default();
            let a_wires = Fq2::new_bn(&mut circuit, true, false);
            let c_wires = Fq2::frobenius_montgomery(&mut circuit, &a_wires, 0);

            c_wires.0.mark_as_output(&mut circuit);
            c_wires.1.mark_as_output(&mut circuit);

            let expected = Fq2::as_montgomery(a_val.frobenius_map(0));

            let a_input = Fq2::get_wire_bits_fn(&a_wires, &Fq2::as_montgomery(a_val)).unwrap();
            let c_output = Fq2::get_wire_bits_fn(&c_wires, &expected).unwrap();

            circuit
                .simple_evaluate(a_input)
                .unwrap()
                .for_each(|(wire_id, value)| {
                    assert_eq!((c_output)(wire_id), Some(value));
                });
        }

        // Test frobenius_map(1)
        {
            let mut circuit = Circuit::default();
            let a_wires = Fq2::new_bn(&mut circuit, true, false);
            let c_wires = Fq2::frobenius_montgomery(&mut circuit, &a_wires, 1);

            c_wires.0.mark_as_output(&mut circuit);
            c_wires.1.mark_as_output(&mut circuit);

            let expected = Fq2::as_montgomery(a_val.frobenius_map(1));

            let a_input = Fq2::get_wire_bits_fn(&a_wires, &Fq2::as_montgomery(a_val)).unwrap();
            let c_output = Fq2::get_wire_bits_fn(&c_wires, &expected).unwrap();

            circuit
                .simple_evaluate(a_input)
                .unwrap()
                .for_each(|(wire_id, value)| {
                    assert_eq!((c_output)(wire_id), Some(value));
                });
        }
    }

    #[test]
    fn test_fq2_div6() {
        let mut circuit = Circuit::default();
        let a_wires = Fq2::new_bn(&mut circuit, true, false);
        let c_wires = Fq2::div6(&mut circuit, &a_wires);

        c_wires.0.mark_as_output(&mut circuit);
        c_wires.1.mark_as_output(&mut circuit);

        let a_val = Fq2::random();
        let expected = a_val / ark_bn254::Fq2::from(6u32);

        let a_input = Fq2::get_wire_bits_fn(&a_wires, &a_val).unwrap();
        let c_output = Fq2::get_wire_bits_fn(&c_wires, &expected).unwrap();

        circuit
            .simple_evaluate(a_input)
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((c_output)(wire_id), Some(value));
            });
    }

    #[test]
    fn test_fq2_norm_montgomery() {
        let mut circuit = Circuit::default();
        let c0_wires = Fq::new_bn(&mut circuit, true, false);
        let c1_wires = Fq::new_bn(&mut circuit, true, false);
        let norm_wires = Fq2::norm_montgomery(&mut circuit, &c0_wires, &c1_wires);

        norm_wires.mark_as_output(&mut circuit);

        let r_val = Fq2::random();
        let expected_norm = Fq::as_montgomery(ark_bn254::Fq::from(r_val.norm()));

        let c0_input = Fq::get_wire_bits_fn(&c0_wires, &Fq::as_montgomery(r_val.c0)).unwrap();
        let c1_input = Fq::get_wire_bits_fn(&c1_wires, &Fq::as_montgomery(r_val.c1)).unwrap();
        let norm_output = Fq::get_wire_bits_fn(&norm_wires, &expected_norm).unwrap();

        circuit
            .simple_evaluate(|wire_id| (c0_input)(wire_id).or((c1_input)(wire_id)))
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((norm_output)(wire_id), Some(value));
            });
    }

    // #[test]
    // #[serial]
    // fn test_fq2_sqrt_c1_is_zero_montgomery() {
    //     let mut r = Fq2::random();
    //     r.c1 = ark_bn254::Fq::ZERO; // Ensure c1 is zero to simplify the test

    //     let bits = Fq2::wires_set_montgomery(r);

    //     let is_qr = {
    //         let wire = new_wirex();
    //         wire.borrow_mut().set(r.c0.legendre().is_qr());
    //         wire
    //     };
    //     println!("is qr: {:?}", is_qr.borrow().get_value());
    //     let circuit = Fq2::sqrt_c1_zero_montgomery(bits, is_qr);
    //     circuit.gate_counts().print();
    //     for mut gate in circuit.1 {
    //         gate.evaluate();
    //     }
    //     let c = Fq2::from_montgomery_wires(circuit.0);
    //     let rq = r.sqrt().unwrap();
    //     assert_eq!(c, rq);
    // }

    // #[test]
    // //#[serial]
    // fn test_fq2_sqrt_c1_is_zero_montgomery_evaluate() {
    //     let mut circuit = Circuit::default();
    //     let a_wires = Fq2::new_bn(&mut circuit, true, false);
    //     let is_qr_wire = circuit.new_wire(true, false);
    //
    //     let mut r = Fq2::random();
    //     r.c1 = ark_bn254::Fq::ZERO; // Ensure c1 is zero to simplify the test
    //
    //     let (c, _gate_count) = Fq2::sqrt_c1_zero_montgomery_evaluate(a_wires.clone(), is_qr_wire);
    //
    //     c.0.mark_as_output(&mut circuit);
    //     c.1.mark_as_output(&mut circuit);
    //
    //     let rq = r.sqrt().unwrap();
    //
    //     let a_input = Fq2::get_wire_bits_fn(&a_wires, &Fq2::as_montgomery(r)).unwrap();
    //     let is_qr_input = |wire_id: WireId| if wire_id == is_qr_wire { Some(r.c0.legendre().is_qr()) } else { None };
    //     let c_output = Fq2::get_wire_bits_fn(&c, &Fq2::as_montgomery(rq)).unwrap();
    //
    //     circuit
    //         .simple_evaluate(|wire_id| (a_input)(wire_id).or((is_qr_input)(wire_id)))
    //         .unwrap()
    //         .for_each(|(wire_id, value)| {
    //             assert_eq!((c_output)(wire_id), Some(value));
    //         });
    // }

    // #[test]
    // #[serial]
    // fn test_fq2_sqrt_general_montgomery() {
    //     let r = Fq2::random();
    //     let rr = r * r;
    //     let bits = Fq2::wires_set_montgomery(rr);

    //     let circuit = Fq2::sqrt_general_montgomery(bits);
    //     circuit.gate_counts().print();
    //     for mut gate in circuit.1 {
    //         gate.evaluate();
    //     }
    //     let c = Fq2::from_montgomery_wires(circuit.0);
    //     assert_eq!(c, rr.sqrt().unwrap());
    // }

    // #[test]
    // //#[serial]
    // fn test_fq2_sqrt_general_montgomery_evaluate() {
    //     let mut circuit = Circuit::default();
    //     let a_wires = Fq2::new_bn(&mut circuit, true, false);
    //
    //     let r = Fq2::random();
    //     let rr = r * r;
    //
    //     let (c, _gate_count) = Fq2::sqrt_general_montgomery_evaluate(a_wires.clone());
    //
    //     c.0.mark_as_output(&mut circuit);
    //     c.1.mark_as_output(&mut circuit);
    //
    //     let expected = rr.sqrt().unwrap();
    //
    //     let a_input = Fq2::get_wire_bits_fn(&a_wires, &Fq2::as_montgomery(rr)).unwrap();
    //     let c_output = Fq2::get_wire_bits_fn(&c, &Fq2::as_montgomery(expected)).unwrap();
    //
    //     circuit
    //         .simple_evaluate(|wire_id| (a_input)(wire_id))
    //         .unwrap()
    //         .for_each(|(wire_id, value)| {
    //             assert_eq!((c_output)(wire_id), Some(value));
    //         });
    // }
}
