//! BN254 Quadratic Extension Field Fq2 Implementation
//!
//! This module provides circuit-based operations on Fq2, the quadratic extension
//! of the BN254 base field Fq. Elements of Fq2 are represented as a + b*u where
//! a, b ∈ Fq and u² = -1 (or equivalently u² + 1 = 0).
//!
//! Fq2 is constructed as Fq[u]/(u² + 1) and is used as an intermediate field
//! in the tower construction leading to Fq12 for pairing operations.

use std::collections::HashMap;

use ark_ff::{Field, Fp2Config, PrimeField, UniformRand};
use num_traits::Zero;
use rand::Rng;

use crate::{
    CircuitContext, Gate, WireId,
    gadgets::{
        bigint::{self, BigIntWires, select},
        bn254::{fp254impl::Fp254Impl, fq::Fq},
    },
};

/// Type alias for a pair of values, used to represent Fq2 components
pub type Pair<T> = (T, T);

/// BN254 quadratic extension field Fq2 = Fq[u]/(u² + 1)
///
/// Represents elements as c0 + c1*u where c0, c1 ∈ Fq and u is the quadratic non-residue.
/// This is implemented as a tuple of two Fq elements [c0, c1].
#[derive(Clone)]
pub struct Fq2(pub [Fq; 2]);

impl AsRef<[Fq; 2]> for Fq2 {
    fn as_ref(&self) -> &[Fq; 2] {
        &self.0
    }
}

impl Fq2 {
    pub fn c0(&self) -> &Fq {
        &self.0[0]
    }

    pub fn c1(&self) -> &Fq {
        &self.0[1]
    }

    pub fn from_components(c0: Fq, c1: Fq) -> Self {
        Fq2([c0, c1])
    }
}

impl Fq2 {
    pub const N_BITS: usize = 2 * Fq::N_BITS;

    pub fn random(rng: &mut impl Rng) -> ark_bn254::Fq2 {
        ark_bn254::Fq2::new(Fq::random(rng), Fq::random(rng))
    }

    pub fn as_montgomery(a: ark_bn254::Fq2) -> ark_bn254::Fq2 {
        ark_bn254::Fq2::new(Fq::as_montgomery(a.c0), Fq::as_montgomery(a.c1))
    }

    pub fn from_montgomery(a: ark_bn254::Fq2) -> ark_bn254::Fq2 {
        ark_bn254::Fq2::new(Fq::from_montgomery(a.c0), Fq::from_montgomery(a.c1))
    }

    pub fn to_bits(u: ark_bn254::Fq2) -> Pair<Vec<bool>> {
        (Fq::to_bits(u.c0), Fq::to_bits(u.c1))
    }

    pub fn from_bits(bits: Pair<Vec<bool>>) -> ark_bn254::Fq2 {
        ark_bn254::Fq2::new(Fq::from_bits(bits.0), Fq::from_bits(bits.1))
    }

    pub fn new<C: CircuitContext>(circuit: &mut C) -> Fq2 {
        Fq2::from_components(Fq::new(circuit), Fq::new(circuit))
    }

    pub fn get_wire_bits_fn(
        wires: &Fq2,
        value: &ark_bn254::Fq2,
    ) -> Result<impl Fn(WireId) -> Option<bool> + use<>, crate::gadgets::bigint::Error> {
        let (_c0_bits, _c1_bits) = Self::to_bits(*value);

        let c0_fn = wires
            .c0()
            .get_wire_bits_fn(&num_bigint::BigUint::from(value.c0.into_bigint()))?;
        let c1_fn = wires
            .c1()
            .get_wire_bits_fn(&num_bigint::BigUint::from(value.c1.into_bigint()))?;

        Ok(move |wire_id| c0_fn(wire_id).or_else(|| c1_fn(wire_id)))
    }

    pub fn to_bitmask(wires: &Fq2, get_val: impl Fn(WireId) -> bool) -> String {
        let c0_mask = wires.c0().to_bitmask(&get_val);
        let c1_mask = wires.c1().to_bitmask(&get_val);
        format!("c0: {c0_mask}, c1: {c1_mask}")
    }

    pub fn equal_constant<C: CircuitContext>(
        circuit: &mut C,
        a: &Fq2,
        b: &ark_bn254::Fq2,
    ) -> WireId {
        let u = Fq::equal_constant(circuit, a.c0(), &b.c0);
        let v = Fq::equal_constant(circuit, a.c1(), &b.c1);
        let w = circuit.issue_wire();
        circuit.add_gate(Gate::and(u, v, w));
        w
    }

    pub fn add<C: CircuitContext>(circuit: &mut C, a: &Fq2, b: &Fq2) -> Fq2 {
        assert_eq!(a.c0().len(), Self::N_BITS / 2);
        assert_eq!(b.c0().len(), Self::N_BITS / 2);

        let c0 = Fq::add(circuit, a.c0(), b.c0());
        let c1 = Fq::add(circuit, a.c1(), b.c1());

        Fq2::from_components(c0, c1)
    }

    pub fn add_constant<C: CircuitContext>(circuit: &mut C, a: &Fq2, b: &ark_bn254::Fq2) -> Fq2 {
        assert_eq!(a.c0().len(), Self::N_BITS / 2);
        assert_eq!(a.c1().len(), Self::N_BITS / 2);

        let c0 = Fq::add_constant(circuit, a.c0(), &b.c0);
        let c1 = Fq::add_constant(circuit, a.c1(), &b.c1);
        Fq2::from_components(c0, c1)
    }

    pub fn neg<C: CircuitContext>(circuit: &mut C, a: Fq2) -> Fq2 {
        assert_eq!(a.c0().len(), Self::N_BITS / 2);
        assert_eq!(a.c1().len(), Self::N_BITS / 2);

        let c0 = Fq::neg(circuit, a.c0());
        let c1 = Fq::neg(circuit, a.c1());
        Fq2::from_components(c0, c1)
    }

    pub fn sub<C: CircuitContext>(circuit: &mut C, a: &Fq2, b: &Fq2) -> Fq2 {
        assert_eq!(a.c0().len(), Self::N_BITS / 2);
        assert_eq!(a.c1().len(), Self::N_BITS / 2);

        assert_eq!(b.c0().len(), Self::N_BITS / 2);
        assert_eq!(b.c1().len(), Self::N_BITS / 2);

        let c0 = Fq::sub(circuit, a.c0(), b.c0());
        let c1 = Fq::sub(circuit, a.c1(), b.c1());

        Fq2::from_components(c0, c1)
    }

    pub fn double<C: CircuitContext>(circuit: &mut C, a: &Fq2) -> Fq2 {
        assert_eq!(a.c0().len(), Self::N_BITS / 2);
        assert_eq!(a.c1().len(), Self::N_BITS / 2);

        let c0 = Fq::double(circuit, a.c0());
        let c1 = Fq::double(circuit, a.c1());

        Fq2::from_components(c0, c1)
    }

    pub fn half<C: CircuitContext>(circuit: &mut C, a: &Fq2) -> Fq2 {
        assert_eq!(a.c0().len(), Self::N_BITS / 2);
        assert_eq!(a.c1().len(), Self::N_BITS / 2);

        let c0 = Fq::half(circuit, a.c0());
        let c1 = Fq::half(circuit, a.c1());

        Fq2::from_components(c0, c1)
    }

    pub fn triple<C: CircuitContext>(circuit: &mut C, a: &Fq2) -> Fq2 {
        assert_eq!(a.c0().len(), Self::N_BITS / 2);
        assert_eq!(a.c1().len(), Self::N_BITS / 2);

        let a_2 = Self::double(circuit, a);

        Self::add(circuit, a, &a_2)
    }

    pub fn mul_montgomery<C: CircuitContext>(circuit: &mut C, a: &Fq2, b: &Fq2) -> Fq2 {
        assert_eq!(a.c0().len(), Self::N_BITS / 2);
        assert_eq!(a.c1().len(), Self::N_BITS / 2);
        assert_eq!(b.c0().len(), Self::N_BITS / 2);
        assert_eq!(b.c1().len(), Self::N_BITS / 2);

        // (a0 + a1) and (b0 + b1)
        let a_sum = Fq::add(circuit, a.c0(), a.c1());
        let b_sum = Fq::add(circuit, b.c0(), b.c1());

        // a0 * b0 and a1 * b1
        let a0_b0 = Fq::mul_montgomery(circuit, a.c0(), b.c0());
        let a1_b1 = Fq::mul_montgomery(circuit, a.c1(), b.c1());

        // (a0 + a1) * (b0 + b1)
        let sum_prod = Fq::mul_montgomery(circuit, &a_sum, &b_sum);

        // Result c0 = a0*b0 - a1*b1 (subtracting nonresidue multiplication)
        let c0 = Fq::sub(circuit, &a0_b0, &a1_b1);

        // Result c1 = (a0+a1)*(b0+b1) - a0*b0 - a1*b1 = a0*b1 + a1*b0
        let sum_a0b0_a1b1 = Fq::add(circuit, &a0_b0, &a1_b1);
        let c1 = Fq::sub(circuit, &sum_prod, &sum_a0b0_a1b1);

        Fq2::from_components(c0, c1)
    }

    pub fn mul_by_constant_montgomery<C: CircuitContext>(
        circuit: &mut C,
        a: &Fq2,
        b: &ark_bn254::Fq2,
    ) -> Fq2 {
        assert_eq!(a.c0().len(), Self::N_BITS / 2);
        assert_eq!(a.c1().len(), Self::N_BITS / 2);

        if *b == ark_bn254::Fq2::ONE {
            return Fq2::from_components(a.c0().clone(), a.c1().clone());
        }

        // Fq2 multiplication: (a0 + a1*u) * (b0 + b1*u) = (a0*b0 - a1*b1) + (a0*b1 + a1*b0)*u
        let a_sum = Fq::add(circuit, a.c0(), a.c1());
        let a0_b0 = Fq::mul_by_constant_montgomery(circuit, a.c0(), &b.c0);
        let a1_b1 = Fq::mul_by_constant_montgomery(circuit, a.c1(), &b.c1);
        let sum_mul_sum = Fq::mul_by_constant_montgomery(circuit, &a_sum, &(b.c0 + b.c1));

        let c0 = Fq::sub(circuit, &a0_b0, &a1_b1);
        let a0b0_plus_a1b1 = Fq::add(circuit, &a0_b0, &a1_b1);
        let c1 = Fq::sub(circuit, &sum_mul_sum, &a0b0_plus_a1b1);

        Fq2::from_components(c0, c1)
    }

    pub fn mul_by_fq_montgomery<C: CircuitContext>(circuit: &mut C, a: &Fq2, b: &Fq) -> Fq2 {
        assert_eq!(a.c0().len(), Self::N_BITS / 2);
        assert_eq!(a.c1().len(), Self::N_BITS / 2);
        assert_eq!(b.len(), Fq::N_BITS);

        let c0 = Fq::mul_montgomery(circuit, a.c0(), b);
        let c1 = Fq::mul_montgomery(circuit, a.c1(), b);

        Fq2::from_components(c0, c1)
    }

    pub fn mul_by_constant_fq_montgomery<C: CircuitContext>(
        circuit: &mut C,
        a: &Fq2,
        b: &ark_bn254::Fq,
    ) -> Fq2 {
        assert_eq!(a.c0().len(), Self::N_BITS / 2);
        assert_eq!(a.c1().len(), Self::N_BITS / 2);

        let c0 = Fq::mul_by_constant_montgomery(circuit, a.c0(), b);
        let c1 = Fq::mul_by_constant_montgomery(circuit, a.c1(), b);

        Fq2::from_components(c0, c1)
    }

    pub fn mul_constant_by_fq_montgomery<C: CircuitContext>(
        circuit: &mut C,
        a: &ark_bn254::Fq2,
        b: &Fq,
    ) -> Fq2 {
        assert_eq!(b.len(), Fq::N_BITS);

        let c0 = Fq::mul_by_constant_montgomery(circuit, b, &a.c0);
        let c1 = Fq::mul_by_constant_montgomery(circuit, b, &a.c1);

        Fq2::from_components(c0, c1)
    }

    pub fn mul_by_nonresidue<C: CircuitContext>(circuit: &mut C, a: &Fq2) -> Fq2 {
        assert_eq!(a.c0().len(), Self::N_BITS / 2);
        assert_eq!(a.c1().len(), Self::N_BITS / 2);

        // Nonresidue multiplication for BN254 Fq2: (a0 + a1*u) * (9 + u) = (9*a0 - a1) + (a0 + 9*a1)*u
        let a0_3 = Fq::triple(circuit, a.c0());
        let a0_9 = Fq::triple(circuit, &a0_3);

        let a1_3 = Fq::triple(circuit, a.c1());
        let a1_9 = Fq::triple(circuit, &a1_3);

        let c0 = Fq::sub(circuit, &a0_9, a.c1());
        let c1 = Fq::add(circuit, &a1_9, a.c0());

        Fq2::from_components(c0, c1)
    }

    pub fn square_montgomery<C: CircuitContext>(circuit: &mut C, a: &Fq2) -> Fq2 {
        assert_eq!(a.c0().len(), Self::N_BITS / 2);
        assert_eq!(a.c1().len(), Self::N_BITS / 2);

        // (a0 + a1*u)^2 = a0^2 - a1^2 + 2*a0*a1*u
        // Using identity: (a0+a1)*(a0-a1) = a0^2-a1^2
        let a0_plus_a1 = Fq::add(circuit, a.c0(), a.c1());
        let a0_minus_a1 = Fq::sub(circuit, a.c0(), a.c1());
        let a0_a1 = Fq::mul_montgomery(circuit, a.c0(), a.c1());
        let c0 = Fq::mul_montgomery(circuit, &a0_plus_a1, &a0_minus_a1);
        let c1 = Fq::double(circuit, &a0_a1);

        Fq2::from_components(c0, c1)
    }

    pub fn inverse_montgomery<C: CircuitContext>(circuit: &mut C, a: &Fq2) -> Fq2 {
        assert_eq!(a.c0().len(), Self::N_BITS / 2);
        assert_eq!(a.c1().len(), Self::N_BITS / 2);

        // For (a0 + a1*u)^-1 = (a0 - a1*u) / (a0^2 + a1^2)
        let a0_square = Fq::square_montgomery(circuit, a.c0());
        let a1_square = Fq::square_montgomery(circuit, a.c1());
        let norm = Fq::add(circuit, &a0_square, &a1_square);
        let inverse_norm = Fq::inverse_montgomery(circuit, &norm);

        let c0 = Fq::mul_montgomery(circuit, a.c0(), &inverse_norm);
        let neg_a1 = Fq::neg(circuit, a.c1());
        let c1 = Fq::mul_montgomery(circuit, &neg_a1, &inverse_norm);

        Fq2::from_components(c0, c1)
    }

    pub fn frobenius_montgomery<C: CircuitContext>(circuit: &mut C, a: &Fq2, i: usize) -> Fq2 {
        assert_eq!(a.c0().len(), Self::N_BITS / 2);
        assert_eq!(a.c1().len(), Self::N_BITS / 2);

        let c1 = Fq::mul_by_constant_montgomery(
            circuit,
            a.c1(),
            &Fq::as_montgomery(
                ark_bn254::Fq2Config::FROBENIUS_COEFF_FP2_C1
                    [i % ark_bn254::Fq2Config::FROBENIUS_COEFF_FP2_C1.len()],
            ),
        );

        Fq2::from_components(a.c0().clone(), c1)
    }

    pub fn div6<C: CircuitContext>(circuit: &mut C, a: &Fq2) -> Fq2 {
        assert_eq!(a.c0().len(), Self::N_BITS / 2);
        assert_eq!(a.c1().len(), Self::N_BITS / 2);

        let c0 = Fq::div6(circuit, a.c0());
        let c1 = Fq::div6(circuit, a.c1());

        Fq2::from_components(c0, c1)
    }

    // Calculate c0² + c1²
    fn norm_montgomery<C: CircuitContext>(circuit: &mut C, c0: &Fq, c1: &Fq) -> Fq {
        let c0_square = Fq::square_montgomery(circuit, c0);
        let c1_square = Fq::square_montgomery(circuit, c1);

        Fq::add(circuit, &c0_square, &c1_square)
    }

    // Square root based on the complex method. See paper https://eprint.iacr.org/2012/685.pdf (Algorithm 8, page 15).
    // Assume that the square root exists.
    // Special case: c1 == 0, not used in real case, just for testing
    pub fn sqrt_c1_zero_montgomery<C: CircuitContext>(
        circuit: &mut C,
        a: &Fq2,
        is_qr: WireId,
    ) -> Fq2 {
        let c0_sqrt = Fq::sqrt_montgomery(circuit, a.c0());
        let c0_neg = Fq::neg(circuit, a.c0());
        let c1_sqrt = Fq::sqrt_montgomery(circuit, &c0_neg);

        let zero = BigIntWires::new_constant(Fq::N_BITS, &num_bigint::BigUint::ZERO).unwrap();

        let c0_final = select(circuit, &c0_sqrt, &zero, is_qr);
        let c1_final = select(circuit, &zero, &c1_sqrt, is_qr);

        Fq2::from_components(Fq(c0_final), Fq(c1_final))
    }

    // General case: c1 != 0
    pub fn sqrt_general_montgomery<C: CircuitContext>(circuit: &mut C, a: &Fq2) -> Fq2 {
        let alpha = Self::norm_montgomery(circuit, a.c0(), a.c1()); // c0² + c1²
        let alpha_sqrt = Fq::sqrt_montgomery(circuit, &alpha); // sqrt(norm)

        let delta_plus = Fq::add(circuit, &alpha_sqrt, a.c0()); // α + c0
        let delta = Fq::half(circuit, &delta_plus); // (α + c0)/2

        let is_qnr = Fq::is_qnr_montgomery(circuit, &delta); // δ is a qnr

        let delta_alt = Fq::sub(circuit, &delta, &alpha_sqrt); // δ - α

        let delta_final = select(circuit, &delta_alt.0, &delta.0, is_qnr);

        let delta_final_fq = Fq(delta_final);
        let c0_final = Fq::sqrt_montgomery(circuit, &delta_final_fq); // sqrt(δ)
        let c0_inv = Fq::inverse_montgomery(circuit, &c0_final);
        let c1_half = Fq::half(circuit, a.c1());
        let c1_final = Fq::mul_montgomery(circuit, &c0_inv, &c1_half); // c1 / (2 * c0)

        Fq2::from_components(c0_final, c1_final)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ark_ff::{AdditiveGroup, Fp6Config};

    //use serial_test::serial;
    use super::*;
    use crate::test_utils::trng;

    fn random() -> ark_bn254::Fq2 {
        Fq2::random(&mut trng())
    }

    #[test]
    fn test_fq2_random() {
        let u = random();
        println!("u: {u:?}");
        let b = Fq2::to_bits(u);
        let v = Fq2::from_bits(b);
        println!("v: {v:?}");
        assert_eq!(u, v);
    }

    #[test]
    fn test_fq2_add() {
        let mut circuit = Circuit::default();
        let a_wires = Fq2::new(&mut circuit, true, false);
        let b_wires = Fq2::new(&mut circuit, true, false);
        let c_wires = Fq2::add(&mut circuit, &a_wires, &b_wires);

        c_wires.mark_as_output(&mut circuit);

        let a_val = random();
        let b_val = random();
        let expected = a_val + b_val;

        let a_input = Fq2::get_wire_bits_fn(&a_wires, &a_val).unwrap();
        let b_input = Fq2::get_wire_bits_fn(&b_wires, &b_val).unwrap();
        let c_output = Fq2::get_wire_bits_fn(&c_wires, &expected).unwrap();

        let actual_c = circuit
            .simple_evaluate(|wire_id| (a_input)(wire_id).or((b_input)(wire_id)))
            .unwrap()
            .collect::<HashMap<WireId, bool>>();

        assert_eq!(
            Fq2::to_bitmask(&c_wires, |wire_id| c_output(wire_id).unwrap()),
            Fq2::to_bitmask(&c_wires, |wire_id| *actual_c.get(&wire_id).unwrap())
        );
    }

    #[test]
    fn test_fq2_neg() {
        let mut circuit = Circuit::default();
        let a_wires = Fq2::new(&mut circuit, true, false);
        let c_wires = Fq2::neg(&mut circuit, a_wires.clone());

        c_wires.mark_as_output(&mut circuit);

        let a_val = random();
        let expected = -a_val;

        let a_input = Fq2::get_wire_bits_fn(&a_wires, &a_val).unwrap();
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
    fn test_fq2_sub() {
        let mut circuit = Circuit::default();
        let a_wires = Fq2::new(&mut circuit, true, false);
        let b_wires = Fq2::new(&mut circuit, true, false);
        let c_wires = Fq2::sub(&mut circuit, &a_wires, &b_wires);

        c_wires.mark_as_output(&mut circuit);

        let a_val = random();
        let b_val = random();
        let expected = a_val - b_val;

        let a_input = Fq2::get_wire_bits_fn(&a_wires, &a_val).unwrap();
        let b_input = Fq2::get_wire_bits_fn(&b_wires, &b_val).unwrap();
        let c_output = Fq2::get_wire_bits_fn(&c_wires, &expected).unwrap();

        let actual_c = circuit
            .simple_evaluate(|wire_id| (a_input)(wire_id).or((b_input)(wire_id)))
            .unwrap()
            .collect::<HashMap<WireId, bool>>();

        assert_eq!(
            Fq2::to_bitmask(&c_wires, |wire_id| c_output(wire_id).unwrap()),
            Fq2::to_bitmask(&c_wires, |wire_id| *actual_c.get(&wire_id).unwrap())
        );
    }

    #[test]
    fn test_fq2_double() {
        let mut circuit = Circuit::default();
        let a_wires = Fq2::new(&mut circuit, true, false);
        let c_wires = Fq2::double(&mut circuit, &a_wires);

        c_wires.mark_as_output(&mut circuit);

        let a_val = random();
        let expected = a_val + a_val;

        let a_input = Fq2::get_wire_bits_fn(&a_wires, &a_val).unwrap();
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
    fn test_fq2_triple() {
        let mut circuit = Circuit::default();
        let a_wires = Fq2::new(&mut circuit, true, false);
        let c_wires = Fq2::triple(&mut circuit, &a_wires);

        c_wires.mark_as_output(&mut circuit);

        let a_val = random();
        let expected = a_val + a_val + a_val;

        let a_input = Fq2::get_wire_bits_fn(&a_wires, &a_val).unwrap();
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
    fn test_fq2_mul_montgomery() {
        let mut circuit = Circuit::default();
        let a_wires = Fq2::new(&mut circuit, true, false);
        let b_wires = Fq2::new(&mut circuit, true, false);
        let c_wires = Fq2::mul_montgomery(&mut circuit, &a_wires, &b_wires);

        c_wires.mark_as_output(&mut circuit);

        let a_val = random();
        let b_val = random();
        let expected = Fq2::as_montgomery(a_val * b_val);

        let a_input = Fq2::get_wire_bits_fn(&a_wires, &Fq2::as_montgomery(a_val)).unwrap();
        let b_input = Fq2::get_wire_bits_fn(&b_wires, &Fq2::as_montgomery(b_val)).unwrap();
        let c_output = Fq2::get_wire_bits_fn(&c_wires, &expected).unwrap();

        let actual_c = circuit
            .simple_evaluate(|wire_id| (a_input)(wire_id).or((b_input)(wire_id)))
            .unwrap()
            .collect::<HashMap<WireId, bool>>();

        assert_eq!(
            Fq2::to_bitmask(&c_wires, |wire_id| c_output(wire_id).unwrap()),
            Fq2::to_bitmask(&c_wires, |wire_id| *actual_c.get(&wire_id).unwrap())
        );
    }

    #[test]
    fn test_fq2_mul_by_constant_montgomery() {
        let mut circuit = Circuit::default();
        let a_wires = Fq2::new(&mut circuit, true, false);

        let a_val = random();
        let b_val = random();
        let c_wires =
            Fq2::mul_by_constant_montgomery(&mut circuit, &a_wires, &Fq2::as_montgomery(b_val));

        c_wires.mark_as_output(&mut circuit);

        let expected = Fq2::as_montgomery(a_val * b_val);

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
    fn test_fq2_mul_by_fq_montgomery() {
        let mut circuit = Circuit::default();
        let a_wires = Fq2::new(&mut circuit, true, false);
        let b_wires = Fq::new(&mut circuit, true, false);
        let c_wires = Fq2::mul_by_fq_montgomery(&mut circuit, &a_wires, &b_wires);

        c_wires.mark_as_output(&mut circuit);

        let a_val = random();
        let b_val = crate::gadgets::bn254::fq::tests::rnd();
        let expected = Fq2::as_montgomery(a_val * ark_bn254::Fq2::new(b_val, ark_bn254::Fq::ZERO));

        let a_input = Fq2::get_wire_bits_fn(&a_wires, &Fq2::as_montgomery(a_val)).unwrap();
        let b_input = Fq::get_wire_bits_fn(&b_wires, &Fq::as_montgomery(b_val)).unwrap();
        let c_output = Fq2::get_wire_bits_fn(&c_wires, &expected).unwrap();

        let actual_c = circuit
            .simple_evaluate(|wire_id| (a_input)(wire_id).or((b_input)(wire_id)))
            .unwrap()
            .collect::<HashMap<WireId, bool>>();

        assert_eq!(
            Fq2::to_bitmask(&c_wires, |wire_id| c_output(wire_id).unwrap()),
            Fq2::to_bitmask(&c_wires, |wire_id| *actual_c.get(&wire_id).unwrap())
        );
    }

    #[test]
    fn test_fq2_mul_by_constant_fq_montgomery() {
        let mut circuit = Circuit::default();
        let a_wires = Fq2::new(&mut circuit, true, false);

        let a_val = random();
        let b_val = crate::gadgets::bn254::fq::tests::rnd();
        let c_wires =
            Fq2::mul_by_constant_fq_montgomery(&mut circuit, &a_wires, &Fq::as_montgomery(b_val));

        c_wires.mark_as_output(&mut circuit);

        let expected = Fq2::as_montgomery(a_val * ark_bn254::Fq2::new(b_val, ark_bn254::Fq::ZERO));

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
    fn test_fq2_mul_by_nonresidue() {
        let mut circuit = Circuit::default();
        let a_wires = Fq2::new(&mut circuit, true, false);
        let c_wires = Fq2::mul_by_nonresidue(&mut circuit, &a_wires);

        c_wires.mark_as_output(&mut circuit);

        let a_val = random();
        let expected = ark_bn254::Fq6Config::mul_fp2_by_nonresidue(a_val);

        let a_input = Fq2::get_wire_bits_fn(&a_wires, &a_val).unwrap();
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
    fn test_fq2_square_montgomery() {
        let mut circuit = Circuit::default();
        let a_wires = Fq2::new(&mut circuit, true, false);
        let c_wires = Fq2::square_montgomery(&mut circuit, &a_wires);

        c_wires.mark_as_output(&mut circuit);

        let a_val = random();
        let expected = Fq2::as_montgomery(a_val * a_val);

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
    fn test_fq2_inverse_montgomery() {
        let mut circuit = Circuit::default();
        let a_wires = Fq2::new(&mut circuit, true, false);
        let c_wires = Fq2::inverse_montgomery(&mut circuit, &a_wires);

        c_wires.mark_as_output(&mut circuit);

        let a_val = random();
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
        let a_val = random();

        // Test frobenius_map(0)
        {
            let mut circuit = Circuit::default();
            let a_wires = Fq2::new(&mut circuit, true, false);
            let c_wires = Fq2::frobenius_montgomery(&mut circuit, &a_wires, 0);

            c_wires.mark_as_output(&mut circuit);

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
            let a_wires = Fq2::new(&mut circuit, true, false);
            let c_wires = Fq2::frobenius_montgomery(&mut circuit, &a_wires, 1);

            c_wires.mark_as_output(&mut circuit);

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
        let a_wires = Fq2::new(&mut circuit, true, false);
        let c_wires = Fq2::div6(&mut circuit, &a_wires);

        c_wires.mark_as_output(&mut circuit);

        let a_val = random();
        let expected = a_val / ark_bn254::Fq2::from(6u32);

        let a_input = Fq2::get_wire_bits_fn(&a_wires, &a_val).unwrap();
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
    fn test_fq2_norm_montgomery() {
        let mut circuit = Circuit::default();
        let c0_wires = Fq::new(&mut circuit, true, false);
        let c1_wires = Fq::new(&mut circuit, true, false);
        let norm_wires = Fq2::norm_montgomery(&mut circuit, &c0_wires, &c1_wires);

        norm_wires.0.mark_as_output(&mut circuit);

        let r_val = random();
        let expected_norm = Fq::as_montgomery(ark_bn254::Fq::from(r_val.norm()));

        let c0_input = Fq::get_wire_bits_fn(&c0_wires, &Fq::as_montgomery(r_val.c0)).unwrap();
        let c1_input = Fq::get_wire_bits_fn(&c1_wires, &Fq::as_montgomery(r_val.c1)).unwrap();
        let norm_output = Fq::get_wire_bits_fn(&norm_wires, &expected_norm).unwrap();

        let actual_norm = circuit
            .simple_evaluate(|wire_id| (c0_input)(wire_id).or((c1_input)(wire_id)))
            .unwrap()
            .collect::<HashMap<WireId, bool>>();

        assert_eq!(
            norm_wires.to_bitmask(|wire_id| norm_output(wire_id).unwrap()),
            norm_wires.to_bitmask(|wire_id| *actual_norm.get(&wire_id).unwrap())
        );
    }

    #[test]
    fn test_fq2_sqrt_c1_is_zero_montgomery() {
        let mut circuit = Circuit::default();
        let a_wires = Fq2::new(&mut circuit, true, false);
        let is_qr_wires = circuit.issue_input_wire();
        let c_wires = Fq2::sqrt_c1_zero_montgomery(&mut circuit, &a_wires, is_qr_wires);

        c_wires.mark_as_output(&mut circuit);

        let mut r_val = random();
        r_val.c1 = ark_bn254::Fq::ZERO;
        let expected = Fq2::as_montgomery(ark_bn254::Fq2::from(r_val.sqrt().unwrap()));

        let a_input = Fq2::get_wire_bits_fn(&a_wires, &Fq2::as_montgomery(r_val)).unwrap();
        let is_qr_input = move |_wire_id| Some(r_val.c0.legendre().is_qr());
        let c_output = Fq2::get_wire_bits_fn(&c_wires, &expected).unwrap();

        circuit
            .simple_evaluate(|wire_id| (a_input)(wire_id).or((is_qr_input)(wire_id)))
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((c_output)(wire_id), Some(value));
            });
    }

    #[test]
    fn test_fq2_sqrt_general_montgomery() {
        let mut circuit = Circuit::default();
        let a_wires = Fq2::new(&mut circuit, true, false);

        let r = random();
        let rr = r * r;

        let c_wires = Fq2::sqrt_general_montgomery(&mut circuit, &a_wires);

        c_wires.mark_as_output(&mut circuit);

        let expected = rr.sqrt().unwrap();

        let a_input = Fq2::get_wire_bits_fn(&a_wires, &Fq2::as_montgomery(rr)).unwrap();
        let c_output = Fq2::get_wire_bits_fn(&c_wires, &Fq2::as_montgomery(expected)).unwrap();

        let actual_c = circuit
            .simple_evaluate(a_input)
            .unwrap()
            .collect::<HashMap<WireId, bool>>();

        assert_eq!(
            Fq2::to_bitmask(&c_wires, |wire_id| c_output(wire_id).unwrap()),
            Fq2::to_bitmask(&c_wires, |wire_id| *actual_c.get(&wire_id).unwrap())
        );
    }
}
