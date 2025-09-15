//! BN254 Quadratic Extension Field Fq2 Implementation
//!
//! This module provides circuit-based operations on Fq2, the quadratic extension
//! of the BN254 base field Fq. Elements of Fq2 are represented as a + b*u where
//! a, b ∈ Fq and u² = -1 (or equivalently u² + 1 = 0).
//!
//! Fq2 is constructed as Fq[u]/(u² + 1) and is used as an intermediate field
//! in the tower construction leading to Fq12 for pairing operations.

use ark_ff::{Field, Fp2Config, PrimeField};
use circuit_component_macro::component;
use rand::Rng;

use crate::{
    CircuitContext, Gate, WireId,
    circuit::WiresObject,
    gadgets::{
        bigint::{BigIntWires, select},
        bn254::{fp254impl::Fp254Impl, fq::Fq},
    },
};

/// Type alias for a pair of values, used to represent Fq2 components
pub type Pair<T> = (T, T);

/// BN254 quadratic extension field Fq2 = Fq[u]/(u² + 1)
///
/// Represents elements as c0 + c1*u where c0, c1 ∈ Fq and u is the quadratic non-residue.
/// This is implemented as a tuple of two Fq elements [c0, c1].
#[derive(Clone, Debug)]
pub struct Fq2(pub [Fq; 2]);

impl WiresObject for Fq2 {
    fn to_wires_vec(&self) -> Vec<WireId> {
        let [
            Fq(BigIntWires { bits: bits1 }),
            Fq(BigIntWires { bits: bits2 }),
        ] = &self.0;

        bits1.iter().chain(bits2.iter()).copied().collect()
    }

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        let Self([f1, f2]) = self;
        Self([f1.clone_from(wire_gen), f2.clone_from(wire_gen)])
    }
}

impl crate::circuit::FromWires for Fq2 {
    fn from_wires(wires: &[WireId]) -> Option<Self> {
        if wires.len() >= 508 {
            // 2 * 254 bits
            let (fq1_wires, fq2_wires) = wires.split_at(254);
            let fq1 = Fq::from_wires(fq1_wires)?;
            let fq2 = Fq::from_wires(fq2_wires)?;
            Some(Self([fq1, fq2]))
        } else {
            None
        }
    }
}

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

    pub fn len(&self) -> usize {
        self.0.iter().map(|fq| fq.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &WireId> {
        self.0.iter().flat_map(|fq2| fq2.iter())
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

    pub fn from_ctx<C: CircuitContext>(circuit: &mut C) -> Fq2 {
        Fq2::from_components(Fq::from_ctx(circuit), Fq::from_ctx(circuit))
    }

    pub fn new(mut issue: impl FnMut() -> WireId) -> Fq2 {
        Fq2::from_components(Fq::new(&mut issue), Fq::new(issue))
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

    #[component(offcircuit_args = "a")]
    pub fn mul_constant_by_fq_montgomery<C: CircuitContext>(
        circuit: &mut C,
        a: &ark_bn254::Fq2,
        b: &Fq,
    ) -> Fq2 {
        assert_eq!(b.len(), Fq::N_BITS);

        // Convert constant components to Montgomery so the result stays in Montgomery form
        let a0_m = Fq::as_montgomery(a.c0);
        let a1_m = Fq::as_montgomery(a.c1);
        let c0 = Fq::mul_by_constant_montgomery(circuit, b, &a0_m);
        let c1 = Fq::mul_by_constant_montgomery(circuit, b, &a1_m);

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

    #[component]
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

        // Multiply c1 by Frobenius coefficient (in Montgomery form to match wire representation)
        let coef = ark_bn254::Fq2Config::FROBENIUS_COEFF_FP2_C1
            [i % ark_bn254::Fq2Config::FROBENIUS_COEFF_FP2_C1.len()];
        let c1 = Fq::mul_by_constant_montgomery(circuit, a.c1(), &Fq::as_montgomery(coef));

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
    #[component]
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
    use std::array;

    use ark_ff::{AdditiveGroup, Fp6Config, PrimeField};
    use test_log::test;

    use super::*;
    use crate::{
        circuit::{
            CircuitInput, CircuitOutput, EncodeInput,
            modes::{CircuitMode, ExecuteMode},
        },
        gadgets::{
            bigint::{BigUint as BigUintOutput, bits_from_biguint_with_len},
            bn254::fp254impl::Fp254Impl,
        },
        test_utils::trng,
    };

    fn random() -> ark_bn254::Fq2 {
        Fq2::random(&mut trng())
    }

    #[test]
    fn test_fq2_random() {
        let u = random();
        let b = Fq2::to_bits(u);
        let v = Fq2::from_bits(b);
        assert_eq!(u, v);
    }

    // Input struct for Fq2 tests
    struct Fq2Input<const N: usize> {
        values: [ark_bn254::Fq2; N],
    }

    impl<const N: usize> Fq2Input<N> {
        fn new(values: [ark_bn254::Fq2; N]) -> Self {
            Self { values }
        }
    }

    impl<const N: usize> CircuitInput for Fq2Input<N> {
        type WireRepr = [Fq2; N];

        fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
            array::from_fn(|_| Fq2::new(&mut issue))
        }

        fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
            repr.iter()
                .flat_map(|fq2| fq2.0.iter().flat_map(|fq| fq.0.iter().copied()))
                .collect()
        }
    }

    impl<const N: usize, M: CircuitMode<WireValue = bool>> EncodeInput<M> for Fq2Input<N> {
        fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
            self.values
                .iter()
                .zip(repr.iter())
                .for_each(|(val, wires)| {
                    let c0_bits = bits_from_biguint_with_len(
                        &BigUintOutput::from(val.c0.into_bigint()),
                        Fq::N_BITS,
                    )
                    .unwrap();
                    let c1_bits = bits_from_biguint_with_len(
                        &BigUintOutput::from(val.c1.into_bigint()),
                        Fq::N_BITS,
                    )
                    .unwrap();

                    wires.0[0]
                        .0
                        .iter()
                        .zip(c0_bits)
                        .for_each(|(w, b)| cache.feed_wire(*w, b));
                    wires.0[1]
                        .0
                        .iter()
                        .zip(c1_bits)
                        .for_each(|(w, b)| cache.feed_wire(*w, b));
                });
        }
    }

    // Output struct for Fq2 tests
    struct Fq2Output {
        value: ark_bn254::Fq2,
    }

    impl CircuitOutput<ExecuteMode> for Fq2Output {
        type WireRepr = Fq2;

        fn decode(wires: Self::WireRepr, cache: &mut ExecuteMode) -> Self {
            let c0 =
                <BigUintOutput as CircuitOutput<ExecuteMode>>::decode(wires.0[0].0.clone(), cache);
            let c1 =
                <BigUintOutput as CircuitOutput<ExecuteMode>>::decode(wires.0[1].0.clone(), cache);
            let value = ark_bn254::Fq2::new(ark_bn254::Fq::from(c0), ark_bn254::Fq::from(c1));
            Self { value }
        }
    }

    // Output for single Fq from within Fq2 tests
    struct FqOutput {
        value: ark_bn254::Fq,
    }

    impl CircuitOutput<ExecuteMode> for FqOutput {
        type WireRepr = Fq;

        fn decode(wires: Self::WireRepr, cache: &mut ExecuteMode) -> Self {
            let biguint = <BigUintOutput as CircuitOutput<ExecuteMode>>::decode(wires.0, cache);
            let value = ark_bn254::Fq::from(biguint);
            Self { value }
        }
    }

    #[test]
    fn test_fq2_add() {
        let a = random();
        let b = random();
        let expected = a + b;

        let input = Fq2Input::new([a, b]);
        let result = crate::circuit::CircuitBuilder::streaming_execute::<_, _, Fq2Output>(
            input,
            10_000,
            |ctx, input| {
                let [a, b] = input;
                Fq2::add(ctx, a, b)
            },
        );

        assert_eq!(result.output_value.value, expected);
    }

    #[test]
    fn test_fq2_neg() {
        let a = random();
        let expected = -a;

        let input = Fq2Input::new([a]);
        let result = crate::circuit::CircuitBuilder::streaming_execute::<_, _, Fq2Output>(
            input,
            10_000,
            |ctx, input| {
                let [a] = input;
                Fq2::neg(ctx, a.clone())
            },
        );

        assert_eq!(result.output_value.value, expected);
    }

    #[test]
    fn test_fq2_sub() {
        let a = random();
        let b = random();
        let expected = a - b;

        let input = Fq2Input::new([a, b]);
        let result = crate::circuit::CircuitBuilder::streaming_execute::<_, _, Fq2Output>(
            input,
            10_000,
            |ctx, input| {
                let [a, b] = input;
                Fq2::sub(ctx, a, b)
            },
        );

        assert_eq!(result.output_value.value, expected);
    }

    #[test]
    fn test_fq2_double() {
        let a = random();
        let expected = a + a;

        let input = Fq2Input::new([a]);
        let result = crate::circuit::CircuitBuilder::streaming_execute::<_, _, Fq2Output>(
            input,
            10_000,
            |ctx, input| {
                let [a] = input;
                Fq2::double(ctx, a)
            },
        );

        assert_eq!(result.output_value.value, expected);
    }

    #[test]
    fn test_fq2_triple() {
        let a = random();
        let expected = a + a + a;

        let input = Fq2Input::new([a]);
        let result = crate::circuit::CircuitBuilder::streaming_execute::<_, _, Fq2Output>(
            input,
            10_000,
            |ctx, input| {
                let [a] = input;
                Fq2::triple(ctx, a)
            },
        );

        assert_eq!(result.output_value.value, expected);
    }

    #[test]
    fn test_fq2_mul_montgomery() {
        let a = random();
        let b = random();
        let a_m = Fq2::as_montgomery(a);
        let b_m = Fq2::as_montgomery(b);
        let expected = Fq2::as_montgomery(a * b);

        let input = Fq2Input::new([a_m, b_m]);
        let result = crate::circuit::CircuitBuilder::streaming_execute::<_, _, Fq2Output>(
            input,
            10_000,
            |ctx, input| {
                let [a, b] = input;
                Fq2::mul_montgomery(ctx, a, b)
            },
        );

        assert_eq!(result.output_value.value, expected);
    }

    #[test]
    fn test_fq2_mul_by_constant_montgomery() {
        let a = random();
        let b = random();
        let a_m = Fq2::as_montgomery(a);
        let b_m = Fq2::as_montgomery(b);
        let expected = Fq2::as_montgomery(a * b);

        let input = Fq2Input::new([a_m]);
        let result = crate::circuit::CircuitBuilder::streaming_execute::<_, _, Fq2Output>(
            input,
            10_000,
            |ctx, input| {
                let [a] = input;
                Fq2::mul_by_constant_montgomery(ctx, a, &b_m)
            },
        );

        assert_eq!(result.output_value.value, expected);
    }

    #[test]
    fn test_fq2_mul_by_fq_montgomery() {
        let a = random();
        let b = crate::gadgets::bn254::fq::tests::rnd();
        let expected = Fq2::as_montgomery(a * ark_bn254::Fq2::new(b, ark_bn254::Fq::ZERO));

        // Custom input type containing both Fq2 and Fq
        struct In {
            a: ark_bn254::Fq2,
            b: ark_bn254::Fq,
        }
        struct InWire {
            a: Fq2,
            b: Fq,
        }
        impl CircuitInput for In {
            type WireRepr = InWire;
            fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
                InWire {
                    a: Fq2::new(&mut issue),
                    b: Fq::new(issue),
                }
            }
            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                let mut ids = repr.a.to_wires_vec();
                ids.extend(repr.b.to_wires_vec());
                ids
            }
        }
        impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for In {
            fn encode(&self, repr: &InWire, cache: &mut M) {
                // encode a (Fq2) in montgomery form
                let a_m = Fq2::as_montgomery(self.a);
                let c0_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(a_m.c0.into_bigint()),
                    Fq::N_BITS,
                )
                .unwrap();
                let c1_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(a_m.c1.into_bigint()),
                    Fq::N_BITS,
                )
                .unwrap();
                repr.a.0[0]
                    .0
                    .iter()
                    .zip(c0_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                repr.a.0[1]
                    .0
                    .iter()
                    .zip(c1_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                // encode b (Fq) in montgomery form
                let b_m = Fq::as_montgomery(self.b);
                let b_bits =
                    bits_from_biguint_with_len(&BigUintOutput::from(b_m.into_bigint()), Fq::N_BITS)
                        .unwrap();
                repr.b
                    .0
                    .iter()
                    .zip(b_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
            }
        }

        let input = In { a, b };
        let result = crate::circuit::CircuitBuilder::streaming_execute::<_, _, Fq2Output>(
            input,
            10_000,
            |ctx, input| Fq2::mul_by_fq_montgomery(ctx, &input.a, &input.b),
        );

        assert_eq!(result.output_value.value, expected);
    }

    #[test]
    fn test_fq2_mul_by_constant_fq_montgomery() {
        let a = random();
        let b = crate::gadgets::bn254::fq::tests::rnd();
        let expected = Fq2::as_montgomery(a * ark_bn254::Fq2::new(b, ark_bn254::Fq::ZERO));

        let input = Fq2Input::new([Fq2::as_montgomery(a)]);
        let result = crate::circuit::CircuitBuilder::streaming_execute::<_, _, Fq2Output>(
            input,
            10_000,
            |ctx, input| {
                let [a] = input;
                Fq2::mul_by_constant_fq_montgomery(ctx, a, &Fq::as_montgomery(b))
            },
        );

        assert_eq!(result.output_value.value, expected);
    }

    #[test]
    fn test_fq2_mul_by_nonresidue() {
        let a = random();
        let expected = ark_bn254::Fq6Config::mul_fp2_by_nonresidue(a);

        let input = Fq2Input::new([a]);
        let result = crate::circuit::CircuitBuilder::streaming_execute::<_, _, Fq2Output>(
            input,
            10_000,
            |ctx, input| {
                let [a] = input;
                Fq2::mul_by_nonresidue(ctx, a)
            },
        );

        assert_eq!(result.output_value.value, expected);
    }

    #[test]
    fn test_fq2_square_montgomery() {
        let a = random();
        let expected = Fq2::as_montgomery(a * a);

        let input = Fq2Input::new([Fq2::as_montgomery(a)]);
        let result = crate::circuit::CircuitBuilder::streaming_execute::<_, _, Fq2Output>(
            input,
            10_000,
            |ctx, input| {
                let [a] = input;
                Fq2::square_montgomery(ctx, a)
            },
        );

        assert_eq!(result.output_value.value, expected);
    }

    #[test]
    fn test_fq2_inverse_montgomery() {
        let a = random();
        let expected = Fq2::as_montgomery(a.inverse().unwrap());

        let input = Fq2Input::new([Fq2::as_montgomery(a)]);
        let result = crate::circuit::CircuitBuilder::streaming_execute::<_, _, Fq2Output>(
            input,
            10_000,
            |ctx, input| {
                let [a] = input;
                Fq2::inverse_montgomery(ctx, a)
            },
        );

        assert_eq!(result.output_value.value, expected);
    }

    #[test]
    fn test_fq2_frobenius_montgomery() {
        let a_val = random();

        // Test frobenius_map(0)
        {
            let input = Fq2Input::new([Fq2::as_montgomery(a_val)]);
            let expected = Fq2::as_montgomery(a_val.frobenius_map(0));

            let result = crate::circuit::CircuitBuilder::streaming_execute::<_, _, Fq2Output>(
                input,
                10_000,
                |ctx, input| {
                    let [a] = input;
                    Fq2::frobenius_montgomery(ctx, a, 0)
                },
            );

            assert_eq!(result.output_value.value, expected);
        }

        // Test frobenius_map(1)
        {
            let input = Fq2Input::new([Fq2::as_montgomery(a_val)]);
            let expected = Fq2::as_montgomery(a_val.frobenius_map(1));

            let result = crate::circuit::CircuitBuilder::streaming_execute::<_, _, Fq2Output>(
                input,
                10_000,
                |ctx, input| {
                    let [a] = input;
                    Fq2::frobenius_montgomery(ctx, a, 1)
                },
            );

            assert_eq!(result.output_value.value, expected);
        }
    }

    #[test]
    fn test_fq2_div6() {
        let a = random();
        let expected = a / ark_bn254::Fq2::from(6u32);

        let input = Fq2Input::new([a]);
        let result = crate::circuit::CircuitBuilder::streaming_execute::<_, _, Fq2Output>(
            input,
            10_000,
            |ctx, input| {
                let [a] = input;
                Fq2::div6(ctx, a)
            },
        );

        assert_eq!(result.output_value.value, expected);
    }

    #[test]
    fn test_fq2_norm_montgomery() {
        let r_val = random();
        let expected_norm = Fq::as_montgomery(ark_bn254::Fq::from(r_val.norm()));

        let input = Fq2Input::new([Fq2::as_montgomery(r_val)]);
        let result = crate::circuit::CircuitBuilder::streaming_execute::<_, _, FqOutput>(
            input,
            10_000,
            |ctx, input| {
                let [a] = input;
                Fq2::norm_montgomery(ctx, a.c0(), a.c1())
            },
        );

        assert_eq!(result.output_value.value, expected_norm);
    }

    // Inputs for sqrt(c1 == 0)
    struct Fq2SqrtZeroInput {
        value: ark_bn254::Fq2,
        is_qr: bool,
    }

    struct Fq2SqrtZeroWire {
        value: Fq2,
        is_qr: WireId,
    }

    impl CircuitInput for Fq2SqrtZeroInput {
        type WireRepr = Fq2SqrtZeroWire;

        fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
            Fq2SqrtZeroWire {
                value: Fq2::new(&mut issue),
                is_qr: (issue)(),
            }
        }

        fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
            let mut ids = repr.value.to_wires_vec();
            ids.push(repr.is_qr);
            ids
        }
    }

    impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for Fq2SqrtZeroInput {
        fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
            let c0_bits = bits_from_biguint_with_len(
                &BigUintOutput::from(self.value.c0.into_bigint()),
                Fq::N_BITS,
            )
            .unwrap();
            let c1_bits = bits_from_biguint_with_len(
                &BigUintOutput::from(self.value.c1.into_bigint()),
                Fq::N_BITS,
            )
            .unwrap();
            repr.value.0[0]
                .0
                .iter()
                .zip(c0_bits)
                .for_each(|(w, b)| cache.feed_wire(*w, b));
            repr.value.0[1]
                .0
                .iter()
                .zip(c1_bits)
                .for_each(|(w, b)| cache.feed_wire(*w, b));
            cache.feed_wire(repr.is_qr, self.is_qr);
        }
    }

    #[test]
    fn test_fq2_sqrt_c1_is_zero_montgomery() {
        let mut r_val = random();
        r_val.c1 = ark_bn254::Fq::ZERO;
        let expected = Fq2::as_montgomery(ark_bn254::Fq2::from(r_val.sqrt().unwrap()));

        let input = Fq2SqrtZeroInput {
            value: Fq2::as_montgomery(r_val),
            is_qr: r_val.c0.legendre().is_qr(),
        };

        let result = crate::circuit::CircuitBuilder::streaming_execute::<_, _, Fq2Output>(
            input,
            1_000_000,
            |ctx, input| {
                let Fq2SqrtZeroWire { value, is_qr } = input;
                Fq2::sqrt_c1_zero_montgomery(ctx, value, *is_qr)
            },
        );

        assert_eq!(result.output_value.value, expected);
    }

    #[test]
    fn test_fq2_sqrt_general_montgomery() {
        let r = random();
        let rr = r * r;
        let expected = rr.sqrt().unwrap();

        let input = Fq2Input::new([Fq2::as_montgomery(rr)]);
        let result = crate::circuit::CircuitBuilder::streaming_execute::<_, _, Fq2Output>(
            input,
            10_000,
            |ctx, input| {
                let [a] = input;
                Fq2::sqrt_general_montgomery(ctx, a)
            },
        );

        assert_eq!(result.output_value.value, Fq2::as_montgomery(expected));
    }
}
