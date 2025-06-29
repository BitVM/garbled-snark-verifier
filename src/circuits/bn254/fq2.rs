use crate::{
    bag::*,
    circuits::bn254::{fp254impl::Fp254Impl, fq::Fq},
};
use ark_ff::{Field, Fp2Config, UniformRand};
use ark_std::rand::SeedableRng;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::{Rng, rng};
use rand_chacha::ChaCha20Rng;

pub struct Fq2;

impl Fq2 {
    pub const N_BITS: usize = 2 * Fq::N_BITS;

    pub fn as_montgomery(a: ark_bn254::Fq2) -> ark_bn254::Fq2 {
        ark_bn254::Fq2::new(Fq::as_montgomery(a.c0), Fq::as_montgomery(a.c1))
    }

    pub fn from_montgomery(a: ark_bn254::Fq2) -> ark_bn254::Fq2 {
        ark_bn254::Fq2::new(Fq::from_montgomery(a.c0), Fq::from_montgomery(a.c1))
    }

    pub fn random() -> ark_bn254::Fq2 {
        let mut prng = ChaCha20Rng::seed_from_u64(rng().random());
        ark_bn254::Fq2::rand(&mut prng)
    }

    pub fn to_bits(u: ark_bn254::Fq2) -> Vec<bool> {
        let mut bits = Vec::new();
        bits.extend(Fq::to_bits(u.c0));
        bits.extend(Fq::to_bits(u.c1));
        bits
    }

    pub fn from_bits(bits: Vec<bool>) -> ark_bn254::Fq2 {
        let bits1 = &bits[0..Fq::N_BITS].to_vec();
        let bits2 = &bits[Fq::N_BITS..Fq::N_BITS * 2].to_vec();
        ark_bn254::Fq2::new(Fq::from_bits(bits1.clone()), Fq::from_bits(bits2.clone()))
    }

    pub fn wires() -> Wires {
        (0..Self::N_BITS).map(|_| new_wirex()).collect()
    }

    pub fn wires_set(u: ark_bn254::Fq2) -> Wires {
        Self::to_bits(u)[0..Self::N_BITS]
            .iter()
            .map(|bit| {
                let wire = new_wirex();
                wire.borrow_mut().set(*bit);
                wire
            })
            .collect()
    }

    pub fn wires_set_montgomery(u: ark_bn254::Fq2) -> Wires {
        Self::wires_set(Self::as_montgomery(u))
    }

    pub fn from_wires(wires: Wires) -> ark_bn254::Fq2 {
        Self::from_bits(wires.iter().map(|wire| wire.borrow().get_value()).collect())
    }

    pub fn from_montgomery_wires(wires: Wires) -> ark_bn254::Fq2 {
        Self::from_montgomery(Self::from_wires(wires))
    }

    pub fn add(a: Wires, b: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(b.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq::N_BITS].to_vec();
        let a_c1 = a[Fq::N_BITS..2 * Fq::N_BITS].to_vec();
        let b_c0 = b[0..Fq::N_BITS].to_vec();
        let b_c1 = b[Fq::N_BITS..2 * Fq::N_BITS].to_vec();
        let wires_1 = circuit.extend(Fq::add(a_c0, b_c0));
        let wires_2 = circuit.extend(Fq::add(a_c1, b_c1));
        circuit.add_wires(wires_1);
        circuit.add_wires(wires_2);
        circuit
    }

    pub fn add_constant(a: Wires, b: ark_bn254::Fq2) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq::N_BITS].to_vec();
        let a_c1 = a[Fq::N_BITS..2 * Fq::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq::add_constant(a_c0, b.c0));
        let wires_2 = circuit.extend(Fq::add_constant(a_c1, b.c1));
        circuit.add_wires(wires_1);
        circuit.add_wires(wires_2);
        circuit
    }

    pub fn neg(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq::N_BITS].to_vec();
        let a_c1 = a[Fq::N_BITS..2 * Fq::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq::neg(a_c0));
        let wires_2 = circuit.extend(Fq::neg(a_c1));
        circuit.add_wires(wires_1);
        circuit.add_wires(wires_2);
        circuit
    }

    pub fn sub(a: Wires, b: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(b.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq::N_BITS].to_vec();
        let a_c1 = a[Fq::N_BITS..2 * Fq::N_BITS].to_vec();
        let b_c0 = b[0..Fq::N_BITS].to_vec();
        let b_c1 = b[Fq::N_BITS..2 * Fq::N_BITS].to_vec();
        let wires_1 = circuit.extend(Fq::sub(a_c0, b_c0));
        let wires_2 = circuit.extend(Fq::sub(a_c1, b_c1));
        circuit.add_wires(wires_1);
        circuit.add_wires(wires_2);
        circuit
    }

    pub fn double(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq::N_BITS].to_vec();
        let a_c1 = a[Fq::N_BITS..2 * Fq::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq::double(a_c0));
        let wires_2 = circuit.extend(Fq::double(a_c1));
        circuit.add_wires(wires_1);
        circuit.add_wires(wires_2);
        circuit
    }

    pub fn half(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq::N_BITS].to_vec();
        let a_c1 = a[Fq::N_BITS..2 * Fq::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq::half(a_c0));
        let wires_2 = circuit.extend(Fq::half(a_c1));
        circuit.add_wires(wires_1);
        circuit.add_wires(wires_2);
        circuit
    }

    pub fn triple(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_2 = circuit.extend(Fq2::double(a.clone()));
        let a_3 = circuit.extend(Fq2::add(a_2, a));
        circuit.add_wires(a_3);
        circuit
    }

    pub fn mul(a: Wires, b: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(b.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq::N_BITS].to_vec();
        let a_c1 = a[Fq::N_BITS..2 * Fq::N_BITS].to_vec();
        let b_c0 = b[0..Fq::N_BITS].to_vec();
        let b_c1 = b[Fq::N_BITS..2 * Fq::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq::add(a_c0.clone(), a_c1.clone()));
        let wires_2 = circuit.extend(Fq::add(b_c0.clone(), b_c1.clone()));
        let wires_3 = circuit.extend(Fq::mul(a_c0.clone(), b_c0.clone()));
        let wires_4 = circuit.extend(Fq::mul(a_c1.clone(), b_c1.clone()));
        let wires_5 = circuit.extend(Fq::add(wires_3.clone(), wires_4.clone()));
        let wires_6 = circuit.extend(Fq::sub(wires_3.clone(), wires_4.clone()));
        let wires_7 = circuit.extend(Fq::mul(wires_1.clone(), wires_2.clone()));
        let wires_8 = circuit.extend(Fq::sub(wires_7.clone(), wires_5.clone()));
        circuit.add_wires(wires_6);
        circuit.add_wires(wires_8);
        circuit
    }

    pub fn mul_montgomery(a: Wires, b: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(b.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq::N_BITS].to_vec();
        let a_c1 = a[Fq::N_BITS..2 * Fq::N_BITS].to_vec();
        let b_c0 = b[0..Fq::N_BITS].to_vec();
        let b_c1 = b[Fq::N_BITS..2 * Fq::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq::add(a_c0.clone(), a_c1.clone()));
        let wires_2 = circuit.extend(Fq::add(b_c0.clone(), b_c1.clone()));
        let wires_3 = circuit.extend(Fq::mul_montgomery(a_c0.clone(), b_c0.clone()));
        let wires_4 = circuit.extend(Fq::mul_montgomery(a_c1.clone(), b_c1.clone()));
        let wires_5 = circuit.extend(Fq::add(wires_3.clone(), wires_4.clone()));
        let wires_6 = circuit.extend(Fq::sub(wires_3.clone(), wires_4.clone()));
        let wires_7 = circuit.extend(Fq::mul_montgomery(wires_1.clone(), wires_2.clone()));
        let wires_8 = circuit.extend(Fq::sub(wires_7.clone(), wires_5.clone()));
        circuit.add_wires(wires_6);
        circuit.add_wires(wires_8);
        circuit
    }

    pub fn mul_by_constant(a: Wires, b: ark_bn254::Fq2) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        if b == ark_bn254::Fq2::ONE {
            circuit.add_wires(a);
            return circuit;
        }

        let a_c0 = a[0..Fq::N_BITS].to_vec();
        let a_c1 = a[Fq::N_BITS..2 * Fq::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq::add(a_c0.clone(), a_c1.clone()));
        let wires_2 = circuit.extend(Fq::mul_by_constant(a_c0.clone(), b.c0));
        let wires_3 = circuit.extend(Fq::mul_by_constant(a_c1.clone(), b.c1));
        let wires_4 = circuit.extend(Fq::mul_by_constant(wires_1.clone(), b.c0 + b.c1));
        let wires_5 = circuit.extend(Fq::sub(wires_2.clone(), wires_3.clone()));
        let wires_6 = circuit.extend(Fq::add(wires_2.clone(), wires_3.clone()));
        let wires_7 = circuit.extend(Fq::sub(wires_4.clone(), wires_6.clone()));
        circuit.add_wires(wires_5);
        circuit.add_wires(wires_7);
        circuit
    }

    pub fn mul_by_constant_montgomery(a: Wires, b: ark_bn254::Fq2) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        if b == ark_bn254::Fq2::ONE {
            circuit.add_wires(a);
            return circuit;
        }

        let a_c0 = a[0..Fq::N_BITS].to_vec();
        let a_c1 = a[Fq::N_BITS..2 * Fq::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq::add(a_c0.clone(), a_c1.clone()));
        let wires_2 = circuit.extend(Fq::mul_by_constant_montgomery(a_c0.clone(), b.c0));
        let wires_3 = circuit.extend(Fq::mul_by_constant_montgomery(a_c1.clone(), b.c1));
        let wires_4 = circuit.extend(Fq::mul_by_constant_montgomery(wires_1.clone(), b.c0 + b.c1));
        let wires_5 = circuit.extend(Fq::sub(wires_2.clone(), wires_3.clone()));
        let wires_6 = circuit.extend(Fq::add(wires_2.clone(), wires_3.clone()));
        let wires_7 = circuit.extend(Fq::sub(wires_4.clone(), wires_6.clone()));
        circuit.add_wires(wires_5);
        circuit.add_wires(wires_7);
        circuit
    }

    pub fn mul_by_fq(a: Wires, b: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(b.len(), Fq::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq::N_BITS].to_vec();
        let a_c1 = a[Fq::N_BITS..2 * Fq::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq::mul(a_c0.clone(), b.clone()));
        let wires_2 = circuit.extend(Fq::mul(a_c1.clone(), b.clone()));
        circuit.add_wires(wires_1);
        circuit.add_wires(wires_2);
        circuit
    }

    pub fn mul_by_fq_montgomery(a: Wires, b: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(b.len(), Fq::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq::N_BITS].to_vec();
        let a_c1 = a[Fq::N_BITS..2 * Fq::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq::mul_montgomery(a_c0.clone(), b.clone()));
        let wires_2 = circuit.extend(Fq::mul_montgomery(a_c1.clone(), b.clone()));
        circuit.add_wires(wires_1);
        circuit.add_wires(wires_2);
        circuit
    }

    pub fn mul_by_constant_fq(a: Wires, b: ark_bn254::Fq) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq::N_BITS].to_vec();
        let a_c1 = a[Fq::N_BITS..2 * Fq::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq::mul_by_constant(a_c0.clone(), b));
        let wires_2 = circuit.extend(Fq::mul_by_constant(a_c1.clone(), b));
        circuit.add_wires(wires_1);
        circuit.add_wires(wires_2);
        circuit
    }

    pub fn mul_by_constant_fq_montgomery(a: Wires, b: ark_bn254::Fq) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq::N_BITS].to_vec();
        let a_c1 = a[Fq::N_BITS..2 * Fq::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq::mul_by_constant_montgomery(a_c0.clone(), b));
        let wires_2 = circuit.extend(Fq::mul_by_constant_montgomery(a_c1.clone(), b));
        circuit.add_wires(wires_1);
        circuit.add_wires(wires_2);
        circuit
    }

    pub fn mul_constant_by_fq(a: ark_bn254::Fq2, b: Wires) -> Circuit {
        assert_eq!(b.len(), Fq::N_BITS);
        let mut circuit = Circuit::empty();

        let wires_1 = circuit.extend(Fq::mul_by_constant(b.clone(), a.c0));
        let wires_2 = circuit.extend(Fq::mul_by_constant(b.clone(), a.c1));
        circuit.add_wires(wires_1);
        circuit.add_wires(wires_2);
        circuit
    }

    pub fn mul_constant_by_fq_montgomery(a: ark_bn254::Fq2, b: Wires) -> Circuit {
        assert_eq!(b.len(), Fq::N_BITS);
        let mut circuit = Circuit::empty();

        let wires_1 = circuit.extend(Fq::mul_by_constant_montgomery(b.clone(), a.c0));
        let wires_2 = circuit.extend(Fq::mul_by_constant_montgomery(b.clone(), a.c1));
        circuit.add_wires(wires_1);
        circuit.add_wires(wires_2);
        circuit
    }

    pub fn mul_by_nonresidue(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq::N_BITS].to_vec();
        let a_c1 = a[Fq::N_BITS..2 * Fq::N_BITS].to_vec();

        let a0_3 = circuit.extend(Fq::triple(a_c0.clone()));
        let a0_9 = circuit.extend(Fq::triple(a0_3.clone()));

        let a1_3 = circuit.extend(Fq::triple(a_c1.clone()));
        let a1_9 = circuit.extend(Fq::triple(a1_3.clone()));

        let u = circuit.extend(Fq::sub(a0_9.clone(), a_c1.clone()));
        let v = circuit.extend(Fq::add(a1_9.clone(), a_c0.clone()));

        circuit.add_wires(u);
        circuit.add_wires(v);
        circuit
    }

    pub fn square(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq::N_BITS].to_vec();
        let a_c1 = a[Fq::N_BITS..2 * Fq::N_BITS].to_vec();

        let a_c0_plus_a_c1 = circuit.extend(Fq::add(a_c0.clone(), a_c1.clone()));
        let a_c0_minus_a_c1 = circuit.extend(Fq::sub(a_c0.clone(), a_c1.clone()));
        let a_c0_a_c1 = circuit.extend(Fq::mul(a_c0.clone(), a_c1));
        let a_c0_square_minus_a_c1_square =
            circuit.extend(Fq::mul(a_c0_plus_a_c1.clone(), a_c0_minus_a_c1));
        let a_c0_a_c1_double = circuit.extend(Fq::double(a_c0_a_c1));
        circuit.add_wires(a_c0_square_minus_a_c1_square);
        circuit.add_wires(a_c0_a_c1_double);
        circuit
    }

    pub fn square_montgomery(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq::N_BITS].to_vec();
        let a_c1 = a[Fq::N_BITS..2 * Fq::N_BITS].to_vec();

        let a_c0_plus_a_c1 = circuit.extend(Fq::add(a_c0.clone(), a_c1.clone()));
        let a_c0_minus_a_c1 = circuit.extend(Fq::sub(a_c0.clone(), a_c1.clone()));
        let a_c0_a_c1 = circuit.extend(Fq::mul_montgomery(a_c0.clone(), a_c1));
        let a_c0_square_minus_a_c1_square =
            circuit.extend(Fq::mul_montgomery(a_c0_plus_a_c1.clone(), a_c0_minus_a_c1));
        let a_c0_a_c1_double = circuit.extend(Fq::double(a_c0_a_c1));
        circuit.add_wires(a_c0_square_minus_a_c1_square);
        circuit.add_wires(a_c0_a_c1_double);
        circuit
    }

    pub fn inverse(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq::N_BITS].to_vec();
        let a_c1 = a[Fq::N_BITS..2 * Fq::N_BITS].to_vec();

        let a_c0_square = circuit.extend(Fq::square(a_c0.clone()));
        let a_c1_square = circuit.extend(Fq::square(a_c1.clone()));
        let norm = circuit.extend(Fq::add(a_c0_square, a_c1_square));
        let inverse_norm = circuit.extend(Fq::inverse(norm));

        let res_c0 = circuit.extend(Fq::mul(a_c0, inverse_norm.clone()));
        let neg_a_c1 = circuit.extend(Fq::neg(a_c1));
        let res_c1 = circuit.extend(Fq::mul(neg_a_c1, inverse_norm.clone()));

        circuit.add_wires(res_c0);
        circuit.add_wires(res_c1);
        circuit
    }

    pub fn inverse_montgomery(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq::N_BITS].to_vec();
        let a_c1 = a[Fq::N_BITS..2 * Fq::N_BITS].to_vec();

        let a_c0_square = circuit.extend(Fq::square_montgomery(a_c0.clone()));
        let a_c1_square = circuit.extend(Fq::square_montgomery(a_c1.clone()));
        let norm = circuit.extend(Fq::add(a_c0_square, a_c1_square));
        let inverse_norm = circuit.extend(Fq::inverse_montgomery(norm));

        let res_c0 = circuit.extend(Fq::mul_montgomery(a_c0, inverse_norm.clone()));
        let neg_a_c1 = circuit.extend(Fq::neg(a_c1));
        let res_c1 = circuit.extend(Fq::mul_montgomery(neg_a_c1, inverse_norm.clone()));

        circuit.add_wires(res_c0);
        circuit.add_wires(res_c1);
        circuit
    }

    pub fn frobenius(a: Wires, i: usize) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq::N_BITS].to_vec();
        let a_c1 = a[Fq::N_BITS..2 * Fq::N_BITS].to_vec();

        let result = circuit.extend(Fq::mul_by_constant(
            a_c1,
            ark_bn254::Fq2Config::FROBENIUS_COEFF_FP2_C1
                [i % ark_bn254::Fq2Config::FROBENIUS_COEFF_FP2_C1.len()],
        ));
        circuit.0.extend(a_c0);
        circuit.0.extend(result);
        circuit
    }

    pub fn frobenius_montgomery(a: Wires, i: usize) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq::N_BITS].to_vec();
        let a_c1 = a[Fq::N_BITS..2 * Fq::N_BITS].to_vec();

        let result = circuit.extend(Fq::mul_by_constant_montgomery(
            a_c1,
            Fq::as_montgomery(
                ark_bn254::Fq2Config::FROBENIUS_COEFF_FP2_C1
                    [i % ark_bn254::Fq2Config::FROBENIUS_COEFF_FP2_C1.len()],
            ),
        ));
        circuit.0.extend(a_c0);
        circuit.0.extend(result);
        circuit
    }

    pub fn div6(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq::N_BITS].to_vec();
        let a_c1 = a[Fq::N_BITS..2 * Fq::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq::div6(a_c0));
        let wires_2 = circuit.extend(Fq::div6(a_c1));
        circuit.add_wires(wires_1);
        circuit.add_wires(wires_2);
        circuit
    }

    fn exp_by_constant_montgomery(a: Wires, b: ark_bn254::Fq) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        if b.is_zero() {
            circuit.add_wires(Fq2::wires_set_montgomery(ark_bn254::Fq2::ONE));
            return circuit;
        }

        if b.is_one() {
            circuit.add_wires(a);
            return circuit;
        }

        let b_bits = Fq::to_bits(b);
        let mut i = Fq::N_BITS - 1;
        while !b_bits[i] {
            i -= 1;
        }

        let mut result = a.clone();
        for b_bit in b_bits.iter().rev().skip(Fq::N_BITS - i) {
            let result_square = circuit.extend(Self::square_montgomery(result.clone()));
            if *b_bit {
                result = circuit.extend(Self::mul_montgomery(a.clone(), result_square));
            } else {
                result = result_square;
            }
        }
        circuit.add_wires(result);
        circuit
    }

    fn norm_montgomery(c0: Wires, c1: Wires) -> Circuit {
        assert_eq!(c0.len(), Fq::N_BITS);
        assert_eq!(c1.len(), Fq::N_BITS);
        let mut circuit = Circuit::empty();

        let c0_square = circuit.extend(Fq::square_montgomery(c0.clone()));
        let c1_square = circuit.extend(Fq::square_montgomery(c1.clone()));

        let c1_mul_nonresidue = circuit.extend(Fq::mul_by_constant_montgomery(
            c1_square,
            Fq::as_montgomery(ark_bn254::Fq2Config::NONRESIDUE),
        ));
        let norm = circuit.extend(Fq::sub(c0_square, c1_mul_nonresidue));

        circuit.add_wires(norm);
        circuit
    }

    // Square root based on the complex method. See paper https://eprint.iacr.org/2012/685.pdf (Algorithm 8, page 15).
    // Assume that the square root exists.
    pub fn sqrt_montgomery(a: Wires) -> Circuit {
        use crate::circuits::bigint::U254;
        let mut c0 = Vec::new();
        c0.extend_from_slice(&a[0..Fq::N_BITS]);

        let mut c1 = Vec::new();
        c1.extend_from_slice(&a[Fq::N_BITS..Fq2::N_BITS]);

        let mut circuit = Circuit::empty();

        // Case 1: c1 == 0
        let is_c1_zero = circuit.extend(U254::equal_constant(c1.clone(), BigUint::ZERO)); // output: 1 if c1 == 0

        let c0_sqrt = circuit.extend(Fq::sqrt_montgomery(c0.clone())); // sqrt(c0)

        let inverse_nonresidue = circuit.extend(Fq::inverse_montgomery(Fq::wires_set_montgomery(
            ark_bn254::Fq2Config::NONRESIDUE,
        ))); // 1 / NONRESIDUE

        let c0_div_nonresidue = circuit.extend(Fq::mul_montgomery(c0.clone(), inverse_nonresidue)); // c0 / NONRESIDUE
        let c1_sqrt = circuit.extend(Fq::sqrt_montgomery(c0_div_nonresidue));

        let is_qnr = circuit.extend(Fq::is_qnr_montgomery(c0.clone()));
        let zero_mont = Fq::wires_set_montgomery(ark_bn254::Fq::zero());
        let part1 = (
            circuit.extend(U254::select(
                c0_sqrt.clone(),
                zero_mont.clone(),
                is_qnr[0].clone(),
            )),
            circuit.extend(U254::select(zero_mont, c1_sqrt, is_qnr[0].clone())),
        );

        // Case 2: general
        let alpha = circuit.extend(Fq2::norm_montgomery(c0.clone(), c1.clone())); // c0² - NONRESIDUE·c1²
        let alpha_sqrt = circuit.extend(Fq::sqrt_montgomery(alpha.clone())); // sqrt(norm)

        let delta_plus = circuit.extend(Fq::add(alpha_sqrt.clone(), c0.clone())); // α + c0

        let inv_two = ark_bn254::Fq::from(2u8).inverse().unwrap(); // 1/2
        let delta = circuit.extend(Fq::mul_by_constant_montgomery(delta_plus, inv_two)); // (α + c0)/2

        let is_qnr = circuit.extend(Fq::is_qnr_montgomery(delta.clone())); // δ is a qnr 

        let delta_alt = circuit.extend(Fq::sub(c0.clone(), alpha_sqrt)); // c0 - α
        let delta_alt_half = circuit.extend(Fq::mul_by_constant_montgomery(delta_alt, inv_two));

        let delta_final = circuit.extend(U254::select(delta, delta_alt_half, is_qnr[0].clone()));

        let c0_final = circuit.extend(Fq::sqrt_montgomery(delta_final.clone())); // sqrt(δ)
        let c0_inv = circuit.extend(Fq::inverse_montgomery(c0_final.clone()));
        let c1_half = circuit.extend(Fq::mul_by_constant(c1.clone(), inv_two));
        let c1_final = circuit.extend(Fq::mul_montgomery(c0_inv.clone(), c1_half)); // c1 / (2 * c0)

        let part2 = (c0_final, c1_final);

        // Select between case 1 and case 2
        let final_c0 = circuit.extend(U254::select(part1.0, part2.0, is_c1_zero[0].clone()));
        let final_c1 = circuit.extend(U254::select(part1.1, part2.1, is_c1_zero[0].clone()));
        circuit.add_wires(final_c0);
        circuit.add_wires(final_c1);

        circuit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{AdditiveGroup, Fp6Config};
    use ark_std::test_rng;

    #[test]
    fn test_fq2_random() {
        let u = Fq2::random();
        println!("u: {:?}", u);
        let b = Fq2::to_bits(u);
        let v = Fq2::from_bits(b);
        println!("v: {:?}", v);
        assert_eq!(u, v);
    }

    #[test]
    fn test_fq2_add() {
        let a = Fq2::random();
        let b = Fq2::random();
        let circuit = Fq2::add(Fq2::wires_set(a), Fq2::wires_set(b));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq2::from_wires(circuit.0);
        assert_eq!(c, a + b);
    }

    #[test]
    fn test_fq2_neg() {
        let a = Fq2::random();
        let circuit = Fq2::neg(Fq2::wires_set(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq2::from_wires(circuit.0);
        assert_eq!(c, -a);
    }

    #[test]
    fn test_fq2_sub() {
        let a = Fq2::random();
        let b = Fq2::random();
        let circuit = Fq2::sub(Fq2::wires_set(a), Fq2::wires_set(b));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq2::from_wires(circuit.0);
        assert_eq!(c, a - b);
    }

    #[test]
    fn test_fq2_double() {
        let a = Fq2::random();
        let circuit = Fq2::double(Fq2::wires_set(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq2::from_wires(circuit.0);
        assert_eq!(c, a + a);
    }

    #[test]
    fn test_fq2_triple() {
        let a = Fq2::random();
        let circuit = Fq2::triple(Fq2::wires_set(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq2::from_wires(circuit.0);
        assert_eq!(c, a + a + a);
    }

    #[test]
    fn test_fq2_mul() {
        let a = Fq2::random();
        let b = Fq2::random();
        let circuit = Fq2::mul(Fq2::wires_set(a), Fq2::wires_set(b));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq2::from_wires(circuit.0);
        assert_eq!(c, a * b);
    }

    #[test]
    fn test_fq2_mul_montgomery() {
        let a = Fq2::random();
        let b = Fq2::random();
        let circuit = Fq2::mul_montgomery(
            Fq2::wires_set(Fq2::as_montgomery(a)),
            Fq2::wires_set(Fq2::as_montgomery(b)),
        );
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq2::from_wires(circuit.0);
        assert_eq!(c, Fq2::as_montgomery(a * b));
    }

    #[test]
    fn test_fq2_mul_by_constant() {
        let a = Fq2::random();
        let b = Fq2::random();
        let circuit = Fq2::mul_by_constant(Fq2::wires_set(a), b);
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq2::from_wires(circuit.0);
        assert_eq!(c, a * b);
    }

    #[test]
    fn test_fq2_mul_by_constant_montgomery() {
        let a = Fq2::random();
        let b = Fq2::random();
        let circuit =
            Fq2::mul_by_constant_montgomery(Fq2::wires_set_montgomery(a), Fq2::as_montgomery(b));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq2::from_wires(circuit.0);
        assert_eq!(c, Fq2::as_montgomery(a * b));
    }

    #[test]
    fn test_fq2_mul_by_fq() {
        let a = Fq2::random();
        let b = Fq::random();
        let circuit = Fq2::mul_by_fq(Fq2::wires_set(a), Fq::wires_set(b));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq2::from_wires(circuit.0);
        assert_eq!(c, a * ark_bn254::Fq2::new(b, ark_bn254::Fq::ZERO));
    }

    #[test]
    fn test_fq2_mul_by_fq_montgomery() {
        let a = Fq2::random();
        let b = Fq::random();
        let circuit =
            Fq2::mul_by_fq_montgomery(Fq2::wires_set_montgomery(a), Fq::wires_set_montgomery(b));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq2::from_wires(circuit.0);
        assert_eq!(
            c,
            Fq2::as_montgomery(a * ark_bn254::Fq2::new(b, ark_bn254::Fq::ZERO))
        );
    }

    #[test]
    fn test_fq2_mul_by_constant_fq() {
        let a = Fq2::random();
        let b = Fq::random();
        let circuit = Fq2::mul_by_constant_fq(Fq2::wires_set(a), b);
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq2::from_wires(circuit.0);
        assert_eq!(c, a * ark_bn254::Fq2::new(b, ark_bn254::Fq::ZERO));
    }

    #[test]
    fn test_fq2_mul_by_constant_fq_montgomery() {
        let a = Fq2::random();
        let b = Fq::random();
        let circuit =
            Fq2::mul_by_constant_fq_montgomery(Fq2::wires_set_montgomery(a), Fq::as_montgomery(b));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq2::from_wires(circuit.0);
        assert_eq!(
            c,
            Fq2::as_montgomery(a * ark_bn254::Fq2::new(b, ark_bn254::Fq::ZERO))
        );
    }

    #[test]
    fn test_fq2_mul_by_nonresiude() {
        let a = Fq2::random();
        let circuit = Fq2::mul_by_nonresidue(Fq2::wires_set(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq2::from_wires(circuit.0);
        assert_eq!(c, ark_bn254::Fq6Config::mul_fp2_by_nonresidue(a));
    }

    #[test]
    fn test_fq2_square() {
        let a = Fq2::random();
        let circuit = Fq2::square(Fq2::wires_set(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq2::from_wires(circuit.0);
        assert_eq!(c, a * a);
    }

    #[test]
    fn test_fq2_square_montgomery() {
        let a = Fq2::random();
        let circuit = Fq2::square_montgomery(Fq2::wires_set_montgomery(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq2::from_wires(circuit.0);
        assert_eq!(c, Fq2::as_montgomery(a * a));
    }

    #[test]
    fn test_fq2_inverse() {
        let a = Fq2::random();
        let circuit = Fq2::inverse(Fq2::wires_set(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq2::from_wires(circuit.0);
        assert_eq!(c, a.inverse().unwrap());
    }

    #[test]
    fn test_fq2_inverse_montgomery() {
        let a = Fq2::random();
        let circuit = Fq2::inverse_montgomery(Fq2::wires_set_montgomery(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq2::from_wires(circuit.0);
        assert_eq!(c, Fq2::as_montgomery(a.inverse().unwrap()));
    }

    #[test]
    fn test_fq2_frobenius() {
        let a = Fq2::random();

        let circuit = Fq2::frobenius(Fq2::wires_set(a), 0);
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq2::from_wires(circuit.0);
        assert_eq!(c, a.frobenius_map(0));

        let circuit = Fq2::frobenius(Fq2::wires_set(a), 1);
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq2::from_wires(circuit.0);
        assert_eq!(c, a.frobenius_map(1));
    }

    #[test]
    fn test_fq2_frobenius_montgomery() {
        let a = Fq2::random();

        let circuit = Fq2::frobenius_montgomery(Fq2::wires_set_montgomery(a), 0);
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq2::from_wires(circuit.0);
        assert_eq!(c, Fq2::as_montgomery(a.frobenius_map(0)));

        let circuit = Fq2::frobenius_montgomery(Fq2::wires_set_montgomery(a), 1);
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq2::from_wires(circuit.0);
        assert_eq!(c, Fq2::as_montgomery(a.frobenius_map(1)));
    }

    #[test]
    fn test_fq2_div6() {
        let a = Fq2::random();
        let circuit = Fq2::div6(Fq2::wires_set(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq2::from_wires(circuit.0);
        assert_eq!(c + c + c + c + c + c, a);
    }

    #[test]
    fn test_fq2_exp_by_constant() {
        use ark_ff::PrimeField;

        let ut = |b: u32| {
            let a = Fq2::random();
            let b = ark_bn254::Fq::from(b);

            let expect_a_to_power_of_b = a.pow(b.into_bigint());

            let circuit = Fq2::exp_by_constant_montgomery(
                Fq2::wires_set_montgomery(a),
                ark_bn254::Fq::from(b),
            );
            circuit.gate_counts().print();
            for mut gate in circuit.1 {
                gate.evaluate();
            }
            let c = Fq2::from_montgomery_wires(circuit.0);
            assert_eq!(expect_a_to_power_of_b, c);
        };
        ut(0);
        ut(1);
        ut(u32::rand(&mut test_rng()));
    }

    #[test]
    fn test_fq2_norm_montgomery() {
        let r = Fq2::random();
        println!("r: {}, rr = {}", r, r * r);
        let expected_norm = ark_bn254::Fq::from(r.norm());

        let circuit = Fq2::norm_montgomery(
            Fq::wires_set_montgomery(r.c0.clone()),
            Fq::wires_set_montgomery(r.c1.clone()),
        );
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq::from_wires(circuit.0);
        assert_eq!(c, Fq::as_montgomery(expected_norm));
    }
}
