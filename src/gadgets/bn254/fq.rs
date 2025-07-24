use std::str::FromStr;

use ark_ff::{Field, PrimeField, UniformRand};
use bitvec::vec::BitVec;
use num_bigint::BigUint;

use super::super::{bigint::BigIntWires, bn254::fp254impl::Fp254Impl};
use crate::{
    core::wire,
    gadgets::{self, bigint},
    Circuit, WireId,
};

/// BN254 base field Fq implementation
pub struct Fq;

impl Fp254Impl for Fq {
    const MODULUS: &'static str =
        "21888242871839275222246405745257275088696311157297823662689037894645226208583";
    const MONTGOMERY_M_INVERSE: &'static str =
        "4759646384140481320982610724935209484903937857060724391493050186936685796471";
    const MONTGOMERY_R_INVERSE: &'static str =
        "18289368484950178621272022062020525048389989670507786348948026221581485535495";
    const N_BITS: usize = 254;

    fn half_modulus() -> BigUint {
        BigUint::from(ark_bn254::Fq::from(1) / ark_bn254::Fq::from(2))
    }

    fn one_third_modulus() -> BigUint {
        BigUint::from(ark_bn254::Fq::from(1) / ark_bn254::Fq::from(3))
    }

    fn two_third_modulus() -> BigUint {
        BigUint::from(ark_bn254::Fq::from(2) / ark_bn254::Fq::from(3))
    }
}

impl Fq {
    /// Create new field element wires
    pub fn new_bn(circuit: &mut Circuit, is_input: bool, is_output: bool) -> BigIntWires {
        BigIntWires::new(circuit, Self::N_BITS, is_input, is_output)
    }

    pub fn get_wire_bits_fn(
        wires: &BigIntWires,
        value: &ark_bn254::Fq,
    ) -> Result<impl Fn(WireId) -> Option<bool> + use<>, gadgets::bigint::Error> {
        wires.get_wire_bits_fn(&BigUint::from(value.into_bigint()))
    }

    /// Convert a field element to Montgomery form
    ///
    /// Montgomery form represents a field element `a` as `a * R mod p` where R = 2^254.
    /// This form enables efficient modular multiplication using Montgomery reduction.
    ///
    /// # Arguments
    /// * `a` - Field element in standard form
    ///
    /// # Returns
    /// Field element in Montgomery form (a * R mod p)
    pub fn as_montgomery(a: ark_bn254::Fq) -> ark_bn254::Fq {
        a * ark_bn254::Fq::from(Self::montgomery_r_as_biguint())
    }

    /// Convert a field element from Montgomery form to standard form
    ///
    /// Converts a Montgomery form element `a_mont = a * R mod p` back to standard form `a`.
    ///
    /// # Arguments  
    /// * `a` - Field element in Montgomery form
    ///
    /// # Returns
    /// Field element in standard form
    pub fn from_montgomery(a: ark_bn254::Fq) -> ark_bn254::Fq {
        a / ark_bn254::Fq::from(Self::montgomery_r_as_biguint())
    }

    pub fn to_bits(u: ark_bn254::Fq) -> Vec<bool> {
        let mut bytes = BigUint::from(u).to_bytes_le();
        bytes.extend(vec![0_u8; 32 - bytes.len()]);
        let mut bits = Vec::new();
        for byte in bytes {
            for i in 0..8 {
                bits.push(((byte >> i) & 1) == 1)
            }
        }
        bits.pop();
        bits.pop();
        bits
    }

    pub fn from_bits(bits: Vec<bool>) -> ark_bn254::Fq {
        let zero = BigUint::ZERO;
        let one = BigUint::from(1_u8);
        let mut u = zero.clone();
        for bit in bits.iter().rev() {
            u = u.clone() + u.clone() + if *bit { one.clone() } else { zero.clone() };
        }
        ark_bn254::Fq::from(u)
    }

    pub fn wires(circuit: &mut Circuit) -> BigIntWires {
        BigIntWires::new(circuit, Self::N_BITS, false, false)
    }

    // Check if field element is quadratic non-residue in Montgomery form
    pub fn is_qnr_montgomery(circuit: &mut Circuit, x: BigIntWires) -> WireId {
        // y = x^((p - 1)/2)
        let y = Fq::exp_by_constant_montgomery(
            circuit,
            &x,
            &BigUint::from(ark_bn254::Fq::MODULUS_MINUS_ONE_DIV_TWO),
        );

        let neg_one_mont =
            BigIntWires::new_constant(circuit, Self::N_BITS, &BigUint::from(-ark_bn254::Fq::ONE))
                .unwrap();

        bigint::equal(circuit, &y, &neg_one_mont)
    }

    /// Square root in Montgomery form (assuming input is quadratic residue)
    pub fn sqrt_montgomery(circuit: &mut Circuit, a: &BigIntWires) -> BigIntWires {
        assert_eq!(a.len(), Self::N_BITS);

        Self::exp_by_constant_montgomery(
            circuit,
            a,
            &BigUint::from_str(Self::MODULUS_ADD_1_DIV_4).unwrap(),
        )
    }
}

#[cfg(test)]
pub(super) mod tests {
    use std::collections::HashMap;

    use ark_ff::AdditiveGroup;
    use rand::Rng;
    use test_log::test;

    use super::*;
    use crate::test_utils::trng;

    pub fn rnd() -> ark_bn254::Fq {
        loop {
            if let Some(bn) = ark_bn254::Fq::from_random_bytes(&trng().random::<[u8; 32]>()) {
                return bn;
            }
        }
    }

    #[test]
    fn test_fq_random() {
        let u = rnd();
        println!("u: {u:?}");
        let b = Fq::to_bits(u);
        let v = Fq::from_bits(b);
        println!("v: {v:?}");
        assert_eq!(u, v);
    }

    /// Macro to simplify field operation tests
    macro_rules! test_fq {
        // Unary operation: test_fq!(neg, Fq::neg, |a| -a)
        (unary $name:ident, $op:expr, $ark_op:expr) => {
            #[test_log::test]
            fn $name() {
                let mut circuit = Circuit::default();
                let a = Fq::new_bn(&mut circuit, true, false);
                let c = $op(&mut circuit, &a);
                c.mark_as_output(&mut circuit);

                let a_v = rnd();
                let expected = $ark_op(a_v);

                let a_input = Fq::get_wire_bits_fn(&a, &a_v).unwrap();
                let c_output = Fq::get_wire_bits_fn(&c, &expected).unwrap();
                circuit
                    .simple_evaluate(|wire_id| (a_input)(wire_id))
                    .unwrap()
                    .for_each(|(wire_id, value)| {
                        assert_eq!((c_output)(wire_id), Some(value));
                    });
            }
        };

        // Binary operation: test_fq!(binary add, Fq::add, |a, b| a + b)
        (binary $name:ident, $op:expr, $ark_op:expr) => {
            #[test_log::test]
            fn $name() {
                let mut circuit = Circuit::default();
                let a = Fq::new_bn(&mut circuit, true, false);
                let b = Fq::new_bn(&mut circuit, true, false);
                let c = $op(&mut circuit, &a, &b);
                c.mark_as_output(&mut circuit);

                let a_v = rnd();
                let b_v = rnd();
                let expected = $ark_op(a_v, b_v);

                let a_input = Fq::get_wire_bits_fn(&a, &a_v).unwrap();
                let b_input = Fq::get_wire_bits_fn(&b, &b_v).unwrap();
                let c_output = Fq::get_wire_bits_fn(&c, &expected).unwrap();

                circuit
                    .simple_evaluate(|wire_id| (a_input)(wire_id).or((b_input)(wire_id)))
                    .unwrap()
                    .for_each(|(wire_id, value)| {
                        assert_eq!((c_output)(wire_id), Some(value));
                    });
            }
        };

        // Constant operation: test_fq!(constant add_constant, Fq::add_constant, |a, b| a + b)
        (constant $name:ident, $op:expr, $ark_op:expr) => {
            #[test_log::test]
            fn $name() {
                let mut circuit = Circuit::default();
                let a = Fq::new_bn(&mut circuit, true, false);
                let b_v = rnd();
                let c = $op(&mut circuit, &a, &b_v);
                c.mark_as_output(&mut circuit);

                let a_v = rnd();
                let expected = $ark_op(a_v, b_v);

                let a_input = Fq::get_wire_bits_fn(&a, &a_v).unwrap();
                let c_output = Fq::get_wire_bits_fn(&c, &expected).unwrap();

                circuit
                    .simple_evaluate(|wire_id| (a_input)(wire_id))
                    .unwrap()
                    .for_each(|(wire_id, value)| {
                        assert_eq!((c_output)(wire_id), Some(value));
                    });
            }
        };

        // Custom assertion: test_fq!(custom div6, Fq::div6, |a, c| c + c + c + c + c + c == a)
        (custom $name:ident, $op:expr, $check:expr) => {
            #[test_log::test]
            fn $name() {
                let mut circuit = Circuit::default();
                let a = Fq::new_bn(&mut circuit, true, false);
                let c = $op(&mut circuit, &a);
                c.mark_as_output(&mut circuit);

                let a_v = rnd();

                let a_input = Fq::get_wire_bits_fn(&a, &a_v).unwrap();

                circuit
                    .simple_evaluate(|wire_id| (a_input)(wire_id))
                    .unwrap()
                    .for_each(|(wire_id, value)| {
                        if let Some(c_bit) = circuit.get_wire_value(wire_id) {
                            let c_wire = BigIntWires::from_wire_values(&circuit, c_bit);
                            if let Ok(c_value) = Fq::get_wire_bits_fn(&c_wire, &ark_bn254::Fq::ZERO)
                            {
                                assert!($check(a_v /* extracted c value */,));
                            }
                        }
                    });
            }
        };
    }

    test_fq!(binary test_fq_add, Fq::add, (|a: ark_bn254::Fq, b: ark_bn254::Fq| { a + b }));
    test_fq!(binary test_fq_mul_montgomery, Fq::mul_montgomery, (|a: ark_bn254::Fq, b: ark_bn254::Fq| Fq::as_montgomery(Fq::from_montgomery(a) * Fq::from_montgomery(b))));
    test_fq!(binary test_fq_sub, Fq::sub, (|a: ark_bn254::Fq, b: ark_bn254::Fq| a - b));

    test_fq!(constant test_fq_add_constant, Fq::add_constant, (|a: ark_bn254::Fq, b: ark_bn254::Fq| a + b));

    test_fq!(unary test_fq_double, Fq::double, (|a: ark_bn254::Fq| a + a));
    test_fq!(unary test_fq_half, Fq::half, (|a: ark_bn254::Fq| a / ark_bn254::Fq::from(2u32)));
    test_fq!(unary test_fq_inverse, Fq::inverse, (|a: ark_bn254::Fq| a.inverse().unwrap()));
    test_fq!(unary test_fq_neg, Fq::neg, (|a: ark_bn254::Fq| -a));
    test_fq!(unary test_fq_square_montgomery, Fq::square_montgomery, (|a: ark_bn254::Fq| Fq::as_montgomery(Fq::from_montgomery(a) * Fq::from_montgomery(a))));
    test_fq!(unary test_fq_triple, Fq::triple, (|a: ark_bn254::Fq| a + a + a));

    #[test]
    fn test_fq_mul_by_constant_montgomery() {
        let mut circuit = Circuit::default();

        let a_val = rnd();
        let b_val = rnd();

        let a = Fq::new_bn(&mut circuit, true, false);

        let a_mont = Fq::as_montgomery(a_val);
        let b_mont = Fq::as_montgomery(b_val);

        let c = Fq::mul_by_constant_montgomery(&mut circuit, &a, &b_mont);

        c.mark_as_output(&mut circuit);

        // For Montgomery multiplication: (a_mont * b_mont) * R^-1 = Montgomery(a_val * b_val)
        let expected = Fq::as_montgomery(a_val * b_val);

        let a_input = Fq::get_wire_bits_fn(&a, &a_mont).unwrap();
        let c_output = Fq::get_wire_bits_fn(&c, &expected).unwrap();

        circuit
            .simple_evaluate(a_input)
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((c_output)(wire_id), Some(value));
            });
    }

    #[test]
    fn test_fq_inverse_montgomery() {
        log::debug!("start");
        let mut circuit = Circuit::default();
        let a = Fq::new_bn(&mut circuit, true, false);
        let c = Fq::inverse_montgomery(&mut circuit, &a);
        c.mark_as_output(&mut circuit);

        let a_val = rnd();

        let expected = a_val.inverse().unwrap();

        dbg!((&a_val, &expected));

        let a_input = Fq::get_wire_bits_fn(&a, &Fq::as_montgomery(a_val)).unwrap();
        let c_output = Fq::get_wire_bits_fn(&c, &Fq::as_montgomery(expected)).unwrap();

        let actual_c = circuit
            .simple_evaluate(a_input)
            .unwrap()
            .collect::<HashMap<WireId, bool>>();

        assert_eq!(
            c.to_bitmask(|wire_id| c_output(wire_id).unwrap()),
            c.to_bitmask(|wire_id| *actual_c.get(&wire_id).unwrap())
        );
    }

    #[test]
    fn test_fq_div6() {
        let mut circuit = Circuit::default();
        let a = Fq::new_bn(&mut circuit, true, false);
        let c = Fq::div6(&mut circuit, &a);
        c.mark_as_output(&mut circuit);

        let a_v = rnd();
        let expected_c = a_v / ark_bn254::Fq::from(6u32);

        let a_input = Fq::get_wire_bits_fn(&a, &a_v).unwrap();
        let c_output = Fq::get_wire_bits_fn(&c, &expected_c).unwrap();

        circuit
            .simple_evaluate(a_input)
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((c_output)(wire_id), Some(value));
            });
    }

    #[test]
    fn test_fq_mul_by_constant_montgomery_one() {
        let mut circuit = Circuit::default();
        let a = Fq::new_bn(&mut circuit, true, false);
        let c = Fq::mul_by_constant_montgomery(
            &mut circuit,
            &a,
            &Fq::as_montgomery(ark_bn254::Fq::ONE),
        );
        c.mark_as_output(&mut circuit);

        let a_v = Fq::as_montgomery(rnd());
        let expected_c = a_v; // a * 1 = a

        let a_input = Fq::get_wire_bits_fn(&a, &a_v).unwrap();
        let c_output = Fq::get_wire_bits_fn(&c, &expected_c).unwrap();

        circuit
            .simple_evaluate(a_input)
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((c_output)(wire_id), Some(value));
            });
    }

    #[test]
    fn test_fq_mul_by_constant_montgomery_zero() {
        let mut circuit = Circuit::default();
        let a = Fq::new_bn(&mut circuit, true, false);
        let c = Fq::mul_by_constant_montgomery(
            &mut circuit,
            &a,
            &Fq::as_montgomery(ark_bn254::Fq::ZERO),
        );
        c.mark_as_output(&mut circuit);

        let a_v = Fq::as_montgomery(rnd());
        let expected_c = Fq::as_montgomery(ark_bn254::Fq::ZERO); // a * 0 = 0

        let a_input = Fq::get_wire_bits_fn(&a, &a_v).unwrap();
        let c_output = Fq::get_wire_bits_fn(&c, &expected_c).unwrap();

        circuit
            .simple_evaluate(a_input)
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((c_output)(wire_id), Some(value));
            });
    }

    #[test]
    fn test_fq_montgomery_reduce() {
        let mut circuit = Circuit::default();

        // Create a 508-bit input (2 * 254 bits) for montgomery_reduce
        let x = BigIntWires::new(&mut circuit, 2 * Fq::N_BITS, true, false);
        let result = Fq::montgomery_reduce(&mut circuit, &x);
        result.mark_as_output(&mut circuit);

        // Test with a random value multiplied by R (to create valid Montgomery form input)
        let a_v = rnd();
        let b_v = rnd();
        let product = a_v * b_v;
        let montgomery_product = Fq::as_montgomery(product);

        // Create input that represents the double-width multiplication result
        let input_value = BigUint::from(montgomery_product) * Fq::montgomery_r_as_biguint();

        // Expected result is the Montgomery form of the product
        let expected = montgomery_product;

        let x_input = x.get_wire_bits_fn(&input_value).unwrap();
        let result_output = Fq::get_wire_bits_fn(&result, &expected).unwrap();

        circuit
            .simple_evaluate(x_input)
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((result_output)(wire_id), Some(value));
            });
    }

    #[test]
    fn test_fq_sqrt_montgomery() {
        let mut circuit = Circuit::default();
        let aa_wire = Fq::new_bn(&mut circuit, true, false);
        let c = Fq::sqrt_montgomery(&mut circuit, &aa_wire);
        c.mark_as_output(&mut circuit);

        let a_v = rnd();
        let aa_v = a_v * a_v; // Perfect square
        let aa_montgomery = Fq::as_montgomery(aa_v);

        // Expected result: if a.legendre().is_qnr() then -a else a
        let expected_c = match a_v.legendre().is_qnr() {
            true => Fq::as_montgomery(-a_v),
            false => Fq::as_montgomery(a_v),
        };

        let aa_input = Fq::get_wire_bits_fn(&aa_wire, &aa_montgomery).unwrap();
        let c_output = Fq::get_wire_bits_fn(&c, &expected_c).unwrap();

        circuit
            .simple_evaluate(aa_input)
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((c_output)(wire_id), Some(value));
            });
    }
}
