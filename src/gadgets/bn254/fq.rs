use std::{
    ops::{Deref, DerefMut},
    str::FromStr,
};

use ark_ff::{Field, PrimeField};
use num_bigint::BigUint;
use rand::Rng;

use super::super::{bigint::BigIntWires, bn254::fp254impl::Fp254Impl};
use crate::{
    CircuitContext, WireId,
    circuit::{FromWires, WiresObject},
    gadgets::{
        self,
        bigint::{self, Error},
    },
};

/// BN254 base field Fq implementation
#[derive(Clone, Debug)]
pub struct Fq(pub BigIntWires);

impl Deref for Fq {
    type Target = BigIntWires;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Fq {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl WiresObject for Fq {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.0.iter().copied().collect()
    }

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        Self(self.0.clone_from(wire_gen))
    }
}

impl FromWires for Fq {
    fn from_wires(wires: &[WireId]) -> Option<Self> {
        Some(Self(crate::gadgets::bigint::BigIntWires::from_bits(
            wires.iter().copied(),
        )))
    }
}

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
    pub fn random(rng: &mut impl Rng) -> ark_bn254::Fq {
        let bytes: [u8; 31] = rng.r#gen();
        ark_bn254::Fq::from_random_bytes(&bytes).unwrap()
    }

    pub fn new_constant(u: &ark_bn254::Fq) -> Result<Fq, Error> {
        Ok(Fq(BigIntWires::new_constant(
            Self::N_BITS,
            &BigUint::from(u.into_bigint()),
        )?))
    }

    pub fn from_ctx<C: CircuitContext>(circuit: &mut C) -> Fq {
        Fq(BigIntWires::from_ctx(circuit, Self::N_BITS))
    }

    pub fn new(issue: impl FnMut() -> WireId) -> Fq {
        Fq(BigIntWires::new(issue, Self::N_BITS))
    }

    pub fn get_wire_bits_fn(
        wires: &Fq,
        value: &ark_bn254::Fq,
    ) -> Result<impl Fn(WireId) -> Option<bool> + use<>, gadgets::bigint::Error> {
        wires
            .0
            .get_wire_bits_fn(&BigUint::from(value.into_bigint()))
    }

    /// Convert field element wires to a bitmask string for debugging
    ///
    /// # Arguments
    /// * `wires` - The field element wires
    /// * `get_val` - Function to get the boolean value of a wire
    ///
    /// # Returns
    /// String representation of the field element as bits
    pub fn to_bitmask(wires: &Fq, get_val: impl Fn(WireId) -> bool) -> String {
        wires.0.to_bitmask(&get_val)
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

    pub fn wires<C: CircuitContext>(circuit: &mut C) -> Fq {
        Fq(BigIntWires::from_ctx(circuit, Self::N_BITS))
    }

    // Check if field element is quadratic non-residue in Montgomery form
    //
    pub fn is_qnr_montgomery<C: CircuitContext>(circuit: &mut C, x: &Fq) -> WireId {
        // y = x^((p - 1)/2)
        let y = Fq::exp_by_constant_montgomery(
            circuit,
            x,
            &BigUint::from(ark_bn254::Fq::MODULUS_MINUS_ONE_DIV_TWO),
        );

        let neg_one_mont = Fq(BigIntWires::new_constant(
            Self::N_BITS,
            &BigUint::from(Fq::as_montgomery(-ark_bn254::Fq::ONE)),
        )
        .unwrap());

        bigint::equal(circuit, &y.0, &neg_one_mont.0)
    }

    // Field arithmetic methods (directly using Fp254Impl trait methods)
    pub fn add(circuit: &mut impl crate::CircuitContext, a: &Fq, b: &Fq) -> Fq {
        Fq(<Self as Fp254Impl>::add(circuit, &a.0, &b.0))
    }

    pub fn add_constant(circuit: &mut impl crate::CircuitContext, a: &Fq, b: &ark_bn254::Fq) -> Fq {
        Fq(<Self as Fp254Impl>::add_constant(circuit, &a.0, b))
    }

    pub fn sub(circuit: &mut impl crate::CircuitContext, a: &Fq, b: &Fq) -> Fq {
        Fq(<Self as Fp254Impl>::sub(circuit, &a.0, &b.0))
    }

    pub fn neg(circuit: &mut impl crate::CircuitContext, a: &Fq) -> Fq {
        Fq(<Self as Fp254Impl>::neg(circuit, &a.0))
    }

    pub fn double(circuit: &mut impl crate::CircuitContext, a: &Fq) -> Fq {
        Fq(<Self as Fp254Impl>::double(circuit, &a.0))
    }

    pub fn half(circuit: &mut impl crate::CircuitContext, a: &Fq) -> Fq {
        Fq(<Self as Fp254Impl>::half(circuit, &a.0))
    }

    pub fn triple(circuit: &mut impl crate::CircuitContext, a: &Fq) -> Fq {
        Fq(<Self as Fp254Impl>::triple(circuit, &a.0))
    }

    pub fn div6(circuit: &mut impl crate::CircuitContext, a: &Fq) -> Fq {
        Fq(<Self as Fp254Impl>::div6(circuit, &a.0))
    }

    pub fn inverse(circuit: &mut impl crate::CircuitContext, a: &Fq) -> Fq {
        Fq(<Self as Fp254Impl>::inverse(circuit, &a.0))
    }

    pub fn mul_montgomery(circuit: &mut impl crate::CircuitContext, a: &Fq, b: &Fq) -> Fq {
        Fq(<Self as Fp254Impl>::mul_montgomery(circuit, &a.0, &b.0))
    }

    pub fn mul_by_constant_montgomery(
        circuit: &mut impl crate::CircuitContext,
        a: &Fq,
        b: &ark_bn254::Fq,
    ) -> Fq {
        Fq(<Self as Fp254Impl>::mul_by_constant_montgomery(
            circuit, &a.0, b,
        ))
    }

    pub fn square_montgomery(circuit: &mut impl crate::CircuitContext, a: &Fq) -> Fq {
        Fq(<Self as Fp254Impl>::square_montgomery(circuit, &a.0))
    }

    pub fn montgomery_reduce(circuit: &mut impl crate::CircuitContext, x: &BigIntWires) -> Fq {
        Fq(<Self as Fp254Impl>::montgomery_reduce(circuit, x))
    }

    pub fn inverse_montgomery(circuit: &mut impl crate::CircuitContext, a: &Fq) -> Fq {
        Fq(<Self as Fp254Impl>::inverse_montgomery(circuit, &a.0))
    }

    pub fn exp_by_constant_montgomery(
        circuit: &mut impl crate::CircuitContext,
        a: &Fq,
        exp: &BigUint,
    ) -> Fq {
        Fq(<Self as Fp254Impl>::exp_by_constant_montgomery(
            circuit, &a.0, exp,
        ))
    }

    pub fn multiplexer(
        circuit: &mut impl crate::CircuitContext,
        a: &[Fq],
        s: &[WireId],
        w: usize,
    ) -> Fq {
        let bigint_array: Vec<BigIntWires> = a.iter().map(|fq| fq.0.clone()).collect();
        Fq(<Self as Fp254Impl>::multiplexer(
            circuit,
            &bigint_array,
            s,
            w,
        ))
    }

    pub fn equal_constant(
        circuit: &mut impl crate::CircuitContext,
        a: &Fq,
        b: &ark_bn254::Fq,
    ) -> WireId {
        <Self as Fp254Impl>::equal_constant(circuit, &a.0, b)
    }

    /// Square root in Montgomery form (assuming input is quadratic residue)
    pub fn sqrt_montgomery<C: CircuitContext>(circuit: &mut C, a: &Fq) -> Fq {
        assert_eq!(a.0.len(), Self::N_BITS);

        Self::exp_by_constant_montgomery(
            circuit,
            a,
            &BigUint::from_str(Self::MODULUS_ADD_1_DIV_4).unwrap(),
        )
    }
}

#[cfg(test)]
pub(super) mod tests {
    use std::{array, iter};

    use ark_ff::AdditiveGroup;
    use rand::Rng;
    use test_log::test;
    use tracing::trace;

    use super::*;
    use crate::{
        circuit::{
            CircuitBuilder, CircuitInput, CircuitMode, CircuitOutput, EncodeInput,
            modes::ExecuteMode,
        },
        gadgets::{
            bigint::{BigUint as BigUintOutput, bits_from_biguint_with_len},
            bn254::fp254impl::Fp254Impl,
        },
        test_utils::trng,
    };

    // Input struct for Fq tests
    struct FqInput<const N: usize> {
        values: [ark_bn254::Fq; N],
    }

    impl<const N: usize> FqInput<N> {
        fn new(values: [ark_bn254::Fq; N]) -> Self {
            Self { values }
        }
    }

    impl<const N: usize> CircuitInput for FqInput<N> {
        type WireRepr = [Fq; N];

        fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
            array::from_fn(|_| Fq::new(&mut issue))
        }

        fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
            repr.iter().flat_map(|fq| fq.0.iter().copied()).collect()
        }
    }

    impl<const N: usize, M: CircuitMode<WireValue = bool>> EncodeInput<M> for FqInput<N> {
        fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
            self.values
                .iter()
                .zip(repr.iter())
                .for_each(|(val, fq_wires)| {
                    let bits =
                        bits_from_biguint_with_len(&BigUint::from(val.into_bigint()), Fq::N_BITS)
                            .unwrap();
                    fq_wires.0.iter().zip(bits).for_each(|(w, b)| {
                        cache.feed_wire(*w, b);
                    });
                });
        }
    }

    // Output struct for Fq tests
    struct FqOutput {
        value: ark_bn254::Fq,
    }

    impl CircuitOutput<ExecuteMode> for FqOutput {
        type WireRepr = Fq;

        fn decode(wires: Self::WireRepr, cache: &mut ExecuteMode) -> Self {
            // Decode BigIntWires to BigUint, then convert to ark_bn254::Fq
            let biguint = BigUintOutput::decode(wires.0, cache);
            let value = ark_bn254::Fq::from(biguint);
            Self { value }
        }
    }

    pub fn rnd() -> ark_bn254::Fq {
        loop {
            if let Some(bn) = ark_bn254::Fq::from_random_bytes(&trng().r#gen::<[u8; 32]>()) {
                return bn;
            }
        }
    }

    fn random() -> ark_bn254::Fq {
        Fq::random(&mut trng())
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
        // Unary operation: test_fq!(unary neg, Fq::neg, |a| -a)
        (unary $name:ident, $op:expr, $ark_op:expr) => {
            #[test_log::test]
            fn $name() {
                let a_v = rnd();
                let expected = $ark_op(a_v);
                let input = FqInput::new([a_v]);

                let result = CircuitBuilder::streaming_execute::<_, _, FqOutput>(
                    input,
                    10_000,
                    |ctx, input| {
                        let [a] = input;
                        $op(ctx, a)
                    },
                );

                assert_eq!(result.output_value.value, expected);
            }
        };

        // Binary operation: test_fq!(binary add, Fq::add, |a, b| a + b)
        (binary $name:ident, $op:expr, $ark_op:expr) => {
            #[test_log::test]
            fn $name() {
                let a_v = rnd();
                let b_v = rnd();
                let expected = $ark_op(a_v, b_v);
                let input = FqInput::new([a_v, b_v]);

                let result = CircuitBuilder::streaming_execute::<_, _, FqOutput>(
                    input,
                    10_000,
                    |ctx, input| {
                        let [a, b] = input;
                        $op(ctx, a, b)
                    },
                );

                assert_eq!(result.output_value.value, expected);
            }
        };

        // Constant operation: test_fq!(constant add_constant, Fq::add_constant, |a, b| a + b)
        (constant $name:ident, $op:expr, $ark_op:expr) => {
            #[test_log::test]
            fn $name() {
                let a_v = rnd();
                let b_v = rnd();
                let expected = $ark_op(a_v, b_v);
                let input = FqInput::new([a_v]);

                let result = CircuitBuilder::streaming_execute::<_, _, FqOutput>(
                    input,
                    10_000,
                    |ctx, input| {
                        let [a] = input;
                        $op(ctx, a, &b_v)
                    },
                );

                assert_eq!(result.output_value.value, expected);
            }
        };

        // Montgomery unary operation: test_fq!(montgomery_unary square_montgomery, Fq::square_montgomery, |a| a * a)
        (montgomery_unary $name:ident, $op:expr, $ark_op:expr) => {
            #[test_log::test]
            fn $name() {
                let a_v = rnd();
                let a_mont = Fq::as_montgomery(a_v);
                let expected = Fq::as_montgomery($ark_op(a_v));
                let input = FqInput::new([a_mont]);

                let result = CircuitBuilder::streaming_execute::<_, _, FqOutput>(
                    input,
                    10_000,
                    |ctx, input| {
                        let [a] = input;
                        $op(ctx, a)
                    },
                );

                assert_eq!(result.output_value.value, expected);
            }
        };

        // Montgomery binary operation: test_fq!(montgomery_binary mul_montgomery, Fq::mul_montgomery, |a, b| a * b)
        (montgomery_binary $name:ident, $op:expr, $ark_op:expr) => {
            #[test_log::test]
            fn $name() {
                let a_v = rnd();
                let b_v = rnd();
                let a_mont = Fq::as_montgomery(a_v);
                let b_mont = Fq::as_montgomery(b_v);
                let expected = Fq::as_montgomery($ark_op(a_v, b_v));
                let input = FqInput::new([a_mont, b_mont]);

                let result = CircuitBuilder::streaming_execute::<_, _, FqOutput>(
                    input,
                    10_000,
                    |ctx, input| {
                        let [a, b] = input;
                        $op(ctx, a, b)
                    },
                );

                assert_eq!(result.output_value.value, expected);
            }
        };

        // Montgomery constant operation: test_fq!(montgomery_constant mul_by_constant_montgomery, Fq::mul_by_constant_montgomery, |a, b| a * b)
        (montgomery_constant $name:ident, $op:expr, $ark_op:expr) => {
            #[test_log::test]
            fn $name() {
                let a_v = rnd();
                let b_v = rnd();
                let a_mont = Fq::as_montgomery(a_v);
                let b_mont = Fq::as_montgomery(b_v);
                let expected = Fq::as_montgomery($ark_op(a_v, b_v));
                let input = FqInput::new([a_mont]);

                let result = CircuitBuilder::streaming_execute::<_, _, FqOutput>(
                    input,
                    10_000,
                    |ctx, input| {
                        let [a] = input;
                        $op(ctx, a, &b_mont)
                    },
                );

                assert_eq!(result.output_value.value, expected);
            }
        };

        // Property-based test: test_fq!(property associative_add, |a, b, c| (a + b) + c == a + (b + c))
        (property $name:ident, $property:expr) => {
            #[test_log::test]
            fn $name() {
                for _ in 0..10 {
                    let a = rnd();
                    let b = rnd();
                    let c = rnd();
                    assert!($property(a, b, c));
                }
            }
        };

        // Montgomery property test: test_fq!(montgomery_property conversion_roundtrip, |a| Fq::from_montgomery(Fq::as_montgomery(a)) == a)
        (montgomery_property $name:ident, $property:expr) => {
            #[test_log::test]
            fn $name() {
                for _ in 0..10 {
                    let a = rnd();
                    assert!($property(a));
                }
            }
        };
    }

    // Standard field operations
    test_fq!(binary test_fq_add, Fq::add, (|a: ark_bn254::Fq, b: ark_bn254::Fq| { a + b }));
    test_fq!(binary test_fq_sub, Fq::sub, (|a: ark_bn254::Fq, b: ark_bn254::Fq| a - b));
    test_fq!(constant test_fq_add_constant, Fq::add_constant, (|a: ark_bn254::Fq, b: ark_bn254::Fq| a + b));

    test_fq!(unary test_fq_double, Fq::double, (|a: ark_bn254::Fq| a + a));
    test_fq!(unary test_fq_half, Fq::half, (|a: ark_bn254::Fq| a / ark_bn254::Fq::from(2u32)));
    test_fq!(unary test_fq_inverse, Fq::inverse, (|a: ark_bn254::Fq| a.inverse().unwrap()));
    test_fq!(unary test_fq_neg, Fq::neg, (|a: ark_bn254::Fq| -a));
    test_fq!(unary test_fq_triple, Fq::triple, (|a: ark_bn254::Fq| a + a + a));

    // Montgomery form operations
    test_fq!(montgomery_binary test_fq_mul_montgomery, Fq::mul_montgomery, (|a: ark_bn254::Fq, b: ark_bn254::Fq| a * b));
    test_fq!(montgomery_unary test_fq_square_montgomery, Fq::square_montgomery, (|a: ark_bn254::Fq| a * a));
    test_fq!(montgomery_constant test_fq_mul_by_constant_montgomery, Fq::mul_by_constant_montgomery, (|a: ark_bn254::Fq, b: ark_bn254::Fq| a * b));

    // Property-based tests for algebraic properties
    test_fq!(property test_fq_add_associative, (|a: ark_bn254::Fq, b: ark_bn254::Fq, c: ark_bn254::Fq| (a + b) + c == a + (b + c)));
    test_fq!(property test_fq_add_commutative, (|a: ark_bn254::Fq, b: ark_bn254::Fq, _c: ark_bn254::Fq| a + b == b + a));
    test_fq!(property test_fq_mul_associative, (|a: ark_bn254::Fq, b: ark_bn254::Fq, c: ark_bn254::Fq| (a * b) * c == a * (b * c)));
    test_fq!(property test_fq_mul_commutative, (|a: ark_bn254::Fq, b: ark_bn254::Fq, _c: ark_bn254::Fq| a * b == b * a));
    test_fq!(property test_fq_distributive, (|a: ark_bn254::Fq, b: ark_bn254::Fq, c: ark_bn254::Fq| a * (b + c) == a * b + a * c));

    // Montgomery form property tests
    test_fq!(montgomery_property test_fq_montgomery_roundtrip, (|a: ark_bn254::Fq| Fq::from_montgomery(Fq::as_montgomery(a)) == a));
    test_fq!(montgomery_property test_fq_montgomery_zero, (|_a: ark_bn254::Fq| Fq::as_montgomery(ark_bn254::Fq::ZERO) != ark_bn254::Fq::ZERO || ark_bn254::Fq::ZERO == ark_bn254::Fq::ZERO));
    test_fq!(montgomery_property test_fq_montgomery_one, (|_a: ark_bn254::Fq| Fq::from_montgomery(Fq::as_montgomery(ark_bn254::Fq::ONE)) == ark_bn254::Fq::ONE));

    // Additional Montgomery operations
    test_fq!(montgomery_unary test_fq_inverse_montgomery, Fq::inverse_montgomery, (|a: ark_bn254::Fq| a.inverse().unwrap()));

    // Special operations
    test_fq!(unary test_fq_div6, Fq::div6, (|a: ark_bn254::Fq| a / ark_bn254::Fq::from(6u32)));

    #[test]
    fn test_fq_montgomery_reduce() {
        // Test with a random value multiplied by R (to create valid Montgomery form input)
        let a_v = rnd();
        let b_v = rnd();
        let product = a_v * b_v;
        let montgomery_product = Fq::as_montgomery(product);

        // Create input that represents the double-width multiplication result
        let input_value = BigUint::from(montgomery_product) * Fq::montgomery_r_as_biguint();

        // Expected result is the Montgomery form of the product
        let expected = montgomery_product;

        // Create custom input for BigIntWires
        struct BigIntInput {
            len: usize,
            value: BigUint,
        }

        impl CircuitInput for BigIntInput {
            type WireRepr = BigIntWires;

            fn allocate(&self, issue: impl FnMut() -> WireId) -> Self::WireRepr {
                BigIntWires::new(issue, self.len)
            }

            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                repr.iter().copied().collect()
            }
        }

        impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for BigIntInput {
            fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
                assert_eq!(repr.len(), self.len);

                repr.iter()
                    .zip(
                        bits_from_biguint_with_len(&self.value, self.len)
                            .unwrap()
                            .into_iter()
                            .chain(iter::repeat(false)),
                    )
                    .for_each(|(w, b)| {
                        trace!("we feed wire={w:?} to {b}");
                        cache.feed_wire(*w, b);
                    });
            }
        }

        let input = BigIntInput {
            len: Fq::N_BITS * 2,
            value: input_value,
        };

        let result =
            CircuitBuilder::streaming_execute::<_, _, FqOutput>(input, 10_000, |ctx, x| {
                Fq::montgomery_reduce(ctx, x)
            });

        assert_eq!(result.output_value.value, expected);
    }

    #[test]
    fn test_fq_sqrt_montgomery() {
        let a_v = rnd();
        let aa_v = a_v * a_v; // Perfect square
        let aa_montgomery = Fq::as_montgomery(aa_v);

        // Expected result: if a.legendre().is_qnr() then -a else a
        let expected_c = match a_v.legendre().is_qnr() {
            true => Fq::as_montgomery(-a_v),
            false => Fq::as_montgomery(a_v),
        };

        let input = FqInput::new([aa_montgomery]);

        let result =
            CircuitBuilder::streaming_execute::<_, _, FqOutput>(input, 10_000, |ctx, input| {
                let [aa_wire] = input;
                Fq::sqrt_montgomery(ctx, aa_wire)
            });

        assert_eq!(result.output_value.value, expected_c);
    }

    #[test]
    fn test_fq_multiplexer() {
        let w = 1;
        let n = 2_usize.pow(w as u32);
        let a_val = (0..n).map(|_| random()).collect::<Vec<_>>();
        let s_val = (0..w).map(|_| trng().r#gen()).collect::<Vec<_>>();

        let mut u = 0;
        for i in s_val.iter().rev() {
            u = u + u + if *i { 1 } else { 0 };
        }
        let expected = a_val[u];

        // Create custom input for multiplexer
        struct MultiplexerInput {
            a_values: Vec<ark_bn254::Fq>,
            s_values: Vec<bool>,
            w: usize,
        }

        impl CircuitInput for MultiplexerInput {
            type WireRepr = (Vec<Fq>, Vec<WireId>);

            fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
                let a = self.a_values.iter().map(|_| Fq::new(&mut issue)).collect();
                let s = (0..self.w).map(|_| (issue)()).collect();
                (a, s)
            }

            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                let (a, s) = repr;
                a.iter()
                    .flat_map(|fq| fq.0.iter().copied())
                    .chain(s.iter().copied())
                    .collect()
            }
        }

        impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for MultiplexerInput {
            fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
                let (a, s) = repr;
                // Encode a values
                for (fq_wires, val) in a.iter().zip(self.a_values.iter()) {
                    let bits =
                        bits_from_biguint_with_len(&BigUint::from(val.into_bigint()), Fq::N_BITS)
                            .unwrap();
                    fq_wires.0.iter().zip(bits).for_each(|(w, b)| {
                        cache.feed_wire(*w, b);
                    });
                }
                // Encode s values
                for (wire, val) in s.iter().zip(self.s_values.iter()) {
                    cache.feed_wire(*wire, *val);
                }
            }
        }

        let input = MultiplexerInput {
            a_values: a_val.clone(),
            s_values: s_val,
            w,
        };

        let result =
            CircuitBuilder::streaming_execute::<_, _, FqOutput>(input, 10_000, |ctx, input| {
                let (a, s) = input;
                Fq::multiplexer(ctx, a, s, w)
            });

        assert_eq!(result.output_value.value, expected);
    }
}
