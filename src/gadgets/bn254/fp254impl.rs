use std::str::FromStr;

use ark_ff::{AdditiveGroup, Field, PrimeField};
use circuit_component_macro::bn_component;
use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::{One, Zero};

use super::super::bigint::{self, BigIntWires};
use crate::{
    CircuitContext, Gate, WireId,
    circuit::{FALSE_WIRE, FromWires, TRUE_WIRE, WiresObject},
    math::montgomery::calculate_montgomery_constants,
};

/// Core trait for BN254 field implementation with 254-bit prime field arithmetic
/// Provides constants and operations for field elements in Montgomery form
pub trait Fp254Impl {
    /// The prime modulus for the field
    const MODULUS: &'static str;

    /// Montgomery constant R = 2^254
    const MONTGOMERY_R: &'static str =
        "28948022309329048855892746252171976963317496166410141009864396001978282409984";

    /// MODULUS^-1 modulo R  
    const MONTGOMERY_M_INVERSE: &'static str;

    /// R^-1 modulo MODULUS
    const MONTGOMERY_R_INVERSE: &'static str;

    /// Number of bits in field elements
    const N_BITS: usize;

    /// (MODULUS+1)/4 for square root operations
    const MODULUS_ADD_1_DIV_4: &'static str =
        "5472060717959818805561601436314318772174077789324455915672259473661306552146";

    /// Convert modulus string to BigUint
    fn modulus_as_biguint() -> BigUint {
        BigUint::from_str(Self::MODULUS).unwrap()
    }

    /// Convert Montgomery R to BigUint
    fn montgomery_r_as_biguint() -> BigUint {
        BigUint::from_str(Self::MONTGOMERY_R).unwrap()
    }

    /// Convert Montgomery modulus inverse to BigUint
    fn montgomery_m_inverse_as_biguint() -> BigUint {
        BigUint::from_str(Self::MONTGOMERY_M_INVERSE).unwrap()
    }

    /// Convert Montgomery R inverse to BigUint
    fn montgomery_r_inverse_as_biguint() -> BigUint {
        BigUint::from_str(Self::MONTGOMERY_R_INVERSE).unwrap()
    }

    /// Calculate 2^N_BITS - MODULUS
    fn not_modulus_as_biguint() -> BigUint {
        let p = Self::modulus_as_biguint();
        let a = BigUint::from(2u32).pow(Self::N_BITS.try_into().unwrap());
        a - p
    }

    /// Half of the modulus for efficient division by 2
    fn half_modulus() -> BigUint;

    /// One third of the modulus for division by 6
    fn one_third_modulus() -> BigUint;

    /// Two thirds of the modulus for division by 6
    fn two_third_modulus() -> BigUint;

    /// Validate Montgomery constants are correct
    fn validate_montgomery_constants() -> bool {
        let modulus = Self::modulus_as_biguint();
        let r = Self::montgomery_r_as_biguint();
        let (r_inv_calc, m_inv_calc) = calculate_montgomery_constants(modulus.clone(), r.clone());

        let r_inv_expected = Self::montgomery_r_inverse_as_biguint();
        let m_inv_expected = Self::montgomery_m_inverse_as_biguint();

        r_inv_calc == r_inv_expected && m_inv_calc == m_inv_expected
    }

    fn equal_constant<C: CircuitContext>(
        circuit: &mut C,
        a: &BigIntWires,
        b: &ark_bn254::Fq,
    ) -> WireId {
        bigint::equal_constant(circuit, a, &BigUint::from(b.into_bigint()))
    }

    #[bn_component(arity = "Self::N_BITS")]
    fn add<C: CircuitContext>(circuit: &mut C, a: &BigIntWires, b: &BigIntWires) -> BigIntWires {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(b.len(), Self::N_BITS);

        let mut wires1 = bigint::add(circuit, a, b);
        let u = wires1.pop().unwrap();

        let mut wires2 = bigint::add_constant(circuit, &wires1, &Self::not_modulus_as_biguint());

        wires2.pop();

        let v = bigint::less_than_constant(circuit, &wires1, &Self::modulus_as_biguint());
        let s = circuit.issue_wire();

        circuit.add_gate(Gate::and_variant(u, v, s, [true, false, false]));

        bigint::select(circuit, &wires1, &wires2, s)
    }

    #[bn_component(arity = "Self::N_BITS", offcircuit_args = "b")]
    fn add_constant<C: CircuitContext>(
        circuit: &mut C,
        a: &BigIntWires,
        b: &ark_bn254::Fq,
    ) -> BigIntWires {
        assert_eq!(a.len(), Self::N_BITS);
        if b.is_zero() {
            return (*a).clone();
        }

        let mut wires_1 = bigint::add_constant(circuit, a, &BigUint::from(*b));
        let u = wires_1.pop().unwrap();
        let mut wires_2 = bigint::add_constant(circuit, &wires_1, &Self::not_modulus_as_biguint());

        wires_2.pop();

        let v = bigint::less_than_constant(circuit, &wires_1, &Self::modulus_as_biguint());

        let s = circuit.issue_wire();

        circuit.add_gate(Gate::and_variant(u, v, s, [true, false, false]));

        bigint::select(circuit, &wires_1, &wires_2, s)
    }

    /// Field subtraction: (a - b) mod p
    #[bn_component(arity = "Self::N_BITS")]
    fn sub<C: CircuitContext>(circuit: &mut C, a: &BigIntWires, b: &BigIntWires) -> BigIntWires {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(b.len(), Self::N_BITS);

        let neg_b = Self::neg(circuit, b);
        Self::add(circuit, a, &neg_b)
    }

    /// Field negation: (-a) mod p
    #[bn_component(arity = "Self::N_BITS")]
    fn neg<C: CircuitContext>(circuit: &mut C, a: &BigIntWires) -> BigIntWires {
        assert_eq!(a.len(), Self::N_BITS);

        let not_a = BigIntWires::from_ctx(circuit, a.len());
        not_a.iter().zip(a.iter()).for_each(|(not_a, a_i)| {
            circuit.add_gate(Gate::xor(*a_i, TRUE_WIRE, *not_a));
        });

        Self::add_constant(
            circuit,
            &not_a,
            &(ark_bn254::Fq::from(1) - ark_bn254::Fq::from(Self::not_modulus_as_biguint())),
        )
    }

    /// Field doubling: (2 * a) mod p
    #[bn_component(arity = "Self::N_BITS")]
    fn double<C: CircuitContext>(circuit: &mut C, a: &BigIntWires) -> BigIntWires {
        assert_eq!(a.len(), Self::N_BITS);

        let shift_wire = FALSE_WIRE;

        let mut shifted_a = (*a).clone();
        let u = shifted_a.pop().unwrap();
        shifted_a.insert(0, shift_wire);

        let mut wires_2 =
            bigint::add_constant(circuit, &shifted_a, &Self::not_modulus_as_biguint());
        wires_2.pop();

        let v = bigint::less_than_constant(circuit, &shifted_a, &Self::modulus_as_biguint());

        let s = circuit.issue_wire();
        circuit.add_gate(Gate::and_variant(u, v, s, [true, false, false]));

        bigint::select(circuit, &shifted_a, &wires_2, s)
    }

    /// Field halving: (a / 2) mod p
    #[bn_component(arity = "Self::N_BITS")]
    fn half<C: CircuitContext>(circuit: &mut C, a: &BigIntWires) -> BigIntWires {
        assert_eq!(a.len(), Self::N_BITS);

        let selector = a.get(0).unwrap();
        let wires_1 = bigint::half(circuit, a);
        let wires_2 = bigint::add_constant_without_carry(circuit, &wires_1, &Self::half_modulus());

        bigint::select(circuit, &wires_2, &wires_1, selector)
    }

    /// Montgomery multiplication for circuit wires
    ///
    /// Performs multiplication of two field elements in Montgomery form:
    /// `(a_mont * b_mont) * R^-1 mod p` where both inputs are in Montgomery form.
    /// The result is also in Montgomery form.
    ///
    /// # Arguments
    /// * `circuit` - Circuit to add gates to
    /// * `a` - First operand in Montgomery form
    /// * `b` - Second operand in Montgomery form
    ///
    /// # Returns
    /// Product in Montgomery form
    fn mul_montgomery<C: CircuitContext>(
        circuit: &mut C,
        a: &BigIntWires,
        b: &BigIntWires,
    ) -> BigIntWires {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(b.len(), Self::N_BITS);

        let mul_result = bigint::mul(circuit, a, b);
        Self::montgomery_reduce(circuit, &mul_result)
    }

    /// Convert field element to Montgomery form
    ///
    /// # Arguments
    /// * `a` - Field element in standard form
    ///
    /// # Returns
    /// Field element in Montgomery form (a * R mod p)
    fn as_montgomery(a: ark_bn254::Fq) -> ark_bn254::Fq {
        a * ark_bn254::Fq::from(Self::montgomery_r_as_biguint())
    }

    /// Montgomery multiplication by constant for circuit wires
    ///
    /// Multiplies a Montgomery form wire by a standard form constant:
    /// `(a_mont * b) * R^-1 mod p` where `a_mont` is in Montgomery form and `b` is standard.
    /// The result is in Montgomery form.
    ///
    /// # Arguments
    /// * `circuit` - Circuit to add gates to
    /// * `a` - Wire in Montgomery form
    /// * `b` - Constant in standard form
    ///
    /// # Returns
    /// Product in Montgomery form
    #[bn_component(arity = "Self::N_BITS", offcircuit_args = "b")]
    fn mul_by_constant_montgomery<C: CircuitContext>(
        circuit: &mut C,
        a: &BigIntWires,
        b: &ark_bn254::Fq,
    ) -> BigIntWires {
        assert_eq!(a.len(), Self::N_BITS);

        if b == &ark_bn254::Fq::ZERO {
            return BigIntWires::new_constant(a.len(), &BigUint::zero()).unwrap();
        }

        if b == &Self::as_montgomery(ark_bn254::Fq::ONE) {
            return (*a).clone();
        }

        let mul_circuit = bigint::mul_by_constant(circuit, a, &b.into_bigint().into());

        Self::montgomery_reduce(circuit, &mul_circuit)
    }

    /// Montgomery squaring for circuit wires
    ///
    /// Computes the square of a Montgomery form element:
    /// `(a_mont * a_mont) * R^-1 mod p` where input is in Montgomery form.
    /// The result is also in Montgomery form.
    ///
    /// # Arguments
    /// * `circuit` - Circuit to add gates to  
    /// * `a` - Wire in Montgomery form
    ///
    /// # Returns
    /// Square in Montgomery form
    fn square_montgomery<C: CircuitContext>(circuit: &mut C, a: &BigIntWires) -> BigIntWires {
        Self::mul_montgomery(circuit, a, a)
    }

    /// Montgomery reduction for circuit wires
    ///
    /// Reduces a double-width product to single-width Montgomery form.
    /// Takes a 508-bit result from multiplication and reduces it to 254-bit Montgomery form
    /// using the Montgomery reduction algorithm: `x * R^-1 mod p`.
    ///
    /// This is the core operation that enables efficient Montgomery multiplication.
    ///
    /// # Arguments
    /// * `circuit` - Circuit to add gates to
    /// * `x` - Double-width (508-bit) multiplication result
    ///
    /// # Returns
    /// Single-width (254-bit) result in Montgomery form
    #[bn_component(arity = "Self::N_BITS")]
    fn montgomery_reduce<C: CircuitContext>(circuit: &mut C, x: &BigIntWires) -> BigIntWires {
        assert_eq!(x.len(), 2 * Self::N_BITS);

        let (x_low, x_high) = (*x).clone().split_at(254);

        let q = bigint::mul_by_constant_modulo_power_two(
            circuit,
            &x_low,
            &Self::montgomery_m_inverse_as_biguint(),
            254,
        );

        let sub = bigint::mul_by_constant(circuit, &q, &Self::modulus_as_biguint())
            .split_at(254)
            .1
            .truncate(254);

        let bound_check = bigint::greater_than(circuit, &sub, &x_high);

        let modulus_as_biguint =
            BigIntWires::new_constant(x_high.len(), &Self::modulus_as_biguint()).unwrap();

        let subtract_if_too_much = bigint::self_or_zero(circuit, &modulus_as_biguint, bound_check);

        let new_sub = bigint::sub_without_borrow(circuit, &sub, &subtract_if_too_much);

        bigint::sub_without_borrow(circuit, &x_high, &new_sub)
    }

    /// Modular inverse using extended Euclidean algorithm
    #[bn_component(arity = "Self::N_BITS")]
    fn inverse<C: CircuitContext>(circuit: &mut C, a: &BigIntWires) -> BigIntWires {
        assert_eq!(a.len(), Self::N_BITS);

        #[derive(Clone)]
        struct IterationContext {
            u: BigIntWires,
            v: BigIntWires,
            r: BigIntWires,
            s: BigIntWires,
            k: BigIntWires,
        }

        impl WiresObject for IterationContext {
            fn to_wires_vec(&self) -> Vec<WireId> {
                let mut wires = Vec::new();
                wires.extend(self.u.iter().copied());
                wires.extend(self.v.iter().copied());
                wires.extend(self.r.iter().copied());
                wires.extend(self.s.iter().copied());
                wires.extend(self.k.iter().copied());
                wires
            }

            fn clone_from(&self, mut wire_gen: &mut impl FnMut() -> WireId) -> Self {
                let Self { u, v, r, s, k } = self;
                let u = u.clone_from(&mut wire_gen);
                let v = v.clone_from(&mut wire_gen);
                let r = r.clone_from(&mut wire_gen);
                let s = s.clone_from(&mut wire_gen);
                let k = k.clone_from(&mut wire_gen);

                Self { u, v, r, s, k }
            }
        }

        impl FromWires for IterationContext {
            fn from_wires(wires: &[WireId]) -> Option<Self> {
                let chunk_size = wires.len() / 5;
                let mut chunks = wires.chunks(chunk_size);

                let u = BigIntWires::from_wires(chunks.next()?)?;
                let v = BigIntWires::from_wires(chunks.next()?)?;
                let r = BigIntWires::from_wires(chunks.next()?)?;
                let s = BigIntWires::from_wires(chunks.next()?)?;
                let k = BigIntWires::from_wires(chunks.next()?)?;

                Some(Self { u, v, r, s, k })
            }
        }

        let [odd_part, even_part] = bigint::odd_part(circuit, a);

        // initialize value for wires
        let neg_odd_part = Self::neg(circuit, &odd_part);
        let u = bigint::half(circuit, &neg_odd_part);
        let v = odd_part;

        let k = BigIntWires::new_constant(a.len(), &BigUint::from(ark_bn254::Fq::ONE)).unwrap();

        let r = BigIntWires::new_constant(a.len(), &BigUint::from(ark_bn254::Fq::ONE)).unwrap();

        let s = BigIntWires::new_constant(
            a.len(),
            &BigUint::from(ark_bn254::Fq::ONE + ark_bn254::Fq::ONE),
        )
        .unwrap();

        let mut input = IterationContext { u, v, r, s, k };

        const PER_CHUNK: usize = 4;

        for chunk in (0..2 * Self::N_BITS).chunks(PER_CHUNK).into_iter() {
            let chunk = chunk.into_iter().collect::<Vec<_>>();

            input = circuit.with_named_child(
                crate::component_key!("inverse_iteration", 5 * Self::N_BITS, 5 * Self::N_BITS),
                input,
                |circuit, input| {
                    let IterationContext {
                        mut u,
                        mut v,
                        mut r,
                        mut s,
                        mut k,
                    } = input.clone();

                    for _ in chunk.iter() {
                        let not_x1 = u.get(0).unwrap();
                        let not_x2 = v.get(0).unwrap();

                        //let x1 = circuit.issue_wire();
                        //let x2 = circuit.issue_wire();
                        //circuit.add(Gate::not(x1x.clone(), x1.clone()));
                        //circuit.add(Gate::not(x2x.clone(), x2.clone()));
                        let x3 = bigint::greater_than(circuit, &u, &v);

                        //let p1 = x1.clone();
                        //let not_x1 = circuit.issue_wire();
                        //circuit.add(Gate::not(x1.clone(), not_x1.clone()));
                        let p2 = circuit.issue_wire();
                        circuit.add_gate(Gate::and_variant(
                            not_x1,
                            not_x2,
                            p2,
                            [false, true, false],
                        ));
                        let p3 = circuit.issue_wire();
                        //let not_x2 = circuit.issue_wire();
                        //circuit.add(Gate::not(x2, not_x2.clone()));
                        let wires_2 = circuit.issue_wire();
                        circuit.add_gate(Gate::and(not_x1, not_x2, wires_2));
                        circuit.add_gate(Gate::and(wires_2, x3, p3));
                        let p4 = circuit.issue_wire();
                        circuit.add_gate(Gate::nimp(wires_2, x3, p4));

                        //part1
                        let u1 = bigint::half(circuit, &u);
                        let v1 = v.clone();
                        let r1 = r.clone();
                        let s1 = bigint::double_without_overflow(circuit, &s);
                        let k1 = bigint::add_constant_without_carry(circuit, &k, &BigUint::one());

                        // part2
                        let u2 = u.clone();
                        let v2 = bigint::half(circuit, &v);
                        let r2 = bigint::double_without_overflow(circuit, &r);
                        let s2 = s.clone();
                        let k2 = bigint::add_constant_without_carry(circuit, &k, &BigUint::one());

                        // part3
                        let u3 = bigint::sub_without_borrow(circuit, &u1, &v2);
                        let v3 = v.clone();
                        let r3 = bigint::add_without_carry(circuit, &r, &s);
                        let s3 = bigint::double_without_overflow(circuit, &s);
                        let k3 = bigint::add_constant_without_carry(circuit, &k, &BigUint::one());

                        // part4
                        let u4 = u.clone();
                        let v4 = bigint::sub_without_borrow(circuit, &v2, &u1);
                        let r4 = bigint::double_without_overflow(circuit, &r);
                        let s4 = bigint::add_without_carry(circuit, &r, &s);
                        let k4 = bigint::add_constant_without_carry(circuit, &k, &BigUint::one());

                        // calculate new u
                        let wire_u_1 = bigint::self_or_zero_inv(circuit, &u1, not_x1);
                        let wire_u_2 = bigint::self_or_zero(circuit, &u2, p2);
                        let wire_u_3 = bigint::self_or_zero(circuit, &u3, p3);
                        let wire_u_4 = bigint::self_or_zero(circuit, &u4, p4);

                        let add_u_1 = bigint::add_without_carry(circuit, &wire_u_1, &wire_u_2);
                        let add_u_2 = bigint::add_without_carry(circuit, &add_u_1, &wire_u_3);
                        let new_u = bigint::add_without_carry(circuit, &add_u_2, &wire_u_4);

                        // calculate new v
                        let wire_v_1 = bigint::self_or_zero_inv(circuit, &v1, not_x1);
                        let wire_v_2 = bigint::self_or_zero(circuit, &v2, p2);
                        let wire_v_3 = bigint::self_or_zero(circuit, &v3, p3);
                        let wire_v_4 = bigint::self_or_zero(circuit, &v4, p4);

                        let add_v_1 = bigint::add_without_carry(circuit, &wire_v_1, &wire_v_2);
                        let add_v_2 = bigint::add_without_carry(circuit, &add_v_1, &wire_v_3);
                        let new_v = bigint::add_without_carry(circuit, &add_v_2, &wire_v_4);

                        // calculate new r
                        let wire_r_1 = bigint::self_or_zero_inv(circuit, &r1, not_x1);
                        let wire_r_2 = bigint::self_or_zero(circuit, &r2, p2);
                        let wire_r_3 = bigint::self_or_zero(circuit, &r3, p3);
                        let wire_r_4 = bigint::self_or_zero(circuit, &r4, p4);

                        let add_r_1 = bigint::add_without_carry(circuit, &wire_r_1, &wire_r_2);
                        let add_r_2 = bigint::add_without_carry(circuit, &add_r_1, &wire_r_3);
                        let new_r = bigint::add_without_carry(circuit, &add_r_2, &wire_r_4);

                        // calculate new s
                        let wire_s_1 = bigint::self_or_zero_inv(circuit, &s1, not_x1);
                        let wire_s_2 = bigint::self_or_zero(circuit, &s2, p2);
                        let wire_s_3 = bigint::self_or_zero(circuit, &s3, p3);
                        let wire_s_4 = bigint::self_or_zero(circuit, &s4, p4);

                        let add_s_1 = bigint::add_without_carry(circuit, &wire_s_1, &wire_s_2);
                        let add_s_2 = bigint::add_without_carry(circuit, &add_s_1, &wire_s_3);
                        let new_s = bigint::add_without_carry(circuit, &add_s_2, &wire_s_4);

                        // calculate new k
                        let wire_k_1 = bigint::self_or_zero_inv(circuit, &k1, not_x1);
                        let wire_k_2 = bigint::self_or_zero(circuit, &k2, p2);
                        let wire_k_3 = bigint::self_or_zero(circuit, &k3, p3);
                        let wire_k_4 = bigint::self_or_zero(circuit, &k4, p4);

                        let add_k_1 = bigint::add_without_carry(circuit, &wire_k_1, &wire_k_2);
                        let add_k_2 = bigint::add_without_carry(circuit, &add_k_1, &wire_k_3);
                        let new_k = bigint::add_without_carry(circuit, &add_k_2, &wire_k_4);

                        // set new values

                        let v_equals_one = bigint::equal_constant(circuit, &v, &BigUint::one());

                        u = bigint::select(circuit, &u, &new_u, v_equals_one);
                        v = bigint::select(circuit, &v, &new_v, v_equals_one);
                        r = bigint::select(circuit, &r, &new_r, v_equals_one);
                        s = bigint::select(circuit, &s, &new_s, v_equals_one);
                        k = bigint::select(circuit, &k, &new_k, v_equals_one);
                    }

                    IterationContext { u, v, r, s, k }
                },
                5 * Self::N_BITS, // IterationContext has 5 BigIntWires fields
            );
        }

        let IterationContext { s, k, .. } = input;

        let s = circuit.with_named_child(
            crate::component_key!(
                "inverse::divide_result_by_even_part",
                2 * Self::N_BITS,
                s.len() + even_part.len()
            ),
            (s, even_part),
            |circuit, inputs| {
                let (s, even_part) = inputs;

                let mut s = s.clone();
                let mut even_part = even_part.clone();

                for (chunk_idx, chunk) in
                    (0..Self::N_BITS).chunks(PER_CHUNK).into_iter().enumerate()
                {
                    let chunk = chunk.collect::<Vec<_>>();

                    let chunk_idx_bytes = chunk_idx.to_le_bytes();

                    let (new_s, new_even_part) = circuit.with_named_child(
                        crate::component_key!(
                            "inverse::divide_result_by_even_part::chunk",
                            chunk_idx = &chunk_idx_bytes[..] ;
                            2 * Self::N_BITS,
                            s.len() + even_part.len()
                        ),
                        (s, even_part),
                        |circuit, inputs| {
                            let (s, even_part) = inputs;
                            let mut s = s.clone();
                            let mut even_part = even_part.clone();

                            for _ in chunk.iter() {
                                let updated_s = Self::half(circuit, &s);
                                let updated_even_part = Self::half(circuit, &even_part);

                                let selector =
                                    bigint::equal_constant(circuit, &even_part, &BigUint::one());

                                s = bigint::select(circuit, &s, &updated_s, selector);
                                even_part = bigint::select(
                                    circuit,
                                    &even_part,
                                    &updated_even_part,
                                    selector,
                                );
                            }

                            (s, even_part)
                        },
                        2 * Self::N_BITS, // Returns tuple of 2 BigIntWires
                    );

                    s = new_s;
                    even_part = new_even_part;
                }

                s
            },
            Self::N_BITS, // Returns single BigIntWires
        );

        let input_wires = [s.clone().to_wires_vec(), k.clone().to_wires_vec()].concat();
        let input_wires_len = input_wires.len();
        circuit.with_named_child(
            crate::component_key!(
                "inverse::divide_result_by_2^k",
                2 * Self::N_BITS,
                input_wires_len
            ),
            (s.clone(), k.clone()),
            |circuit, inputs| {
                let (mut s, mut k) = inputs.clone();

                // divide result by 2^k
                for chunk in (0..2 * Self::N_BITS).chunks(PER_CHUNK).into_iter() {
                    let chunk = chunk.collect::<Vec<_>>();

                    let (new_s, new_k) = circuit.with_named_child(
                        crate::component_key!(
                            "inverse::divide_result_by_2^k::chunk",
                            2 * Self::N_BITS,
                            s.len() + k.len()
                        ),
                        (s, k),
                        |circuit, inputs| {
                            let (mut s, mut k) = inputs.clone();

                            for _ in chunk.iter() {
                                let updated_s = Self::half(circuit, &s);
                                let updated_k =
                                    Self::add_constant(circuit, &k, &ark_bn254::Fq::from(-1));

                                let selector =
                                    Self::equal_constant(circuit, &k, &ark_bn254::Fq::ZERO);

                                s = bigint::select(circuit, &s, &updated_s, selector);
                                k = bigint::select(circuit, &k, &updated_k, selector);
                            }

                            (s, k)
                        },
                        2 * Self::N_BITS, // Returns tuple of 2 BigIntWires
                    );

                    s = new_s;
                    k = new_k;
                }

                s
            },
            Self::N_BITS, // Returns single BigIntWires
        )
    }

    /// Modular inverse in Montgomery form for circuit wires
    ///
    /// Computes the modular inverse of a Montgomery form element.
    /// Given `a_mont` in Montgomery form, returns `a_mont^-1` also in Montgomery form.
    ///
    /// The implementation first converts to standard form, computes the inverse,
    /// then converts back to Montgomery form with appropriate scaling.
    ///
    /// # Arguments
    /// * `circuit` - Circuit to add gates to
    /// * `a` - Wire in Montgomery form (must be non-zero)
    ///
    /// # Returns
    /// Modular inverse in Montgomery form
    ///
    /// # Panics
    /// Will panic if the input is zero (no modular inverse exists)
    fn inverse_montgomery<C: CircuitContext>(circuit: &mut C, a: &BigIntWires) -> BigIntWires {
        let b = Self::inverse(circuit, a);

        Self::mul_by_constant_montgomery(
            circuit,
            &b,
            &(ark_bn254::Fq::from(Self::montgomery_r_as_biguint()).square()
                * ark_bn254::Fq::from(Self::montgomery_r_as_biguint())),
        )
    }

    /// Exponentiation by constant in Montgomery form
    #[bn_component(arity = "Self::N_BITS", offcircuit_args = "exp")]
    fn exp_by_constant_montgomery<C: CircuitContext>(
        circuit: &mut C,
        a: &BigIntWires,
        exp: &BigUint,
    ) -> BigIntWires {
        if exp.is_zero() {
            return BigIntWires::new_constant(a.len(), &BigUint::one()).unwrap();
        }

        if exp.is_one() {
            return (*a).clone();
        }

        let b_bits = bigint::bits_from_biguint(exp);
        let len = b_bits.len();
        let mut i = len - 1;
        while !b_bits[i] {
            i -= 1;
        }

        let mut result = (*a).clone();
        for b_bit in b_bits.iter().rev().skip(len - i) {
            let result_square = Self::square_montgomery(circuit, &result);

            if *b_bit {
                result = Self::mul_montgomery(circuit, a, &result_square);
            } else {
                result = result_square;
            }
        }

        result.clone()
    }

    #[bn_component(arity = "Self::N_BITS")]
    fn triple<C: CircuitContext>(circuit: &mut C, a: &BigIntWires) -> BigIntWires {
        assert_eq!(a.len(), Self::N_BITS);
        let a_2 = Self::double(circuit, a);
        Self::add(circuit, &a_2, a)
    }

    #[bn_component(arity = "Self::N_BITS")]
    fn div6<C: CircuitContext>(circuit: &mut C, a: &BigIntWires) -> BigIntWires {
        assert_eq!(a.len(), Self::N_BITS);

        let half = Self::half(circuit, a);
        let mut result = BigIntWires::from_ctx(circuit, a.len());
        let mut r1 = FALSE_WIRE;
        let mut r2 = FALSE_WIRE;

        for i in 0..Self::N_BITS {
            // msb to lsb
            let j = Self::N_BITS - 1 - i;

            // result wire
            let r2_and_hj = circuit.issue_wire();

            circuit.add_gate(Gate::and(r2, half.get(j).unwrap(), r2_and_hj));
            let result_wire = circuit.issue_wire();

            circuit.add_gate(Gate::or(r1, r2_and_hj, result_wire));

            result.set(j, result_wire);

            //let not_hj = circuit.issue_wire();
            //circuit.add_gate(Gate::not(half[j].clone(), not_hj.clone()));
            //r1 = circuit.selector(not_r2.clone(), r2.clone(), result_wire.clone());
            let new_r1 = circuit.issue_wire();
            circuit.add_gate(Gate::xor(r2, result_wire, new_r1));
            r1 = new_r1;

            //let not_r2 = circuit.issue_wire();
            //circuit.add_gate(Gate::not(r2.clone(), not_r2.clone()));
            //r2 = circuit.selector(not_hj.clone(), half[j].clone(), result_wire.clone());
            let new_r2 = circuit.issue_wire();
            circuit.add_gate(Gate::xor(half.get(j).unwrap(), result_wire, new_r2));
            r2 = new_r2;

            // special case if 1 0 0 then 0 1 instead of 1 1 so we need to not r1 if 1 0 0 is the case

            let edge_case = circuit.issue_wire();
            circuit.add_gate(Gate::nimp(result_wire, half.get(j).unwrap(), edge_case));

            //let not_r1 = circuit.issue_wire();
            //circuit.add_gate(Gate::not(r1.clone(), not_r1));
            //r1 = circuit.selector(not_r1.clone(), r1.clone(), edge_case);
            let new_r1 = circuit.issue_wire();
            circuit.add_gate(Gate::xor(r1, edge_case, new_r1));
            r1 = new_r1;
        }
        // residue for r2
        let result_plus_one_third =
            bigint::add_constant_without_carry(circuit, &result, &Self::one_third_modulus());

        result = bigint::select(circuit, &result_plus_one_third, &result, r2);
        // residue for r1
        let result_plus_two_third =
            bigint::add_constant_without_carry(circuit, &result, &Self::two_third_modulus());

        bigint::select(circuit, &result_plus_two_third, &result, r1)
    }

    fn multiplexer<C: CircuitContext>(
        circuit: &mut C,
        a: &[BigIntWires],
        s: &[WireId],
        w: usize,
    ) -> BigIntWires {
        bigint::multiplexer(circuit, a, s, w)
    }
}
