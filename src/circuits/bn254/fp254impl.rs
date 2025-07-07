use crate::{
    bag::*,
    circuits::{
        basic::selector,
        bigint::{
            U254,
            utils::bits_from_biguint,
        },
        bn254::fq::Fq,
    },
};
use ark_ff::{AdditiveGroup, Field};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use std::str::FromStr;

pub trait Fp254Impl {
    const MODULUS: &'static str;
    const MONTGOMERY_R: &'static str =
        "28948022309329048855892746252171976963317496166410141009864396001978282409984"; //2^254
    const MONTGOMERY_M_INVERSE: &'static str; // MODULUS^-1 modulo R
    const MONTGOMERY_R_INVERSE: &'static str; // R^-1 modulo MODULUS
    const N_BITS: usize;
    const MODULUS_ADD_1_DIV_4: &'static str =
        "5472060717959818805561601436314318772174077789324455915672259473661306552146"; // (MODULUS+1)/4 

    fn modulus_as_biguint() -> BigUint {
        BigUint::from_str(Self::MODULUS).unwrap()
    }

    fn montgomery_r_as_biguint() -> BigUint {
        BigUint::from_str(Self::MONTGOMERY_R).unwrap()
    }

    fn montgomery_m_inverse_as_biguint() -> BigUint {
        BigUint::from_str(Self::MONTGOMERY_M_INVERSE).unwrap()
    }

    fn montgomery_r_inverse_as_biguint() -> BigUint {
        BigUint::from_str(Self::MONTGOMERY_R_INVERSE).unwrap()
    }

    fn modulus_as_bits() -> Vec<bool> {
        bits_from_biguint(&Self::modulus_as_biguint())
    }

    fn not_modulus_as_biguint() -> BigUint {
        let p = Self::modulus_as_biguint();
        let a = BigUint::from_str("2")
            .unwrap()
            .pow(Self::N_BITS.try_into().unwrap());
        a - p
    }

    fn not_modulus_as_bits() -> Vec<bool> {
        bits_from_biguint(&Self::not_modulus_as_biguint())
    }

    fn half_modulus() -> BigUint;

    fn one_third_modulus() -> BigUint;

    fn two_third_modulus() -> BigUint;

    fn self_or_zero(a: Wires, s: Wirex) -> Circuit {
        U254::self_or_zero(a, s)
    }

    fn multiplexer(a: Vec<Wires>, s: Wires, w: usize) -> Circuit {
        U254::multiplexer(a, s, w)
    }

    fn equal(a: Wires, b: Wires) -> Circuit {
        U254::equal(a, b)
    }

    fn equal_constant(a: Wires, b: ark_bn254::Fq) -> Circuit {
        U254::equal_constant(a, &BigUint::from(b))
    }

    fn equal_zero(a: Wires) -> Circuit {
        U254::equal_constant(a, &BigUint::ZERO)
    }

    fn add(a: Wires, b: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(b.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let mut wires_1 = circuit.extend(U254::add(a, b));
        let u = wires_1.pop().unwrap();
        let c = Self::not_modulus_as_biguint();
        let mut wires_2 = circuit.extend(U254::add_constant(wires_1.clone(), &c));
        wires_2.pop();
        let v = circuit.extend(U254::less_than_constant(
            wires_1.clone(),
            &Self::modulus_as_biguint(),
        ))[0]
            .clone();
        let s = new_wirex();
        circuit.add(Gate::and_variant(
            u.clone(),
            v.clone(),
            s.clone(),
            [1, 0, 0],
        ));
        let wires_3 = circuit.extend(U254::select(wires_1, wires_2, s));
        circuit.add_wires(wires_3);
        circuit
    }

    fn add_evaluate(a: Wires, b: Wires) -> (Wires, GateCount) {
        let circuit = Self::add(a, b);
        for mut gate in circuit.1.clone() {
            gate.evaluate();
        }
        (circuit.0.clone(), circuit.gate_counts())
    }

    fn add_constant(a: Wires, b: ark_bn254::Fq) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        if b == ark_bn254::Fq::ZERO {
            circuit.add_wires(a);
            return circuit;
        }

        let mut wires_1 = circuit.extend(U254::add_constant(a.clone(), &BigUint::from(b)));
        let u = wires_1.pop().unwrap();
        let c = Self::not_modulus_as_biguint();
        let mut wires_2 = circuit.extend(U254::add_constant(wires_1.clone(), &c));
        wires_2.pop();
        let v = circuit.extend(U254::less_than_constant(
            wires_1.clone(),
            &Self::modulus_as_biguint(),
        ))[0]
            .clone();
        let s = new_wirex();
        circuit.add(Gate::and_variant(
            u.clone(),
            v.clone(),
            s.clone(),
            [1, 0, 0],
        ));
        let wires_3 = circuit.extend(U254::select(wires_1, wires_2, s));
        circuit.add_wires(wires_3);
        circuit
    }

    fn neg(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let not_a = Fq::wires();
        for i in 0..Self::N_BITS {
            circuit.add(Gate::not(a[i].clone(), not_a[i].clone()));
        }

        let wires = circuit.extend(Self::add_constant(
            not_a,
            ark_bn254::Fq::from(1) - ark_bn254::Fq::from(Self::not_modulus_as_biguint()),
        ));
        circuit.add_wires(wires);
        circuit
    }

    fn neg_evaluate(a: Wires) -> (Wires, GateCount) {
        assert_eq!(a.len(), Self::N_BITS);
        let circuit = Self::neg(a);
        for mut gate in circuit.1.clone() {
            gate.evaluate();
        }
        (circuit.0.clone(), circuit.gate_counts())
    }

    fn sub(a: Wires, b: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(b.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let neg_b = circuit.extend(Self::neg(b));
        let result = circuit.extend(Self::add(a, neg_b));
        circuit.add_wires(result);
        circuit
    }

    fn sub_eval(a: Wires, b: Wires) -> (Wires, GateCount) {
        let circuit = Self::sub(a, b);
        for mut gate in circuit.1.clone() {
            gate.evaluate();
        }
        (circuit.0.clone(), circuit.gate_counts())
    }

    fn double(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let shift_wire = new_wirex();
        /*
        let x = a[0].clone();
        let not_x = new_wirex();
        circuit.add(Gate::not(x.clone(), not_x.clone()));
        circuit.add(Gate::and(x.clone(), not_x.clone(), shift_wire.clone()));
        */
        shift_wire.borrow_mut().set(false);
        let mut aa = a.clone();
        let u = aa.pop().unwrap();
        let mut shifted_wires = vec![shift_wire];
        shifted_wires.extend(aa);
        let c = Self::not_modulus_as_biguint();
        let mut wires_2 = circuit.extend(U254::add_constant(shifted_wires.clone(), &c));
        wires_2.pop();
        let v = circuit.extend(U254::less_than_constant(
            shifted_wires.clone(),
            &Self::modulus_as_biguint(),
        ))[0]
            .clone();
        let s = new_wirex();
        circuit.add(Gate::and_variant(
            u.clone(),
            v.clone(),
            s.clone(),
            [1, 0, 0],
        ));
        let result = circuit.extend(U254::select(shifted_wires, wires_2, s));
        circuit.add_wires(result);
        circuit
    }

    fn half(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let selector = a[0].clone();
        let wires_1 = circuit.extend(U254::half(a.clone()));
        let wires_2 = circuit.extend(U254::add_constant_without_carry(
            wires_1.clone(),
            &Self::half_modulus(),
        ));
        let result = circuit.extend(U254::select(wires_2, wires_1, selector));
        circuit.add_wires(result);
        circuit
    }

    fn half_evaluate(a: Wires) -> (Wires, GateCount) {
        assert_eq!(a.len(), Self::N_BITS);
        let circuit = Self::half(a);
        for mut gate in circuit.1.clone() {
            gate.evaluate();
        }
        (circuit.0.clone(), circuit.gate_counts())
    }

    fn triple(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_2 = circuit.extend(Self::double(a.clone()));
        let a_3 = circuit.extend(Self::add(a_2, a));
        circuit.add_wires(a_3);
        circuit
    }

    fn mul(a: Wires, b: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(b.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_or_zero = circuit.extend(Self::self_or_zero(a.clone(), b[Self::N_BITS - 1].clone()));
        let mut result: Vec<Wirex> = a_or_zero.clone();
        for b_wire in b.iter().rev().skip(1) {
            let result_double = circuit.extend(Self::double(result.clone()));
            let a_or_zero_i = circuit.extend(Self::self_or_zero(a.clone(), b_wire.clone()));
            result = circuit.extend(Self::add(result_double, a_or_zero_i));
        }
        circuit.add_wires(result);
        circuit
    }

    fn exp_by_constant_montgomery(a: Wires, b: BigUint) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        if b.is_zero() {
            circuit.add_wires(Fq::wires_set_montgomery(ark_bn254::Fq::ONE));
            return circuit;
        }

        if b.is_one() {
            circuit.add_wires(a);
            return circuit;
        }

        let b_bits = bits_from_biguint(&b);

        {
            let len = b_bits.len();
            let mut i = len - 1;
            while !b_bits[i] {
                i -= 1;
            }
            let mut result = a.clone();
            for b_bit in b_bits.iter().rev().skip(len - i) {
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
        /* 
        {
            let nb_digits = change_to_neg_pos_decomposition(b_bits.clone());
            let a_inv = circuit.extend(Self::inverse_montgomery(a.clone()));
            let mut result = a.clone();
            for digit in nb_digits.iter().rev().skip(1) {
                result = circuit.extend(Self::square_montgomery(result));
                if *digit == 1 {
                    result = circuit.extend(Self::mul_montgomery(result, a.clone()));
                } else if *digit == -1 {
                    result = circuit.extend(Self::mul_montgomery(result, a_inv.clone()));
                }
            }
            circuit.add_wires(result);
            circuit
        }  
        */      
    }

    fn exp_by_constant_montgomery_evaluate(a: Wires, b: BigUint) -> (Wires, GateCount) {
        assert_eq!(a.len(), Self::N_BITS);

        if b.is_zero() {            
            return (Fq::wires_set_montgomery(ark_bn254::Fq::ONE), GateCount::zero());
        }

        if b.is_one() {
            return (a, GateCount::zero());
        }

        let mut gc = GateCount::zero();
        let b_bits = bits_from_biguint(&b);

        {
            let len = b_bits.len();
            let mut i = len - 1;
            while !b_bits[i] {
                i -= 1;
            }
            let mut result = a.clone();
            for b_bit in b_bits.iter().rev().skip(len - i) {
                let (result_square, mut add_gc) = Self::square_montgomery_evaluate(result.clone());
                gc += add_gc;
                if *b_bit {
                    (result, add_gc) = Self::mul_montgomery_evaluate(a.clone(), result_square);
                    gc += add_gc;
                } else {
                    result = result_square;
                }
            }
            (result, gc)
        }
        /* 
        {
            let nb_digits = change_to_neg_pos_decomposition(b_bits.clone());
            let a_inv = circuit.extend(Self::inverse_montgomery(a.clone()));
            let mut result = a.clone();
            for digit in nb_digits.iter().rev().skip(1) {
                result = circuit.extend(Self::square_montgomery(result));
                if *digit == 1 {
                    result = circuit.extend(Self::mul_montgomery(result, a.clone()));
                } else if *digit == -1 {
                    result = circuit.extend(Self::mul_montgomery(result, a_inv.clone()));
                }
            }
            circuit.add_wires(result);
            circuit
        }  
        */      
    }


    fn montgomery_reduce(x: Wires) -> Circuit {
        let mut circuit = Circuit::empty();

        let x_low = x[..254].to_vec();
        let x_high = x[254..].to_vec();
        let q = circuit.extend(U254::mul_by_constant_modulo_power_two(
            x_low,
            Self::montgomery_m_inverse_as_biguint(),
            254,
        ));
        let sub =
            circuit.extend(U254::mul_by_constant(q, Self::modulus_as_biguint()))[254..508].to_vec();
        let bound_check = circuit.extend(U254::greater_than(sub.clone(), x_high.clone()));
        let subtract_if_too_much = circuit.extend(U254::self_or_zero_constant(
            &Self::modulus_as_biguint(),
            bound_check[0].clone(),
        ));
        let new_sub = circuit.extend(U254::sub_without_borrow(sub, subtract_if_too_much));
        let result = circuit.extend(U254::sub_without_borrow(x_high, new_sub));
        circuit.add_wires(result);

        circuit
    }

    fn mul_montgomery(a: Wires, b: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(b.len(), Self::N_BITS);
        let mul_circuit = U254::mul_karatsuba(a, b);
        let reduction_circuit = Self::montgomery_reduce(mul_circuit.0);
        let mut result_circuit = Circuit::new(reduction_circuit.0, mul_circuit.1);
        result_circuit.1.extend(reduction_circuit.1);
        result_circuit
    }

    fn mul_montgomery_evaluate(a: Wires, b: Wires) -> (Wires, GateCount) {
        let circuit = Self::mul_montgomery(a, b);
        for mut gate in circuit.1.clone() {
            gate.evaluate();
        }
        (circuit.0.clone(), circuit.gate_counts())
    }


    fn mul_by_constant(a: Wires, b: ark_bn254::Fq) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        if b == ark_bn254::Fq::ZERO {
            circuit.add_wires(Fq::wires_set(ark_bn254::Fq::ZERO));
            return circuit;
        }

        if b == ark_bn254::Fq::ONE {
            circuit.add_wires(a);
            return circuit;
        }

        let b_bits = Fq::to_bits(b);
        let mut i = Self::N_BITS - 1;
        while !b_bits[i] {
            i -= 1;
        }

        let mut result = a.clone();
        for b_bit in b_bits.iter().rev().skip(Self::N_BITS - i) {
            let result_double = circuit.extend(Self::double(result.clone()));
            if *b_bit {
                result = circuit.extend(Self::add(a.clone(), result_double));
            } else {
                result = result_double;
            }
        }
        circuit.add_wires(result);
        circuit
    }

    fn mul_by_constant_montgomery(a: Wires, b: ark_bn254::Fq) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);

        let mut circuit = Circuit::empty();

        if b == ark_bn254::Fq::ZERO {
            circuit.add_wires(Fq::wires_set(ark_bn254::Fq::ZERO));
            return circuit;
        }

        if b == Fq::as_montgomery(ark_bn254::Fq::ONE) {
            circuit.add_wires(a);
            return circuit;
        }

        let mul_circuit = U254::mul_by_constant(a, b.into());
        let reduction_circuit = Self::montgomery_reduce(mul_circuit.0);
        let mut result_circuit = Circuit::new(reduction_circuit.0, mul_circuit.1);
        result_circuit.1.extend(reduction_circuit.1);
        result_circuit
    }

    fn mul_by_constant_montgomery_evaluate(a: Wires, b: ark_bn254::Fq) -> (Wires, GateCount) {
        let result_circuit = Self::mul_by_constant_montgomery(a, b);
        for mut gate in result_circuit.1.clone() {
            gate.evaluate();
        }
        (result_circuit.0.clone(), result_circuit.gate_counts())
    }

    fn square(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_or_zero = circuit.extend(Self::self_or_zero(a.clone(), a[Self::N_BITS - 1].clone()));
        let mut result = a_or_zero.clone();
        for a_wire in a.iter().rev().skip(1) {
            let result_double = circuit.extend(Self::double(result.clone()));
            let a_or_zero_i = circuit.extend(Self::self_or_zero(a.clone(), a_wire.clone()));
            result = circuit.extend(Self::add(result_double, a_or_zero_i));
        }
        circuit.add_wires(result);
        circuit
    }

    fn square_montgomery(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);

        Self::mul_montgomery(a.clone(), a)
    }

    fn square_montgomery_evaluate(a: Wires) -> (Wires, GateCount) {
        assert_eq!(a.len(), Self::N_BITS);

        Self::mul_montgomery_evaluate(a.clone(), a)
    }

    fn inverse(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let wires_1 = circuit.extend(U254::odd_part(a.clone()));
        let odd_part = wires_1[0..Self::N_BITS].to_vec();
        let mut even_part = wires_1[Self::N_BITS..2 * Self::N_BITS].to_vec();

        // initialize value for wires
        let neg_odd_part = circuit.extend(Self::neg(odd_part.clone()));
        let mut u = circuit.extend(U254::half(neg_odd_part));
        let mut v = odd_part;
        let mut k = Fq::wires_set(ark_bn254::Fq::ONE);
        let mut r = Fq::wires_set(ark_bn254::Fq::ONE);
        let mut s = Fq::wires_set(ark_bn254::Fq::from(2));

        for _ in 0..2 * Self::N_BITS {
            let not_x1 = u[0].clone();
            let not_x2 = v[0].clone();
            //let x1 = new_wirex();
            //let x2 = new_wirex();
            //circuit.add(Gate::not(x1x.clone(), x1.clone()));
            //circuit.add(Gate::not(x2x.clone(), x2.clone()));
            let x3 = circuit.extend(U254::greater_than(u.clone(), v.clone()))[0].clone();

            //let p1 = x1.clone();
            //let not_x1 = new_wirex();
            //circuit.add(Gate::not(x1.clone(), not_x1.clone()));
            let p2 = new_wirex();
            circuit.add(Gate::and_variant(
                not_x1.clone(),
                not_x2.clone(),
                p2.clone(),
                [0, 1, 0],
            ));
            let p3 = new_wirex();
            //let not_x2 = new_wirex();
            //circuit.add(Gate::not(x2, not_x2.clone()));
            let wires_2 = new_wirex();
            circuit.add(Gate::and(not_x1.clone(), not_x2.clone(), wires_2.clone()));
            circuit.add(Gate::and(wires_2.clone(), x3.clone(), p3.clone()));
            let p4 = new_wirex();
            let not_x3 = new_wirex();
            circuit.add(Gate::not(x3.clone(), not_x3.clone()));
            circuit.add(Gate::and(wires_2, not_x3, p4.clone()));

            //part1
            let u1 = circuit.extend(U254::half(u.clone()));
            let v1 = v.clone();
            let r1 = r.clone();
            let s1 = circuit.extend(U254::double_without_overflow(s.clone()));
            let k1 = circuit.extend(U254::add_constant_without_carry(
                k.clone(),
                &BigUint::from_str("1").unwrap(),
            ));

            // part2
            let u2 = u.clone();
            let v2 = circuit.extend(U254::half(v.clone()));
            let r2 = circuit.extend(U254::double_without_overflow(r.clone()));
            let s2 = s.clone();
            let k2 = circuit.extend(U254::add_constant_without_carry(
                k.clone(),
                &BigUint::from_str("1").unwrap(),
            ));

            // part3
            let u3 = circuit.extend(U254::sub_without_borrow(u1.clone(), v2.clone()));
            let v3 = v.clone();
            let r3 = circuit.extend(U254::add_without_carry(r.clone(), s.clone()));
            let s3 = circuit.extend(U254::double_without_overflow(s.clone()));
            let k3 = circuit.extend(U254::add_constant_without_carry(
                k.clone(),
                &BigUint::from_str("1").unwrap(),
            ));

            // part4
            let u4 = u.clone();
            let v4 = circuit.extend(U254::sub_without_borrow(v2.clone(), u1.clone()));
            let r4 = circuit.extend(U254::double_without_overflow(r.clone()));
            let s4 = circuit.extend(U254::add_without_carry(r.clone(), s.clone()));
            let k4 = circuit.extend(U254::add_constant_without_carry(
                k.clone(),
                &BigUint::from_str("1").unwrap(),
            ));

            // calculate new u
            let wire_u_1 = circuit.extend(U254::self_or_zero_inv(u1.clone(), not_x1.clone()));
            let wire_u_2 = circuit.extend(U254::self_or_zero(u2.clone(), p2.clone()));
            let wire_u_3 = circuit.extend(U254::self_or_zero(u3.clone(), p3.clone()));
            let wire_u_4 = circuit.extend(U254::self_or_zero(u4.clone(), p4.clone()));

            let add_u_1 = circuit.extend(U254::add_without_carry(wire_u_1, wire_u_2));
            let add_u_2 = circuit.extend(U254::add_without_carry(add_u_1, wire_u_3));
            let new_u = circuit.extend(U254::add_without_carry(add_u_2, wire_u_4));

            // calculate new v
            let wire_v_1 = circuit.extend(U254::self_or_zero_inv(v1.clone(), not_x1.clone()));
            let wire_v_2 = circuit.extend(U254::self_or_zero(v2.clone(), p2.clone()));
            let wire_v_3 = circuit.extend(U254::self_or_zero(v3.clone(), p3.clone()));
            let wire_v_4 = circuit.extend(U254::self_or_zero(v4.clone(), p4.clone()));

            let add_v_1 = circuit.extend(U254::add_without_carry(wire_v_1, wire_v_2));
            let add_v_2 = circuit.extend(U254::add_without_carry(add_v_1, wire_v_3));
            let new_v = circuit.extend(U254::add_without_carry(add_v_2, wire_v_4));

            // calculate new r
            let wire_r_1 = circuit.extend(U254::self_or_zero_inv(r1.clone(), not_x1.clone()));
            let wire_r_2 = circuit.extend(U254::self_or_zero(r2.clone(), p2.clone()));
            let wire_r_3 = circuit.extend(U254::self_or_zero(r3.clone(), p3.clone()));
            let wire_r_4 = circuit.extend(U254::self_or_zero(r4.clone(), p4.clone()));

            let add_r_1 = circuit.extend(U254::add_without_carry(wire_r_1, wire_r_2));
            let add_r_2 = circuit.extend(U254::add_without_carry(add_r_1, wire_r_3));
            let new_r = circuit.extend(U254::add_without_carry(add_r_2, wire_r_4));

            // calculate new s
            let wire_s_1 = circuit.extend(U254::self_or_zero_inv(s1.clone(), not_x1.clone()));
            let wire_s_2 = circuit.extend(U254::self_or_zero(s2.clone(), p2.clone()));
            let wire_s_3 = circuit.extend(U254::self_or_zero(s3.clone(), p3.clone()));
            let wire_s_4 = circuit.extend(U254::self_or_zero(s4.clone(), p4.clone()));

            let add_s_1 = circuit.extend(U254::add_without_carry(wire_s_1, wire_s_2));
            let add_s_2 = circuit.extend(U254::add_without_carry(add_s_1, wire_s_3));
            let new_s = circuit.extend(U254::add_without_carry(add_s_2, wire_s_4));

            // calculate new k
            let wire_k_1 = circuit.extend(U254::self_or_zero_inv(k1.clone(), not_x1.clone()));
            let wire_k_2 = circuit.extend(U254::self_or_zero(k2.clone(), p2.clone()));
            let wire_k_3 = circuit.extend(U254::self_or_zero(k3.clone(), p3.clone()));
            let wire_k_4 = circuit.extend(U254::self_or_zero(k4.clone(), p4.clone()));

            let add_k_1 = circuit.extend(U254::add_without_carry(wire_k_1, wire_k_2));
            let add_k_2 = circuit.extend(U254::add_without_carry(add_k_1, wire_k_3));
            let new_k = circuit.extend(U254::add_without_carry(add_k_2, wire_k_4));

            // set new values

            let v_equals_one = circuit.extend(U254::equal_constant(
                v.clone(),
                &BigUint::from_str("1").unwrap(),
            ))[0]
                .clone();
            u = circuit.extend(U254::select(u, new_u, v_equals_one.clone()));
            v = circuit.extend(U254::select(v.clone(), new_v, v_equals_one.clone()));
            r = circuit.extend(U254::select(r, new_r, v_equals_one.clone()));
            s = circuit.extend(U254::select(s.clone(), new_s, v_equals_one.clone()));
            k = circuit.extend(U254::select(k, new_k, v_equals_one.clone()));
        }

        // divide result by even part
        for _ in 0..Self::N_BITS {
            let updated_s = circuit.extend(Self::half(s.clone()));
            let updated_even_part = circuit.extend(Self::half(even_part.clone()));
            let selector = circuit
                .extend(Self::equal_constant(even_part.clone(), ark_bn254::Fq::ONE))[0]
                .clone();
            s = circuit.extend(U254::select(s.clone(), updated_s, selector.clone()));
            even_part =
                circuit.extend(U254::select(even_part, updated_even_part, selector.clone()));
        }

        // divide result by 2^k
        for _ in 0..2 * Self::N_BITS {
            let updated_s = circuit.extend(Self::half(s.clone()));
            let updated_k = circuit.extend(Self::add_constant(k.clone(), ark_bn254::Fq::from(-1)));
            let selector = circuit.extend(Self::equal_constant(k.clone(), ark_bn254::Fq::ZERO));
            s = circuit.extend(U254::select(s, updated_s, selector[0].clone()));
            k = circuit.extend(U254::select(k, updated_k, selector[0].clone()));
        }
        circuit.add_wires(s.clone());
        circuit
    }

    fn inverse_montgomery(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let b = circuit.extend(Fq::inverse(a.clone()));
        let result = circuit.extend(Fq::mul_by_constant_montgomery(
            b,
            ark_bn254::Fq::from(Fq::montgomery_r_as_biguint()).square()
                * ark_bn254::Fq::from(Fq::montgomery_r_as_biguint()),
        ));

        circuit.add_wires(result);
        circuit
    }

    fn inverse_montgomery_evaluate(a: Wires) -> (Wires, GateCount) {
        let circuit = Self::inverse_montgomery(a);
        for mut gate in circuit.1.clone() {
            gate.evaluate();
        }
        (circuit.0.clone(), circuit.gate_counts())
    }

    fn div6(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let half = circuit.extend(Self::half(a.clone()));
        let mut result = Fq::wires();
        let mut r1 = new_wirex();
        let mut r2 = new_wirex();
        r1.borrow_mut().set(false);
        r2.borrow_mut().set(false);
        for i in 0..U254::N_BITS {
            // msb to lsb
            let j = U254::N_BITS - 1 - i;

            // result wire
            let r2_and_hj = new_wirex();
            circuit.add(Gate::and(r2.clone(), half[j].clone(), r2_and_hj.clone()));
            let result_wire = new_wirex();
            circuit.add(Gate::or(r1.clone(), r2_and_hj.clone(), result_wire.clone()));
            result[j] = result_wire.clone();
            // update r1 r2 values
            let not_hj = new_wirex();
            let not_r2 = new_wirex();
            circuit.add(Gate::not(half[j].clone(), not_hj.clone()));
            circuit.add(Gate::not(r2.clone(), not_r2.clone()));
            r1 = circuit.extend(selector(not_r2.clone(), r2.clone(), result_wire.clone()))[0]
                .clone();
            r2 = circuit.extend(selector(
                not_hj.clone(),
                half[j].clone(),
                result_wire.clone(),
            ))[0]
                .clone();

            // special case if 1 0 0 then 0 1 instead of 1 1 so we need to not r1 if 1 0 0 is the case
            let not_r1 = new_wirex();
            circuit.add(Gate::not(r1.clone(), not_r1.clone()));
            let edge_case = new_wirex();
            circuit.add(Gate::and(result_wire.clone(), not_hj, edge_case.clone()));
            r1 = circuit.extend(selector(not_r1.clone(), r1.clone(), edge_case))[0].clone();
        }
        // residue for r2
        let result_plus_one_third = circuit.extend(U254::add_constant_without_carry(
            result.clone(),
            &Self::one_third_modulus(),
        ));
        result = circuit.extend(U254::select(
            result_plus_one_third,
            result.clone(),
            r2.clone(),
        ));
        // residue for r1
        let result_plus_two_third = circuit.extend(U254::add_constant_without_carry(
            result.clone(),
            &Self::two_third_modulus(),
        ));
        result = circuit.extend(U254::select(
            result_plus_two_third,
            result.clone(),
            r1.clone(),
        ));
        circuit.add_wires(result.clone());
        circuit
    }
}
