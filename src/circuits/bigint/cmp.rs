use super::BigIntImpl;
use crate::circuits::basic::multiplexer;
use crate::circuits::bigint::utils::bits_from_biguint;
use crate::{bag::*, circuits::basic::selector};
use num_bigint::BigUint;

pub fn self_or_zero_generic(a: Wires, s: Wirex, len: usize) -> Circuit {
    assert_eq!(a.len(), len);
    let mut circuit = Circuit::empty();

    let mut result = vec![];
    for i in 0..len {
        result.push(new_wirex());
        circuit.add(Gate::and(a[i].clone(), s.clone(), result[i].clone()));
    }
    circuit.add_wires(result);
    circuit
}

impl<const N_BITS: usize> BigIntImpl<N_BITS> {
    pub fn equal(a: Wires, b: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(b.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let c = Self::wires();
        for i in 0..N_BITS {
            circuit.add(Gate::xor(a[i].clone(), b[i].clone(), c[i].clone()));
        }
        let result = circuit.extend(Self::equal_constant(c, BigUint::ZERO));
        circuit.add_wires(result);
        circuit
    }

    pub fn equal_constant(a: Wires, b: BigUint) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let b_bits = bits_from_biguint(b);
        let mut output = a[0].clone();
        if !b_bits[0] {
            let not_a0 = new_wirex();
            circuit.add(Gate::not(a[0].clone(), not_a0.clone()));
            output = not_a0;
        }

        for i in 1..N_BITS {
            let mut a_or_a_not = a[i].clone();
            if !b_bits[i] {
                let not_ai = new_wirex();
                circuit.add(Gate::not(a[i].clone(), not_ai.clone()));
                a_or_a_not = not_ai;
            }
            let new_output = new_wirex();
            circuit.add(Gate::and(
                output.clone(),
                a_or_a_not.clone(),
                new_output.clone(),
            ));
            output = new_output;
        }
        circuit.add_wire(output);
        circuit
    }

    pub fn greater_than(a: Wires, b: Wires) -> Circuit {
        assert_eq!(a.len(), N_BITS);
        assert_eq!(b.len(), N_BITS);
        let mut circuit = Circuit::empty();

        let not_b = Self::wires();

        for i in 0..N_BITS {
            circuit.add(Gate::not(b[i].clone(), not_b[i].clone()));
        }

        let wires = circuit.extend(Self::add(a, not_b));
        circuit.add_wire(wires[N_BITS].clone());
        circuit
    }

    pub fn less_than_constant(a: Wires, b: BigUint) -> Circuit {
        assert_eq!(a.len(), N_BITS);
        let mut circuit = Circuit::empty();

        let not_a = Self::wires();

        for i in 0..N_BITS {
            circuit.add(Gate::not(a[i].clone(), not_a[i].clone()));
        }

        let wires = circuit.extend(Self::add_constant(not_a, b));
        circuit.add_wire(wires[N_BITS].clone());
        circuit
    }

    pub fn select(a: Wires, b: Wires, s: Wirex) -> Circuit {
        assert_eq!(a.len(), N_BITS);
        assert_eq!(b.len(), N_BITS);
        let mut circuit = Circuit::empty();

        for i in 0..N_BITS {
            let wires = circuit.extend(selector(a[i].clone(), b[i].clone(), s.clone()));
            circuit.add_wire(wires[0].clone());
        }
        circuit
    }

    pub fn self_or_zero(a: Wires, s: Wirex) -> Circuit {
        self_or_zero_generic(a, s, N_BITS)
    }

    pub fn self_or_zero_constant(a: BigUint, s: Wirex) -> Circuit {
        let mut bit_wires = vec![];
        let mut bits = bits_from_biguint(a);
        bits.resize(Self::N_BITS, false);
        for i in 0..Self::N_BITS {
            bit_wires.push(new_wirex());
            bit_wires[i].borrow_mut().set(bits[i]);
        }
        Self::self_or_zero(bit_wires, s)
    }

    pub fn multiplexer(a: Vec<Wires>, s: Wires, w: usize) -> Circuit {
        let n = 2_usize.pow(w.try_into().unwrap());
        assert_eq!(a.len(), n);
        for x in a.clone() {
            assert_eq!(x.len(), N_BITS);
        }
        assert_eq!(s.len(), w);
        let mut circuit = Circuit::empty();

        for i in 0..N_BITS {
            let ith_wires = a.iter().map(|x| x[i].clone()).collect();
            let ith_result = circuit.extend(multiplexer(ith_wires, s.clone(), w))[0].clone();
            circuit.add_wire(ith_result);
        }

        circuit
    }
}

#[cfg(test)]
mod tests {
    use rand::{Rng, rng};
    use std::str::FromStr;

    use super::*;
    use crate::circuits::bigint::{
        U254,
        utils::{biguint_from_wires, random_biguint_n_bits},
    };

    #[test]
    fn test_equal_and_equal_constant() {
        let a = random_biguint_n_bits(254);
        let b = random_biguint_n_bits(254);
        let circuit = U254::equal(
            U254::wires_set_from_number(a.clone()),
            U254::wires_set_from_number(b.clone()),
        );
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        assert_eq!(a == b, circuit.0[0].borrow().get_value());

        let a = random_biguint_n_bits(254);
        let circuit = U254::equal(
            U254::wires_set_from_number(a.clone()),
            U254::wires_set_from_number(a.clone()),
        );
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        assert!(circuit.0[0].borrow().get_value());

        let a = random_biguint_n_bits(254);
        let circuit = U254::equal_constant(U254::wires_set_from_number(a.clone()), b.clone());
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        assert_eq!(a == b, circuit.0[0].borrow().get_value());
    }

    #[test]
    fn test_greater_than() {
        let a = random_biguint_n_bits(254);
        let b = random_biguint_n_bits(254);
        let circuit = U254::greater_than(
            U254::wires_set_from_number(a.clone()),
            U254::wires_set_from_number(b.clone()),
        );
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        assert_eq!(a > b, circuit.0[0].borrow().get_value());

        let a = random_biguint_n_bits(254);
        let circuit = U254::greater_than(
            U254::wires_set_from_number(a.clone()),
            U254::wires_set_from_number(a.clone()),
        );
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        assert!(!circuit.0[0].borrow().get_value());

        let a = random_biguint_n_bits(254);
        let circuit = U254::greater_than(
            U254::wires_set_from_number(a.clone() + BigUint::from_str("1").unwrap()),
            U254::wires_set_from_number(a.clone()),
        );
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        assert!(circuit.0[0].borrow().get_value());
    }

    #[test]
    fn test_less_than_constant() {
        let a = random_biguint_n_bits(254);
        let b = random_biguint_n_bits(254);
        let circuit = U254::less_than_constant(U254::wires_set_from_number(a.clone()), b.clone());
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        assert_eq!(a < b, circuit.0[0].borrow().get_value());
    }

    #[test]
    fn test_select() {
        let a = random_biguint_n_bits(254);
        let b = random_biguint_n_bits(254);
        let s = new_wirex();
        s.borrow_mut().set(true);
        let circuit = U254::select(
            U254::wires_set_from_number(a.clone()),
            U254::wires_set_from_number(b.clone()),
            s,
        );
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = biguint_from_wires(circuit.0);
        assert_eq!(a, c);
    }

    #[test]
    fn test_self_or_zero() {
        let a = random_biguint_n_bits(254);

        let s = new_wirex();
        s.borrow_mut().set(true);
        let circuit = U254::self_or_zero(U254::wires_set_from_number(a.clone()), s);
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = biguint_from_wires(circuit.0);
        assert_eq!(a, c);

        let s = new_wirex();
        s.borrow_mut().set(false);
        let circuit = U254::self_or_zero(U254::wires_set_from_number(a.clone()), s);
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = biguint_from_wires(circuit.0);
        assert_eq!(c, BigUint::ZERO);
    }

    #[test]
    fn test_multiplexer() {
        let w = 5;
        let n = 2_usize.pow(w as u32);
        let a: Vec<BigUint> = (0..n).map(|_| random_biguint_n_bits(254)).collect();
        let s: Wires = (0..w).map(|_| new_wirex()).collect();

        let mut a_wires = Vec::new();
        for e in a.clone() {
            a_wires.push(U254::wires_set_from_number(e));
        }

        let mut u = 0;
        for wire in s.iter().rev() {
            let x = rng().random();
            u = u + u + if x { 1 } else { 0 };
            wire.borrow_mut().set(x);
        }

        let circuit = U254::multiplexer(a_wires, s.clone(), w);
        circuit.gate_counts().print();

        for mut gate in circuit.1 {
            gate.evaluate();
        }

        let result = biguint_from_wires(circuit.0);
        let expected = a[u].clone();

        assert_eq!(result, expected);
    }
}
