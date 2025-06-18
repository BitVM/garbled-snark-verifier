use super::BigIntImpl;
use crate::{
    bag::*,
    circuits::{
        basic::{full_adder, full_subtracter, half_adder, half_subtracter},
        bigint::utils::{bits_from_biguint, wires_for_u254},
    },
};
use num_bigint::BigUint;

impl<const N_BITS: usize> BigIntImpl<N_BITS> {
    pub fn add(a: Wires, b: Wires) -> Circuit {
        assert_eq!(a.len(), N_BITS);
        assert_eq!(b.len(), N_BITS);
        let mut circuit = Circuit::empty();
        let wires = circuit.extend(half_adder(a[0].clone(), b[0].clone()));
        circuit.add_wire(wires[0].clone());
        let mut carry = wires[1].clone();
        for i in 1..N_BITS {
            let wires = circuit.extend(full_adder(a[i].clone(), b[i].clone(), carry));
            circuit.add_wire(wires[0].clone());
            carry = wires[1].clone();
        }
        circuit.add_wire(carry);
        circuit
    }

    pub fn add_constant(a: Wires, b: BigUint) -> Circuit {
        assert_eq!(a.len(), N_BITS);
        assert_ne!(b, BigUint::ZERO);
        let mut circuit = Circuit::empty();

        let b_bits = bits_from_biguint(b);

        let mut carry = Rc::new(RefCell::new(Wire::new()));
        let mut first_one = 0;
        while !b_bits[first_one] {
            first_one += 1;
        }

        for i in 0..N_BITS {
            if i < first_one {
                circuit.add_wire(a[i].clone());
            } else if i == first_one {
                let wire = Rc::new(RefCell::new(Wire::new()));
                circuit.add(Gate::not(a[i].clone(), wire.clone()));
                circuit.add_wire(wire);
                carry = a[i].clone();
            } else if b_bits[i] {
                let wire_1 = Rc::new(RefCell::new(Wire::new()));
                let wire_2 = Rc::new(RefCell::new(Wire::new()));
                circuit.add(Gate::xnor(a[i].clone(), carry.clone(), wire_1.clone()));
                circuit.add(Gate::or(a[i].clone(), carry.clone(), wire_2.clone()));
                circuit.add_wire(wire_1);
                carry = wire_2;
            } else {
                let wire_1 = Rc::new(RefCell::new(Wire::new()));
                let wire_2 = Rc::new(RefCell::new(Wire::new()));
                circuit.add(Gate::xor(a[i].clone(), carry.clone(), wire_1.clone()));
                circuit.add(Gate::and(a[i].clone(), carry.clone(), wire_2.clone()));
                circuit.add_wire(wire_1);
                carry = wire_2;
            }
        }
        circuit.add_wire(carry);
        circuit
    }

    pub fn add_without_carry(a: Wires, b: Wires) -> Circuit {
        assert_eq!(a.len(), N_BITS);
        assert_eq!(b.len(), N_BITS);
        let mut circuit = Circuit::empty();
        let wires = circuit.extend(half_adder(a[0].clone(), b[0].clone()));
        circuit.add_wire(wires[0].clone());
        let mut carry = wires[1].clone();
        for i in 1..N_BITS {
            let wires = circuit.extend(full_adder(a[i].clone(), b[i].clone(), carry));
            circuit.add_wire(wires[0].clone());
            carry = wires[1].clone();
        }
        circuit
    }

    pub fn add_constant_without_carry(a: Wires, b: BigUint) -> Circuit {
        assert_eq!(a.len(), N_BITS);
        assert_ne!(b, BigUint::ZERO);
        let mut circuit = Circuit::empty();

        let b_bits = bits_from_biguint(b);

        let mut carry = Rc::new(RefCell::new(Wire::new()));
        let mut first_one = 0;
        while !b_bits[first_one] {
            first_one += 1;
        }

        for i in 0..N_BITS {
            if i < first_one {
                circuit.add_wire(a[i].clone());
            } else if i == first_one {
                let wire = Rc::new(RefCell::new(Wire::new()));
                circuit.add(Gate::not(a[i].clone(), wire.clone()));
                circuit.add_wire(wire);
                carry = a[i].clone();
            } else if b_bits[i] {
                let wire_1 = Rc::new(RefCell::new(Wire::new()));
                let wire_2 = Rc::new(RefCell::new(Wire::new()));
                circuit.add(Gate::xnor(a[i].clone(), carry.clone(), wire_1.clone()));
                circuit.add(Gate::or(a[i].clone(), carry.clone(), wire_2.clone()));
                circuit.add_wire(wire_1);
                carry = wire_2;
            } else {
                let wire_1 = Rc::new(RefCell::new(Wire::new()));
                let wire_2 = Rc::new(RefCell::new(Wire::new()));
                circuit.add(Gate::xor(a[i].clone(), carry.clone(), wire_1.clone()));
                circuit.add(Gate::and(a[i].clone(), carry.clone(), wire_2.clone()));
                circuit.add_wire(wire_1);
                carry = wire_2;
            }
        }
        circuit
    }

    pub fn sub(a: Wires, b: Wires) -> Circuit {
        assert_eq!(a.len(), N_BITS);
        assert_eq!(b.len(), N_BITS);
        let mut circuit = Circuit::empty();
        let wires = circuit.extend(half_subtracter(a[0].clone(), b[0].clone()));
        circuit.add_wire(wires[0].clone());
        let mut borrow = wires[1].clone();
        for i in 1..N_BITS {
            let wires = circuit.extend(full_subtracter(a[i].clone(), b[i].clone(), borrow));
            circuit.add_wire(wires[0].clone());
            borrow = wires[1].clone();
        }
        circuit.add_wire(borrow);
        circuit
    }

    pub fn sub_without_borrow(a: Wires, b: Wires) -> Circuit {
        assert_eq!(a.len(), N_BITS);
        assert_eq!(b.len(), N_BITS);
        let mut circuit = Circuit::empty();
        let wires = circuit.extend(half_subtracter(a[0].clone(), b[0].clone()));
        circuit.add_wire(wires[0].clone());
        let mut borrow = wires[1].clone();
        for i in 1..N_BITS {
            let wires = circuit.extend(full_subtracter(a[i].clone(), b[i].clone(), borrow));
            circuit.add_wire(wires[0].clone());
            borrow = wires[1].clone();
        }
        circuit
    }

    pub fn double(a: Wires) -> Circuit {
        assert_eq!(a.len(), N_BITS);
        let mut circuit = Circuit::empty();
        let zero_wire = Rc::new(RefCell::new(Wire::new()));
        circuit.add_const(false, a[0].clone(), zero_wire.clone());
        circuit.add_wire(zero_wire);
        circuit.add_wires(a[0..N_BITS - 1].to_vec());
        circuit
    }

    pub fn half(a: Wires) -> Circuit {
        assert_eq!(a.len(), N_BITS);
        let mut circuit = Circuit::empty();
        let zero_wire = Rc::new(RefCell::new(Wire::new()));
        circuit.add_const(false, a[0].clone(), zero_wire.clone());
        circuit.add_wires(a[1..N_BITS].to_vec());
        circuit.add_wire(zero_wire);
        circuit
    }

    pub fn odd_part(a: Wires) -> Circuit {
        assert_eq!(a.len(), N_BITS);
        let mut circuit = Circuit::empty();
        let mut select = wires_for_u254();
        let not_select = wires_for_u254();
        select[0] = a[0].clone();
        for i in 1..N_BITS {
            circuit.add(Gate::or(
                select[i - 1].clone(),
                a[i].clone(),
                select[i].clone(),
            ));
        }

        for i in 0..N_BITS {
            circuit.add(Gate::not(select[i].clone(), not_select[i].clone()));
        }

        let mut k = wires_for_u254();
        k[0] = a[0].clone();
        for i in 1..N_BITS {
            circuit.add(Gate::and(
                not_select[i - 1].clone(),
                a[i].clone(),
                k[i].clone(),
            ));
        }

        let mut results = Vec::new();
        results.push(a);
        for i in 0..N_BITS {
            let half_result = circuit.extend(Self::half(results[i].clone()));
            let result = circuit.extend(Self::select(
                results[i].clone(),
                half_result,
                select[i].clone(),
            ));
            results.push(result);
        }
        circuit.add_wires(results[N_BITS].clone());
        circuit.add_wires(k.clone());
        circuit
    }

    // This is optimized without not and xor optimizations, with them, it should be about the same
    pub fn optimized_sub(
        a_wires: Vec<Rc<RefCell<Wire>>>,
        b_wires: Vec<Rc<RefCell<Wire>>>,
        check_bound: bool,
    ) -> Circuit {
        assert_eq!(a_wires.len(), N_BITS);
        assert_eq!(b_wires.len(), N_BITS);

        let mut circuit = Circuit::empty();

        let mut want: Rc<RefCell<Wire>> = Rc::new(RefCell::new(Wire::new()));
        for i in 0..N_BITS {
            circuit.add_wire(Rc::new(RefCell::new(Wire::new())));
            if i > 0 {
                let subtract_bit = Rc::new(RefCell::new(Wire::new()));
                circuit.add(Gate::xor(
                    want.clone(),
                    b_wires[i].clone(),
                    subtract_bit.clone(),
                ));
                circuit.add(Gate::xor(
                    subtract_bit.clone(),
                    a_wires[i].clone(),
                    circuit.0[i].clone(),
                ));
                let new_want_or0 = Rc::new(RefCell::new(Wire::new()));
                let new_want_or1 = Rc::new(RefCell::new(Wire::new()));
                let new_want = Rc::new(RefCell::new(Wire::new()));
                circuit.add(Gate::nimp(
                    subtract_bit.clone(),
                    a_wires[i].clone(),
                    new_want_or0.clone(),
                ));
                circuit.add(Gate::and(
                    want.clone(),
                    b_wires[i].clone(),
                    new_want_or1.clone(),
                ));
                circuit.add(Gate::or(
                    new_want_or0.clone(),
                    new_want_or1.clone(),
                    new_want.clone(),
                ));
                want = new_want;
            } else {
                circuit.add(Gate::xor(
                    b_wires[i].clone(),
                    a_wires[i].clone(),
                    circuit.0[i].clone(),
                ));
                let new_want: Rc<RefCell<Wire>> = Rc::new(RefCell::new(Wire::new()));
                circuit.add(Gate::nimp(
                    b_wires[i].clone(),
                    a_wires[i].clone(),
                    new_want.clone(),
                ));
                want = new_want;
            }
        }

        if check_bound {
            let bound_check_wire = Rc::new(RefCell::new(Wire::new()));
            circuit.add(Gate::not(want.clone(), bound_check_wire.clone()));
            circuit.add_wire(bound_check_wire);
        }

        circuit
    }
}

#[cfg(test)]
mod tests {
    use crate::circuits::bigint::{
        U254,
        utils::{biguint_from_bits, biguint_from_wires, random_u254, wires_set_from_u254},
    };
    use num_bigint::BigUint;
    use std::str::FromStr;

    #[test]
    fn test_add() {
        let a = random_u254();
        let b = random_u254();
        let circuit = U254::add(
            wires_set_from_u254(a.clone()),
            wires_set_from_u254(b.clone()),
        );
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = biguint_from_wires(circuit.0);
        assert_eq!(c, a + b);
    }

    #[test]
    fn test_add_constant() {
        let a = random_u254();
        let b = random_u254();
        let circuit = U254::add_constant(wires_set_from_u254(a.clone()), b.clone());
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = biguint_from_wires(circuit.0);
        assert_eq!(c, a + b);
    }

    #[test]
    fn test_add_without_carry() {
        let a = random_u254();
        let b = random_u254();
        let circuit = U254::add_without_carry(
            wires_set_from_u254(a.clone()),
            wires_set_from_u254(b.clone()),
        );
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = biguint_from_wires(circuit.0);
        let d = c.clone()
            + BigUint::from_str("2")
                .unwrap()
                .pow(U254::N_BITS.try_into().unwrap());
        let e = a + b;
        assert!(e == c || e == d);
    }

    #[test]
    fn test_sub() {
        let mut a = random_u254();
        let mut b = random_u254();
        if a < b {
            (a, b) = (b, a);
        }
        let circuit = U254::sub(
            wires_set_from_u254(a.clone()),
            wires_set_from_u254(b.clone()),
        );
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = biguint_from_wires(circuit.0);
        assert_eq!(c, a - b);
    }

    #[test]
    fn test_double() {
        let a = random_u254();
        let circuit = U254::double(wires_set_from_u254(a.clone()));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = biguint_from_wires(circuit.0);
        assert_eq!(
            c,
            (a.clone() + a.clone()) % BigUint::from_str("2").unwrap().pow(254)
        );
    }

    #[test]
    fn test_half() {
        let a = random_u254();
        let circuit = U254::half(wires_set_from_u254(a.clone()));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = biguint_from_wires(circuit.0);
        let d = a.clone() - c.clone() - c.clone();
        assert!(d == BigUint::ZERO || d == BigUint::from_str("1").unwrap());
    }

    #[test]
    fn test_odd_part() {
        let a = random_u254();
        let circuit = U254::odd_part(wires_set_from_u254(a.clone()));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = biguint_from_wires(circuit.0[0..U254::N_BITS].to_vec());
        let d = biguint_from_wires(circuit.0[U254::N_BITS..2 * U254::N_BITS].to_vec());
        assert_eq!(a, c * d);
    }

    #[test]
    fn test_optimized_sub() {
        for _ in 0..10 {
            let a = random_u254();
            let b = random_u254();
            let mut circuit = U254::optimized_sub(
                wires_set_from_u254(a.clone()),
                wires_set_from_u254(b.clone()),
                true,
            );
            circuit.gate_counts().print();
            let bound_check = circuit.0.pop().unwrap();
            let output_wires = circuit.0;
            for mut gate in circuit.1 {
                gate.evaluate();
            }
            if a < b {
                assert!(!bound_check.borrow().get_value());
            } else {
                assert!(bound_check.borrow().get_value());
                let result = biguint_from_bits(
                    output_wires
                        .iter()
                        .map(|output_wire| output_wire.borrow().get_value())
                        .collect(),
                );
                assert_eq!(result, a - b);
            }
        }
    }
}
