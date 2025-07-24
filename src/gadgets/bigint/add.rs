use std::iter;

use super::{select, BigIntWires, BigUint};
use crate::{Circuit, Gate, WireId};

pub fn add_generic(circuit: &mut Circuit, a: &BigIntWires, b: &BigIntWires) -> BigIntWires {
    assert_eq!(a.len(), b.len());

    let mut bits = Vec::new();

    let (result, mut carry) = circuit.half_adder(a.bits[0], b.bits[0]);
    bits.push(result);

    for i in 1..a.len() {
        let (result, new_carry) = circuit.full_adder(a.bits[i], b.bits[i], carry);
        bits.push(result);
        carry = new_carry;
    }

    bits.push(carry);
    BigIntWires { bits }
}

pub fn add_without_carry(circuit: &mut Circuit, a: &BigIntWires, b: &BigIntWires) -> BigIntWires {
    let mut c = add_generic(circuit, a, b);
    c.pop();
    c
}

pub fn add_constant(circuit: &mut Circuit, a: &BigIntWires, b: &BigUint) -> BigIntWires {
    assert_ne!(b, &BigUint::ZERO);
    let b_bits = super::bits_from_biguint_with_len(b, a.len()).unwrap();

    let mut first_one = 0;
    while !b_bits[first_one] {
        first_one += 1;
    }

    let mut bits = Vec::new();
    let mut carry: Option<WireId> = None;
    for i in 0..a.len() {
        if i < first_one {
            bits.push(a.bits[i]);
        } else if i == first_one {
            let wire = circuit.issue_wire();
            circuit.add_gate(Gate::nand(a.bits[i], a.bits[i], wire));
            bits.push(wire);
            carry = Some(a.bits[i]);
        } else if b_bits[i] {
            let wire_1 = circuit.issue_wire();
            let wire_2 = circuit.issue_wire();
            circuit.add_gate(Gate::xnor(a.bits[i], carry.unwrap(), wire_1));
            circuit.add_gate(Gate::or(a.bits[i], carry.unwrap(), wire_2));
            bits.push(wire_1);
            carry = Some(wire_2);
        } else {
            let wire_1 = circuit.issue_wire();
            let wire_2 = circuit.issue_wire();
            circuit.add_gate(Gate::xor(a.bits[i], carry.unwrap(), wire_1));
            circuit.add_gate(Gate::and(a.bits[i], carry.unwrap(), wire_2));
            bits.push(wire_1);
            carry = Some(wire_2);
        }
    }

    bits.push(carry.unwrap());
    BigIntWires { bits }
}

pub fn add_constant_without_carry(
    circuit: &mut Circuit,
    a: &BigIntWires,
    b: &BigUint,
) -> BigIntWires {
    let mut c = add_constant(circuit, a, b);
    c.pop();
    c
}

pub fn sub_generic(circuit: &mut Circuit, a: &BigIntWires, b: &BigIntWires) -> BigIntWires {
    assert_eq!(a.len(), b.len());
    let mut bits = Vec::with_capacity(a.len() + 1);

    let (result, mut borrow) = circuit.half_subtracter(a.bits[0], b.bits[0]);

    bits.push(result);

    for i in 1..a.len() {
        let (result, new_borrow) = circuit.full_subtracter(a.bits[i], b.bits[i], borrow);
        borrow = new_borrow;
        bits.push(result);
    }

    bits.push(borrow);

    BigIntWires { bits }
}

pub fn sub_generic_without_borrow(
    circuit: &mut Circuit,
    a: &BigIntWires,
    b: &BigIntWires,
) -> BigIntWires {
    let BigIntWires { mut bits } = sub_generic(circuit, a, b);
    bits.pop();
    BigIntWires { bits }
}

pub fn double(circuit: &mut Circuit, a: &BigIntWires) -> BigIntWires {
    let zero_wire = circuit.issue_wire();
    circuit.add_gate(Gate::nimp(a.bits[0], a.bits[0], zero_wire));

    BigIntWires {
        bits: iter::once(zero_wire)
            .chain(a.bits.iter().copied())
            .collect(),
    }
}

//    pub fn double_without_overflow(a: Wires) -> Circuit {
//        assert_eq!(a.len(), N_BITS);
//        let mut circuit = Circuit::empty();
//        let not_a = new_wirex();
//        let zero_wire = new_wirex();
//        circuit.add(Gate::not(a[0].clone(), not_a.clone()));
//        circuit.add(Gate::and(a[0].clone(), not_a.clone(), zero_wire.clone()));
//        circuit.add_wire(zero_wire);
//        circuit.add_wires(a[0..N_BITS - 1].to_vec());
//        circuit
//    }
pub fn double_without_overflow(circuit: &mut Circuit, a: &BigIntWires) -> BigIntWires {
    let zero_wire = circuit.issue_wire();
    circuit.add_gate(Gate::nimp(a.bits[0], a.bits[0], zero_wire));

    BigIntWires {
        bits: iter::once(zero_wire)
            .chain(a.bits.iter().take(a.bits.len() - 1).copied())
            .collect(),
    }
}

pub fn half(circuit: &mut Circuit, a: &BigIntWires) -> BigIntWires {
    let false_ = circuit.get_false_wire_constant();

    BigIntWires {
        bits: a
            .bits
            .iter()
            .skip(1)
            .copied()
            .chain(iter::once(false_))
            .collect(),
    }
}

pub fn odd_part(circuit: &mut Circuit, a: &BigIntWires) -> (BigIntWires, BigIntWires) {
    let mut select_bn = BigIntWires::new(circuit, a.len() - 1, false, false);
    select_bn.insert(0, a.get(0).unwrap());

    for i in 1..a.len() {
        circuit.add_gate(Gate::or(
            select_bn.get(i - 1).unwrap(),
            a.get(i).unwrap(),
            select_bn.get(i).unwrap(),
        ));
    }

    let mut k = BigIntWires::new(circuit, a.len() - 1, false, false);
    k.insert(0, a.get(0).unwrap());

    for i in 1..a.len() {
        circuit.add_gate(Gate::and_variant(
            select_bn.get(i - 1).unwrap(),
            a.get(i).unwrap(),
            k.get(i).unwrap(),
            [true, false, false],
        ));
    }

    let mut odd_acc = a.clone(); // needs `Clone` on BigIntWires

    for i in 0..a.len() {
        let half_res = half(circuit, &odd_acc);
        odd_acc = select(circuit, &odd_acc, &half_res, select_bn.get(i).unwrap());
    }

    (odd_acc, k)
}

#[cfg(test)]
mod tests {

    use std::collections::HashMap;

    use test_log::test;

    use super::*;
    use crate::test_utils::trng;

    fn test_two_input_operation(
        n_bits: usize,
        a_val: u64,
        b_val: u64,
        expected: u64,
        operation: impl FnOnce(&mut Circuit, &BigIntWires, &BigIntWires) -> BigIntWires,
    ) {
        let mut circuit = Circuit::default();
        let a = BigIntWires::new(&mut circuit, n_bits, true, false);
        let b = BigIntWires::new(&mut circuit, n_bits, true, false);
        let result = operation(&mut circuit, &a, &b);
        assert_eq!(result.bits.len(), n_bits + 1);

        result.bits.iter().for_each(|bit| {
            circuit.make_wire_output(*bit);
        });

        let a_big = BigUint::from(a_val);
        let b_big = BigUint::from(b_val);
        let expected_big = BigUint::from(expected);

        let a_input = a.get_wire_bits_fn(&a_big).unwrap();
        let b_input = b.get_wire_bits_fn(&b_big).unwrap();
        let get_expected_result_fn = result.get_wire_bits_fn(&expected_big).unwrap();

        circuit.full_cycle_test(
            |id| a_input(id).or_else(|| b_input(id)),
            get_expected_result_fn,
            &mut trng(),
        );
    }

    fn test_constant_operation(
        n_bits: usize,
        a_val: u64,
        b_val: u64,
        expected: u64,
        operation: impl FnOnce(&mut Circuit, &BigIntWires, &BigUint) -> BigIntWires,
    ) {
        let mut circuit = Circuit::default();

        let a = BigIntWires::new(&mut circuit, n_bits, true, false);
        let b_big = BigUint::from(b_val);
        let result = operation(&mut circuit, &a, &b_big);

        for bit in result.bits.iter() {
            circuit.make_wire_output(*bit);
        }

        let a_big = BigUint::from(a_val);
        let a_input = a.get_wire_bits_fn(&a_big).unwrap();
        let expected_big = BigUint::from(expected);
        let get_expected_result_fn = result.get_wire_bits_fn(&expected_big).unwrap();

        circuit.full_cycle_test(a_input, get_expected_result_fn, &mut trng());
    }

    const NUM_BITS: usize = 4;

    #[test]
    fn test_add_generic_basic() {
        test_two_input_operation(NUM_BITS, 5, 3, 8, add_generic);
    }

    #[test]
    fn test_add_generic_with_carry() {
        test_two_input_operation(NUM_BITS, 7, 9, 16, add_generic);
    }

    #[test]
    fn test_add_generic_max_plus_one() {
        test_two_input_operation(NUM_BITS, 15, 1, 16, add_generic);
    }

    #[test]
    fn test_add_generic_zero_zero() {
        test_two_input_operation(NUM_BITS, 0, 0, 0, add_generic);
    }

    #[test]
    fn test_add_generic_one_one() {
        test_two_input_operation(NUM_BITS, 1, 1, 2, add_generic);
    }

    #[test]
    fn test_add_constant_generic_basic() {
        test_constant_operation(NUM_BITS, 5, 3, 8, add_constant);
    }

    #[test]
    fn test_add_constant_generic_with_carry() {
        test_constant_operation(NUM_BITS, 7, 9, 16, add_constant);
    }

    #[test]
    fn test_add_constant_generic_max_plus_one() {
        test_constant_operation(NUM_BITS, 15, 1, 16, add_constant);
    }

    #[test]
    fn test_add_constant_generic_zero_one() {
        test_constant_operation(NUM_BITS, 0, 1, 1, add_constant);
    }

    #[test]
    fn test_add_constant_generic_one_one() {
        test_constant_operation(NUM_BITS, 1, 1, 2, add_constant);
    }

    #[test]
    fn test_sub_generic_basic() {
        test_two_input_operation(NUM_BITS, 8, 3, 5, sub_generic);
    }

    #[test]
    fn test_sub_generic_zero_zero() {
        test_two_input_operation(NUM_BITS, 0, 0, 0, sub_generic);
    }

    #[test]
    fn test_sub_generic_max_minus_one() {
        test_two_input_operation(NUM_BITS, 15, 1, 14, sub_generic);
    }

    #[test]
    fn test_sub_generic_same_values() {
        test_two_input_operation(NUM_BITS, 7, 7, 0, sub_generic);
    }

    fn test_single_input_operation(
        n_bits: usize,
        a_val: u64,
        expected: u64,
        operation: impl FnOnce(&mut Circuit, &BigIntWires) -> BigIntWires,
    ) {
        let mut circuit = Circuit::default();
        let a = BigIntWires::new(&mut circuit, n_bits, true, false);
        let result = operation(&mut circuit, &a);
        assert_eq!(result.bits.len(), n_bits);

        result.mark_as_output(&mut circuit);

        let a_big = BigUint::from(a_val);
        let expected_big = BigUint::from(expected);

        let a_input = a.get_wire_bits_fn(&a_big).unwrap();
        let get_expected_result_fn = result.get_wire_bits_fn(&expected_big).unwrap();

        circuit.full_cycle_test(a_input, get_expected_result_fn, &mut trng());
    }

    #[test]
    fn test_half_even_number() {
        test_single_input_operation(NUM_BITS, 8, 4, half);
    }

    #[test]
    fn test_half_odd_number() {
        test_single_input_operation(NUM_BITS, 9, 4, half);
    }

    #[test]
    fn test_half_zero() {
        test_single_input_operation(NUM_BITS, 0, 0, half);
    }

    #[test]
    fn test_half_one() {
        test_single_input_operation(NUM_BITS, 1, 0, half);
    }

    #[test]
    fn test_half_max_value() {
        test_single_input_operation(NUM_BITS, 15, 7, half);
    }

    #[test]
    fn test_odd_part_power_of_two() {
        // Input: 8 (binary 1000)
        // Expected: odd_part = 1 (0001), k = 8 (1000)
        let mut circuit = Circuit::default();
        let a = BigIntWires::new(&mut circuit, NUM_BITS, true, false);
        let (odd_result, k_result) = odd_part(&mut circuit, &a);

        odd_result.mark_as_output(&mut circuit);
        k_result.mark_as_output(&mut circuit);

        let input_val = BigUint::from(8u64);
        let expected_odd = BigUint::from(1u64); // 8 >> 3
        let expected_k = BigUint::from(8u64); // 1 << 3

        let a_input = a.get_wire_bits_fn(&input_val).unwrap();
        let expected_odd_fn = odd_result.get_wire_bits_fn(&expected_odd).unwrap();
        let expected_k_fn = k_result.get_wire_bits_fn(&expected_k).unwrap();

        let output = circuit
            .simple_evaluate(a_input)
            .unwrap()
            .collect::<HashMap<WireId, bool>>();

        let expected_odd_bitmask = odd_result.to_bitmask(|w| expected_odd_fn(w).unwrap());
        let expected_k_bitmask = k_result.to_bitmask(|w| expected_k_fn(w).unwrap());

        let actual_odd_bitmask = odd_result.to_bitmask(|w| *output.get(&w).unwrap());
        let actual_k_bitmask = k_result.to_bitmask(|w| *output.get(&w).unwrap());

        assert_eq!(
            (expected_odd_bitmask, expected_k_bitmask),
            (actual_odd_bitmask, actual_k_bitmask)
        );
    }
}
