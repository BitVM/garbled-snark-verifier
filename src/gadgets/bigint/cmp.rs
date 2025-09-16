use circuit_component_macro::{bn_component, component};
use num_bigint::BigUint;

use super::BigIntWires;
use crate::{
    CircuitContext, Gate, WireId,
    gadgets::{basic, bigint::bits_from_biguint_with_len},
};

#[bn_component(arity = "a.len()")]
pub fn self_or_zero<C: CircuitContext>(circuit: &mut C, a: &BigIntWires, s: WireId) -> BigIntWires {
    BigIntWires {
        bits: a
            .iter()
            .map(|a_i| {
                let w = circuit.issue_wire();
                circuit.add_gate(Gate::and(*a_i, s, w));
                w
            })
            .collect(),
    }
}

//s is inverted
#[bn_component(arity = "a.len()")]
pub fn self_or_zero_inv<C: CircuitContext>(
    circuit: &mut C,
    a: &BigIntWires,
    s: WireId,
) -> BigIntWires {
    BigIntWires {
        bits: a
            .iter()
            .map(|a_i| {
                let w = circuit.issue_wire();
                circuit.add_gate(Gate::and_variant(*a_i, s, w, [false, true, false]));
                w
            })
            .collect(),
    }
}

#[component]
pub fn equal<C: CircuitContext>(circuit: &mut C, a: &BigIntWires, b: &BigIntWires) -> WireId {
    assert_eq!(a.len(), b.len());

    let xor_bits = a
        .iter()
        .zip(b.iter())
        .map(|(a_i, b_i)| {
            let c_i = circuit.issue_wire();
            circuit.add_gate(Gate::xor(*a_i, *b_i, c_i));
            c_i
        })
        .collect::<Vec<_>>();

    equal_constant(circuit, &BigIntWires { bits: xor_bits }, &BigUint::ZERO)
}

#[component(offcircuit_args = "b")]
pub fn equal_constant<C: CircuitContext>(circuit: &mut C, a: &BigIntWires, b: &BigUint) -> WireId {
    if b == &BigUint::ZERO {
        return equal_zero(circuit, a);
    }

    let b_bits = bits_from_biguint_with_len(b, a.len()).unwrap();
    let one_ind = b_bits.first_one().unwrap();

    let mut res = a.get(one_ind).unwrap();
    a.iter().enumerate().for_each(|(i, a_i)| {
        if i == one_ind {
            return;
        }
        let new_res = circuit.issue_wire();
        circuit.add_gate(Gate::and_variant(
            *a_i,
            res,
            new_res,
            [!b_bits[i], false, false],
        ));
        res = new_res;
    });

    res
}

#[component]
pub fn equal_zero<C: CircuitContext>(circuit: &mut C, a: &BigIntWires) -> WireId {
    if a.len() == 1 {
        let is_bit_zero = circuit.issue_wire();

        //this xor might be negated with innate NOT maintenance
        circuit.add_gate(Gate::not_with_xor(a.get(0).unwrap(), is_bit_zero));

        return is_bit_zero;
    }

    let mut res = circuit.issue_wire();
    circuit.add_gate(Gate::xnor(a.get(0).unwrap(), a.get(1).unwrap(), res));

    a.iter().skip(1).for_each(|a_i| {
        let next_res = circuit.issue_wire();
        circuit.add_gate(Gate::and_variant(*a_i, res, next_res, [true, false, false]));
        res = next_res;
    });
    res
}

#[component]
pub fn greater_than<C: CircuitContext>(
    circuit: &mut C,
    a: &BigIntWires,
    b: &BigIntWires,
) -> WireId {
    let not_b = BigIntWires {
        bits: b
            .iter()
            .map(|b_i| {
                let w = circuit.issue_wire();
                //this xor might be negated with innate NOT maintenance
                circuit.add_gate(Gate::not_with_xor(*b_i, w));
                w
            })
            .collect(),
    };

    let sum = super::add(circuit, a, &not_b);
    sum.last().unwrap()
}

#[component(offcircuit_args = "b")]
pub fn less_than_constant<C: CircuitContext>(
    circuit: &mut C,
    a: &BigIntWires,
    b: &BigUint,
) -> WireId {
    let not_a = BigIntWires {
        bits: a
            .iter()
            .map(|a_i| {
                let w = circuit.issue_wire();
                //this xor might be negated with innate NOT maintenance
                circuit.add_gate(Gate::not_with_xor(*a_i, w));
                w
            })
            .collect(),
    };

    let sum = super::add_constant(circuit, &not_a, b);
    sum.last().unwrap()
}

#[bn_component(arity = "a.len()")]
pub fn select<C: CircuitContext>(
    circuit: &mut C,
    a: &BigIntWires,
    b: &BigIntWires,
    s: WireId,
) -> BigIntWires {
    assert_eq!(a.len(), b.len());

    BigIntWires {
        bits: a
            .iter()
            .zip(b.iter())
            .map(|(a_i, b_i)| basic::selector(circuit, *a_i, *b_i, s))
            .collect(),
    }
}

#[bn_component(arity = "a[0].len()", offcircuit_args = "w")]
pub fn multiplexer<C: CircuitContext>(
    circuit: &mut C,
    a: &[BigIntWires],
    s: &[WireId],
    w: usize,
) -> BigIntWires {
    let n = 2_usize.pow(w as u32);
    assert_eq!(a.len(), n);
    let n_bits = a.first().map(|a_i| a_i.len()).unwrap();
    assert!(
        a.iter().skip(1).all(|a_i| a_i.len() == n_bits),
        "not all a consistent: {a:?}"
    );

    BigIntWires {
        bits: (0..n_bits)
            .map(|i| {
                let ith_wires = a.iter().map(|a_i| a_i.get(i).unwrap()).collect::<Vec<_>>();
                crate::gadgets::basic::multiplexer(circuit, &ith_wires, s, w)
            })
            .collect(),
    }
}

//#[cfg(test)]
//mod tests {
//    use debug;
//    use test_log::test;
//
//    use super::*;
//    use crate::{test_utils::trng};
//
//    fn test_comparison_operation(
//        n_bits: usize,
//        a_val: u64,
//        b_val: u64,
//        expected: bool,
//        operation: impl FnOnce(&mut Circuit, &BigIntWires, &BigIntWires) -> WireId,
//    ) {
//        let mut circuit = Circuit::default();
//        let a = BigIntWires::new(&mut circuit, n_bits, true, false);
//        let b = BigIntWires::new(&mut circuit, n_bits, true, false);
//        let result = operation(&mut circuit, &a, &b);
//
//        circuit.make_wire_output(result);
//
//        let a_big = BigUint::from(a_val);
//        let b_big = BigUint::from(b_val);
//
//        let a_input = a.get_wire_bits_fn(&a_big).unwrap();
//        let b_input = b.get_wire_bits_fn(&b_big).unwrap();
//
//        circuit.full_cycle_test(
//            |id| a_input(id).or_else(|| b_input(id)),
//            |wire_id| {
//                if wire_id == result {
//                    Some(expected)
//                } else {
//                    None
//                }
//            },
//            &mut trng(),
//        );
//    }
//
//    fn test_constant_comparison_operation(
//        n_bits: usize,
//        a_val: u64,
//        b_val: u64,
//        expected: bool,
//        operation: impl FnOnce(&mut Circuit, &BigIntWires, &BigUint) -> WireId,
//    ) {
//        let mut circuit = Circuit::default();
//        let a = BigIntWires::new(&mut circuit, n_bits, true, false);
//        let b_big = BigUint::from(b_val);
//        let result = operation(&mut circuit, &a, &b_big);
//
//        circuit.make_wire_output(result);
//
//        let a_big = BigUint::from(a_val);
//        let a_input = a.get_wire_bits_fn(&a_big).unwrap();
//
//        circuit.full_cycle_test(
//            a_input,
//            |wire_id| {
//                if wire_id == result {
//                    Some(expected)
//                } else {
//                    None
//                }
//            },
//            &mut trng(),
//        );
//    }
//
//    fn test_select_operation(n_bits: usize, a_val: u64, b_val: u64, selector: bool, expected: u64) {
//        let mut circuit = Circuit::default();
//
//        let a_wire = BigIntWires::new(&mut circuit, n_bits, true, false);
//        let b_wire = BigIntWires::new(&mut circuit, n_bits, true, false);
//        let s_wire = circuit.issue_input_wire();
//
//        debug!("select: if {s_wire:?} then {a_wire:?} else {b_wire:?}");
//        let result_wire = select(&mut circuit, &a_wire, &b_wire, s_wire);
//
//        let a_big = BigUint::from(a_val);
//        let b_big = BigUint::from(b_val);
//        let expected_bn = BigUint::from(expected);
//
//        let a_input = a_wire.get_wire_bits_fn(&a_big).unwrap();
//        let b_input = b_wire.get_wire_bits_fn(&b_big).unwrap();
//        let result_output = result_wire.get_wire_bits_fn(&expected_bn).unwrap();
//
//        result_wire.iter().for_each(|bit| {
//            circuit.make_wire_output(*bit);
//        });
//
//        circuit.full_cycle_test(
//            |id| {
//                if id == s_wire {
//                    return Some(selector);
//                }
//                a_input(id).or_else(|| b_input(id))
//            },
//            |wire_id| {
//                if result_wire.iter().any(|&w| w == wire_id) {
//                    result_output(wire_id)
//                } else {
//                    None
//                }
//            },
//            &mut trng(),
//        );
//    }
//
//    const NUM_BITS: usize = 4;
//
//    #[test]
//    fn test_equal_same_values() {
//        test_comparison_operation(NUM_BITS, 5, 5, true, equal);
//    }
//
//    #[test]
//    fn test_equal_different_values() {
//        test_comparison_operation(NUM_BITS, 5, 3, false, equal);
//    }
//
//    #[test]
//    fn test_equal_zero_zero() {
//        test_comparison_operation(NUM_BITS, 0, 0, true, equal);
//    }
//
//    #[test]
//    fn test_equal_constant_same() {
//        test_constant_comparison_operation(NUM_BITS, 5, 5, true, equal_constant);
//    }
//
//    #[test]
//    fn test_equal_constant_different() {
//        test_constant_comparison_operation(NUM_BITS, 5, 3, false, equal_constant);
//    }
//
//    #[test]
//    fn test_equal_constant_zero() {
//        test_constant_comparison_operation(NUM_BITS, 0, 0, true, equal_constant);
//    }
//
//    fn test_greater_than_operation(n_bits: usize, a_val: u64, b_val: u64, expected: bool) {
//        let mut circuit = Circuit::default();
//        let a = BigIntWires::new(&mut circuit, n_bits, true, false);
//        let b = BigIntWires::new(&mut circuit, n_bits, true, false);
//
//        let a_big = BigUint::from(a_val);
//        let b_big = BigUint::from(b_val);
//
//        let a_input = a.get_wire_bits_fn(&a_big).unwrap();
//        let b_input = b.get_wire_bits_fn(&b_big).unwrap();
//
//        let result = greater_than(&mut circuit, &a, &b);
//
//        circuit.make_wire_output(result);
//
//        let output = circuit
//            .garble(&mut trng())
//            .unwrap()
//            .evaluate(|id| a_input(id).or_else(|| b_input(id)))
//            .unwrap_or_else(|err| panic!("Can't eval with {err:#?}"))
//            .check_correctness()
//            .unwrap_or_else(|err| panic!("Circuit not correct with {err:#?}"))
//            .iter_output()
//            .find(|r| r.0 == result)
//            .unwrap()
//            .1;
//
//        assert_eq!(output, expected);
//    }
//
//    #[test]
//    fn test_greater_than_true() {
//        test_greater_than_operation(NUM_BITS, 8, 3, true);
//    }
//
//    #[test]
//    fn test_greater_than_false() {
//        test_greater_than_operation(NUM_BITS, 3, 8, false);
//    }
//
//    #[test]
//    fn test_greater_than_equal() {
//        test_greater_than_operation(NUM_BITS, 5, 5, false);
//    }
//
//    #[test]
//    fn test_less_than_constant_true() {
//        test_constant_comparison_operation(NUM_BITS, 3, 8, true, less_than_constant);
//    }
//
//    #[test]
//    fn test_less_than_constant_false() {
//        test_constant_comparison_operation(NUM_BITS, 8, 3, false, less_than_constant);
//    }
//
//    #[test]
//    fn test_less_than_constant_equal() {
//        test_constant_comparison_operation(NUM_BITS, 5, 5, false, less_than_constant);
//    }
//
//    #[test]
//    fn test_select_first() {
//        test_select_operation(NUM_BITS, 5, 3, true, 5);
//    }
//
//    #[test]
//    fn test_select_second() {
//        test_select_operation(NUM_BITS, 5, 3, false, 3);
//    }
//
//    #[test]
//    fn test_select_zero() {
//        test_select_operation(NUM_BITS, 0, 7, true, 0);
//    }
//}
