use std::array;

use crate::{CircuitContext, Gate, GateType, WireId};

pub fn half_adder<C: CircuitContext>(circuit: &mut C, a: WireId, b: WireId) -> (WireId, WireId) {
    let result = circuit.issue_wire();
    let carry = circuit.issue_wire();

    circuit.add_gate(Gate::new(GateType::Xor, a, b, result));
    circuit.add_gate(Gate::new(GateType::And, a, b, carry));

    (result, carry)
}

pub fn full_adder<C: CircuitContext>(
    circuit: &mut C,
    a: WireId,
    b: WireId,
    c: WireId,
) -> (WireId, WireId) {
    let [axc, bxc, result, t, carry] = array::from_fn(|_| circuit.issue_wire());

    circuit.add_gate(Gate::new(GateType::Xor, a, c, axc));
    circuit.add_gate(Gate::new(GateType::Xor, b, c, bxc));
    circuit.add_gate(Gate::new(GateType::Xor, a, bxc, result));
    circuit.add_gate(Gate::new(GateType::And, axc, bxc, t));
    circuit.add_gate(Gate::new(GateType::Xor, c, t, carry));

    (result, carry)
}

pub fn half_subtracter<C: CircuitContext>(
    circuit: &mut C,
    a: WireId,
    b: WireId,
) -> (WireId, WireId) {
    let result = circuit.issue_wire();
    let borrow = circuit.issue_wire();

    circuit.add_gate(Gate::new(GateType::Xor, a, b, result));
    circuit.add_gate(Gate::and_variant(a, b, borrow, [true, false, false]));

    (result, borrow)
}

pub fn full_subtracter<C: CircuitContext>(
    circuit: &mut C,
    a: WireId,
    b: WireId,
    c: WireId,
) -> (WireId, WireId) {
    let [bxa, bxc, result, t, carry] = array::from_fn(|_| circuit.issue_wire());

    circuit.add_gate(Gate::new(GateType::Xor, a, b, bxa));
    circuit.add_gate(Gate::new(GateType::Xor, b, c, bxc));
    circuit.add_gate(Gate::new(GateType::Xor, bxa, c, result));
    circuit.add_gate(Gate::new(GateType::And, bxa, bxc, t));
    circuit.add_gate(Gate::new(GateType::Xor, c, t, carry));

    (result, carry)
}

pub fn selector<C: CircuitContext>(circuit: &mut C, a: WireId, b: WireId, c: WireId) -> WireId {
    let [d, f, g] = array::from_fn(|_| circuit.issue_wire());

    circuit.add_gate(Gate::nand(a, c, d));
    circuit.add_gate(Gate::and_variant(c, b, f, [true, false, true]));
    circuit.add_gate(Gate::nand(d, f, g));

    g
}

pub fn multiplexer<C: CircuitContext>(
    circuit: &mut C,
    a: &[WireId],
    s: &[WireId],
    w: usize,
) -> WireId {
    let n = 2_usize.pow(w.try_into().unwrap());
    assert_eq!(a.len(), n);
    assert_eq!(s.len(), w);

    if w == 1 {
        return selector(circuit, a[1], a[0], s[0]);
    }

    let a1 = &a[0..(n / 2)];
    let a2 = &a[(n / 2)..n];
    let su = &s[0..w - 1];
    let sv = s[w - 1];

    let b1 = multiplexer(circuit, a1, su, w - 1);
    let b2 = multiplexer(circuit, a2, su, w - 1);

    selector(circuit, b2, b1, sv)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use test_log::test;

    use super::*;
    use crate::{Circuit, test_utils::trng};

    #[test]
    fn not_not() {
        let mut circuit = Circuit::default();

        let mut wire = circuit.issue_input_wire();
        circuit.make_wire_output(wire);

        circuit.add_gate(Gate::not(&mut wire));
        circuit.add_gate(Gate::not(&mut wire));

        circuit.full_cycle_test(|_id| Some(true), |_wire_id| Some(true), &mut trng());

        circuit.add_gate(Gate::not(&mut wire));

        circuit.full_cycle_test(|_id| Some(true), |_wire_id| Some(false), &mut trng());
    }

    #[test]
    fn xnor_connection_test() {
        let mut circuit = Circuit::default();

        let mut a_wire = circuit.issue_input_wire();
        let mut b_wire = circuit.issue_input_wire();

        let res = circuit.issue_wire();

        circuit.add_gate(Gate::not(&mut a_wire));
        circuit.add_gate(Gate::not(&mut a_wire));

        circuit.add_gate(Gate::not(&mut b_wire));
        circuit.add_gate(Gate::not(&mut b_wire));

        circuit.add_gate(Gate::and(a_wire, b_wire, res));

        circuit.make_wire_output(res);

        circuit.full_cycle_test(|_id| Some(true), |_wire_id| Some(true), &mut trng());
    }

    #[test]
    fn test_half_adder() {
        let result = [
            ((false, false), (false, false)),
            ((false, true), (true, false)),
            ((true, false), (true, false)),
            ((true, true), (false, true)),
        ];

        for ((a, b), (c, d)) in result {
            let mut circuit = Circuit::default();

            let a_wire = circuit.issue_input_wire();
            let b_wire = circuit.issue_input_wire();

            let (result_wire, carry_wire) = half_adder(&mut circuit, a_wire, b_wire);
            circuit.make_wire_output(result_wire);
            circuit.make_wire_output(carry_wire);

            circuit
                .garble(&mut trng())
                .unwrap()
                .evaluate(|id| {
                    if id == a_wire {
                        Some(a)
                    } else if id == b_wire {
                        Some(b)
                    } else {
                        None
                    }
                })
                .unwrap()
                .iter_output()
                .for_each(|(wire_id, value)| {
                    if wire_id == result_wire {
                        assert_eq!(value, c);
                    } else if wire_id == carry_wire {
                        assert_eq!(value, d);
                    } else {
                        unreachable!("no output Wire like that {wire_id}")
                    }
                });
        }
    }

    #[test]
    fn test_full_adder() {
        let result = [
            ((false, false, false), (false, false)),
            ((false, false, true), (true, false)),
            ((false, true, false), (true, false)),
            ((false, true, true), (false, true)),
            ((true, false, false), (true, false)),
            ((true, false, true), (false, true)),
            ((true, true, false), (false, true)),
            ((true, true, true), (true, true)),
        ];

        for ((a, b, c), (d, e)) in result {
            let mut circuit = Circuit::default();

            let a_wire = circuit.issue_input_wire();
            let b_wire = circuit.issue_input_wire();
            let c_wire = circuit.issue_input_wire();

            let (result_wire, carry_wire) = full_adder(&mut circuit, a_wire, b_wire, c_wire);
            circuit.make_wire_output(result_wire);
            circuit.make_wire_output(carry_wire);

            let input = [(a_wire, a), (b_wire, b), (c_wire, c)]
                .into_iter()
                .collect::<HashMap<WireId, bool>>();
            circuit
                .garble(&mut trng())
                .unwrap()
                .evaluate(|id| input.get(&id).copied())
                .unwrap()
                .iter_output()
                .for_each(|(wire_id, value)| {
                    if wire_id == result_wire {
                        assert_eq!(value, d);
                    } else if wire_id == carry_wire {
                        assert_eq!(value, e);
                    } else {
                        unreachable!("no output Wire like that {wire_id}")
                    }
                });
        }
    }

    #[test]
    fn test_half_subtracter() {
        let result = [
            ((false, false), (false, false)),
            ((false, true), (true, true)),
            ((true, false), (true, false)),
            ((true, true), (false, false)),
        ];

        for ((a, b), (c, d)) in result {
            let mut circuit = Circuit::default();

            let a_wire = circuit.issue_input_wire();
            let b_wire = circuit.issue_input_wire();

            let (result_wire, borrow_wire) = half_subtracter(&mut circuit, a_wire, b_wire);
            circuit.make_wire_output(result_wire);
            circuit.make_wire_output(borrow_wire);

            circuit
                .garble(&mut trng())
                .unwrap()
                .evaluate(|id| id.eq(&a_wire).then_some(a).or(id.eq(&b_wire).then_some(b)))
                .unwrap()
                .iter_output()
                .for_each(|(wire_id, value)| {
                    if wire_id == result_wire {
                        assert_eq!(value, c);
                    } else if wire_id == borrow_wire {
                        assert_eq!(value, d);
                    } else {
                        unreachable!("no output Wire like that {wire_id}")
                    }
                });
        }
    }

    #[test]
    fn test_full_subtracter() {
        let result = [
            ((false, false, false), (false, false)),
            ((false, false, true), (true, true)),
            ((false, true, false), (true, true)),
            ((false, true, true), (false, true)),
            ((true, false, false), (true, false)),
            ((true, false, true), (false, false)),
            ((true, true, false), (false, false)),
            ((true, true, true), (true, true)),
        ];

        for ((a, b, c), (d, e)) in result {
            let mut circuit = Circuit::default();

            let a_wire = circuit.issue_input_wire();
            let b_wire = circuit.issue_input_wire();
            let c_wire = circuit.issue_input_wire();

            let (result_wire, carry_wire) = full_subtracter(&mut circuit, a_wire, b_wire, c_wire);
            circuit.make_wire_output(result_wire);
            circuit.make_wire_output(carry_wire);

            let input = [(a_wire, a), (b_wire, b), (c_wire, c)]
                .into_iter()
                .collect::<HashMap<WireId, bool>>();
            circuit
                .garble(&mut trng())
                .unwrap()
                .evaluate(|id| input.get(&id).copied())
                .unwrap()
                .iter_output()
                .for_each(|(wire_id, value)| {
                    if wire_id == result_wire {
                        assert_eq!(value, d);
                    } else if wire_id == carry_wire {
                        assert_eq!(value, e);
                    } else {
                        unreachable!("no output Wire like that {wire_id}")
                    }
                });
        }
    }

    #[test]
    fn test_selector() {
        let result = [
            ((false, false, false), false),
            ((false, false, true), false),
            ((false, true, false), true),
            ((false, true, true), false),
            ((true, false, false), false),
            ((true, false, true), true),
            ((true, true, false), true),
            ((true, true, true), true),
        ];

        for ((a, b, c), d) in result {
            let mut circuit = Circuit::default();

            let a_wire = circuit.issue_input_wire();
            let b_wire = circuit.issue_input_wire();
            let c_wire = circuit.issue_input_wire();

            let result_wire = selector(&mut circuit, a_wire, b_wire, c_wire);
            circuit.make_wire_output(result_wire);

            let input = [(a_wire, a), (b_wire, b), (c_wire, c)]
                .into_iter()
                .collect::<HashMap<WireId, bool>>();

            circuit
                .garble(&mut trng())
                .unwrap()
                .evaluate(|id| input.get(&id).copied())
                .unwrap()
                .iter_output()
                .for_each(|(wire_id, value)| {
                    if wire_id == result_wire {
                        assert_eq!(value, d);
                    } else {
                        unreachable!("no output Wire like that {wire_id}")
                    }
                });
        }
    }

    #[test]
    fn test_multiplexer() {
        use rand::Rng;
        let mut rng = rand::rng();

        let w = 3;
        let n = 2_usize.pow(w as u32);

        let mut circuit = Circuit::default();

        let a: Vec<WireId> = (0..n).map(|_| circuit.issue_input_wire()).collect();
        let s: Vec<WireId> = (0..w).map(|_| circuit.issue_input_wire()).collect();

        let a_values: Vec<bool> = (0..n).map(|_| rng.random()).collect();
        let s_values: Vec<bool> = (0..w).map(|_| rng.random()).collect();

        let mut u = 0;
        for &value in s_values.iter().rev() {
            u = u * 2 + if value { 1 } else { 0 };
        }

        let result_wire = multiplexer(&mut circuit, &a, &s, w);
        circuit.make_wire_output(result_wire);

        let mut input = HashMap::new();
        for (i, &wire) in a.iter().enumerate() {
            input.insert(wire, a_values[i]);
        }
        for (i, &wire) in s.iter().enumerate() {
            input.insert(wire, s_values[i]);
        }

        circuit
            .garble(&mut trng())
            .unwrap()
            .evaluate(|id| input.get(&id).copied())
            .unwrap()
            .iter_output()
            .for_each(|(wire_id, value)| {
                if wire_id == result_wire {
                    assert_eq!(value, a_values[u]);
                } else {
                    unreachable!("no output Wire like that {wire_id}")
                }
            });
    }
}
