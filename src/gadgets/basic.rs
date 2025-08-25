use std::array;

use circuit_component_macro::component;

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
    log::trace!("selector: inputs a={}, b={}, c={}", a.0, b.0, c.0);

    let [d, f, g] = array::from_fn(|_| circuit.issue_wire());

    log::trace!("selector: issued wires d={}, f={}, g={}", d.0, f.0, g.0);

    circuit.add_gate(Gate::nand(a, c, d));
    log::trace!("selector: added gate Nand({}, {}) -> {}", a.0, c.0, d.0);

    circuit.add_gate(Gate::and_variant(c, b, f, [true, false, true]));
    log::trace!(
        "selector: added gate AndVariant({}, {}) -> {}",
        c.0,
        b.0,
        f.0
    );

    circuit.add_gate(Gate::nand(d, f, g));
    log::trace!("selector: added gate Nand({}, {}) -> {}", d.0, f.0, g.0);

    log::trace!("selector: returning wire {}", g.0);
    g
}

#[component(offcircuit_args = "w")]
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
    use test_log::test;

    use super::*;
    use crate::{circuit::CircuitBuilder, test_utils::trng};

    #[test]
    fn not_not() {
        let not_not = CircuitBuilder::streaming_execute::<[bool; 1], _, Vec<bool>>(
            [true],
            10_000,
            |circuit, wire| {
                let [mut wire] = *wire;
                circuit.add_gate(Gate::not(&mut wire));
                circuit.add_gate(Gate::not(&mut wire));

                vec![wire]
            },
        )
        .output_wires[0];
        assert!(not_not);

        let not_not_not = CircuitBuilder::streaming_execute::<[bool; 1], _, Vec<bool>>(
            [true],
            10_000,
            |circuit, wire| {
                let [mut wire] = *wire;
                circuit.add_gate(Gate::not(&mut wire));
                circuit.add_gate(Gate::not(&mut wire));
                circuit.add_gate(Gate::not(&mut wire));

                vec![wire]
            },
        )
        .output_wires[0];

        assert!(!not_not_not);
    }

    #[test]
    fn xnor_connection_test() {
        let result = CircuitBuilder::streaming_execute::<[bool; 2], _, Vec<bool>>(
            [true, true],
            10_000,
            |circuit, wires| {
                let [mut a_wire, mut b_wire] = *wires;

                circuit.add_gate(Gate::not(&mut a_wire));
                circuit.add_gate(Gate::not(&mut a_wire));

                circuit.add_gate(Gate::not(&mut b_wire));
                circuit.add_gate(Gate::not(&mut b_wire));

                let res = circuit.issue_wire();
                circuit.add_gate(Gate::and(a_wire, b_wire, res));

                vec![res]
            },
        )
        .output_wires[0];

        assert!(result);
    }

    #[test]
    fn test_half_adder() {
        let test_cases = [
            ((false, false), (false, false)),
            ((false, true), (true, false)),
            ((true, false), (true, false)),
            ((true, true), (false, true)),
        ];

        for ((a, b), (expected_result, expected_carry)) in test_cases {
            let outputs: Vec<bool> = CircuitBuilder::streaming_execute::<[bool; 2], _, Vec<bool>>(
                [a, b],
                10_000,
                |circuit, wires| {
                    let [a_wire, b_wire] = *wires;
                    let (result_wire, carry_wire) = half_adder(circuit, a_wire, b_wire);
                    vec![result_wire, carry_wire]
                },
            )
            .output_wires;

            assert_eq!(outputs[0], expected_result);
            assert_eq!(outputs[1], expected_carry);
        }
    }

    #[test]
    fn test_full_adder() {
        let test_cases = [
            ((false, false, false), (false, false)),
            ((false, false, true), (true, false)),
            ((false, true, false), (true, false)),
            ((false, true, true), (false, true)),
            ((true, false, false), (true, false)),
            ((true, false, true), (false, true)),
            ((true, true, false), (false, true)),
            ((true, true, true), (true, true)),
        ];

        for ((a, b, c), (expected_result, expected_carry)) in test_cases {
            let outputs: Vec<bool> = CircuitBuilder::streaming_execute::<[bool; 3], _, Vec<bool>>(
                [a, b, c],
                10_000,
                |circuit, wires| {
                    let [a_wire, b_wire, c_wire] = *wires;
                    let (result_wire, carry_wire) = full_adder(circuit, a_wire, b_wire, c_wire);
                    vec![result_wire, carry_wire]
                },
            )
            .output_wires;

            assert_eq!(outputs[0], expected_result);
            assert_eq!(outputs[1], expected_carry);
        }
    }

    #[test]
    fn test_half_subtracter() {
        let test_cases = [
            ((false, false), (false, false)),
            ((false, true), (true, true)),
            ((true, false), (true, false)),
            ((true, true), (false, false)),
        ];

        for ((a, b), (expected_result, expected_borrow)) in test_cases {
            let outputs: Vec<bool> = CircuitBuilder::streaming_execute::<[bool; 2], _, Vec<bool>>(
                [a, b],
                10_000,
                |circuit, wires| {
                    let [a_wire, b_wire] = *wires;
                    let (result_wire, borrow_wire) = half_subtracter(circuit, a_wire, b_wire);
                    vec![result_wire, borrow_wire]
                },
            )
            .output_wires;

            assert_eq!(outputs[0], expected_result);
            assert_eq!(outputs[1], expected_borrow);
        }
    }

    #[test]
    fn test_full_subtracter() {
        let test_cases = [
            ((false, false, false), (false, false)),
            ((false, false, true), (true, true)),
            ((false, true, false), (true, true)),
            ((false, true, true), (false, true)),
            ((true, false, false), (true, false)),
            ((true, false, true), (false, false)),
            ((true, true, false), (false, false)),
            ((true, true, true), (true, true)),
        ];

        for ((a, b, c), (expected_result, expected_carry)) in test_cases {
            let outputs: Vec<bool> = CircuitBuilder::streaming_execute::<[bool; 3], _, Vec<bool>>(
                [a, b, c],
                10_000,
                |circuit, wires| {
                    let [a_wire, b_wire, c_wire] = *wires;
                    let (result_wire, carry_wire) =
                        full_subtracter(circuit, a_wire, b_wire, c_wire);
                    vec![result_wire, carry_wire]
                },
            )
            .output_wires;

            assert_eq!(outputs[0], expected_result);
            assert_eq!(outputs[1], expected_carry);
        }
    }

    #[test]
    fn test_selector() {
        let test_cases = [
            ((false, false, false), false),
            ((false, false, true), false),
            ((false, true, false), true),
            ((false, true, true), false),
            ((true, false, false), false),
            ((true, false, true), true),
            ((true, true, false), true),
            ((true, true, true), true),
        ];

        for ((a, b, c), expected_result) in test_cases {
            let output = CircuitBuilder::streaming_execute::<[bool; 3], _, Vec<bool>>(
                [a, b, c],
                10_000,
                |circuit, wires| {
                    let [a_wire, b_wire, c_wire] = *wires;
                    let result_wire = selector(circuit, a_wire, b_wire, c_wire);
                    vec![result_wire]
                },
            )
            .output_wires[0];

            assert_eq!(output, expected_result);
        }
    }

    #[test]
    fn test_multiplexer() {
        use rand::Rng;

        use crate::circuit::streaming::{CircuitInput, EncodeInput, modes::CircuitMode};

        let mut rng = trng();

        // Test with w=3, which means 8 inputs and 3 selector bits
        // Ad-hoc structure for this test
        struct MuxInputs {
            data: [bool; 8],
            select: [bool; 3],
        }

        struct MuxWires {
            data: [WireId; 8],
            select: [WireId; 3],
        }

        impl CircuitInput for MuxInputs {
            type WireRepr = MuxWires;

            fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
                MuxWires {
                    data: array::from_fn(|_| (issue)()),
                    select: array::from_fn(|_| (issue)()),
                }
            }

            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                let mut wires = Vec::new();
                wires.extend(repr.data.iter().copied());
                wires.extend(repr.select.iter().copied());
                wires
            }
        }

        impl EncodeInput<bool> for MuxInputs {
            fn encode<M: CircuitMode<WireValue = bool>>(
                &self,
                repr: &Self::WireRepr,
                cache: &mut M,
            ) {
                for (i, &value) in self.data.iter().enumerate() {
                    cache.feed_wire(repr.data[i], value);
                }
                for (i, &value) in self.select.iter().enumerate() {
                    cache.feed_wire(repr.select[i], value);
                }
            }
        }

        // Generate random test values using array::from_fn
        let data_values: [bool; 8] = array::from_fn(|_| rng.r#gen());
        let select_values: [bool; 3] = array::from_fn(|_| rng.r#gen());

        // Calculate expected output index
        let mut u = 0;
        for &value in select_values.iter().rev() {
            u = u * 2 + if value { 1 } else { 0 };
        }
        let expected = data_values[u];

        let inputs = MuxInputs {
            data: data_values,
            select: select_values,
        };

        let output = CircuitBuilder::streaming_execute::<MuxInputs, _, Vec<bool>>(
            inputs,
            10_000,
            |circuit, wires| {
                let data_wires = wires.data.to_vec();
                let select_wires = wires.select.to_vec();

                let result_wire = multiplexer(circuit, &data_wires, &select_wires, 3);
                vec![result_wire]
            },
        )
        .output_wires[0];

        assert_eq!(output, expected);
    }
}
