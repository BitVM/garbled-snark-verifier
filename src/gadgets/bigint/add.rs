use std::iter;

use circuit_component_macro::component;

use super::{BigIntWires, BigUint, select};
use crate::{CircuitContext, Gate, WireId, circuit::streaming::FALSE_WIRE, gadgets::basic};

#[component]
pub fn add_generic<C: CircuitContext>(
    circuit: &mut C,
    a: &BigIntWires,
    b: &BigIntWires,
) -> BigIntWires {
    assert_eq!(a.len(), b.len());

    let mut bits = Vec::new();

    let (result, mut carry) = basic::half_adder(circuit, a.get(0).unwrap(), b.get(0).unwrap());
    bits.push(result);

    for i in 1..a.len() {
        let (result, new_carry) =
            basic::full_adder(circuit, a.get(i).unwrap(), b.get(i).unwrap(), carry);
        bits.push(result);
        carry = new_carry;
    }

    bits.push(carry);
    BigIntWires { bits }
}

pub fn add_without_carry<C: CircuitContext>(
    circuit: &mut C,
    a: &BigIntWires,
    b: &BigIntWires,
) -> BigIntWires {
    let mut c = add_generic(circuit, a, b);
    c.pop();
    c
}

#[component(ignore = "b")]
pub fn add_constant<C: CircuitContext>(
    circuit: &mut C,
    a: &BigIntWires,
    b: &BigUint,
) -> BigIntWires {
    assert_ne!(b, &BigUint::ZERO);
    let b_bits = super::bits_from_biguint_with_len(b, a.len()).unwrap();

    let mut first_one = 0;
    while !b_bits[first_one] {
        first_one += 1;
    }

    let mut bits = Vec::new();
    let mut carry: Option<WireId> = None;
    for i in 0..a.len() {
        let a_i = a.get(i).unwrap();
        if i < first_one {
            bits.push(a_i);
        } else if i == first_one {
            let wire = circuit.issue_wire();
            circuit.add_gate(Gate::nand(a_i, a_i, wire));
            bits.push(wire);
            carry = Some(a_i);
        } else if b_bits[i] {
            let wire_1 = circuit.issue_wire();
            let wire_2 = circuit.issue_wire();
            circuit.add_gate(Gate::xnor(a_i, carry.unwrap(), wire_1));
            circuit.add_gate(Gate::or(a_i, carry.unwrap(), wire_2));
            bits.push(wire_1);
            carry = Some(wire_2);
        } else {
            let wire_1 = circuit.issue_wire();
            let wire_2 = circuit.issue_wire();
            circuit.add_gate(Gate::xor(a_i, carry.unwrap(), wire_1));
            circuit.add_gate(Gate::and(a_i, carry.unwrap(), wire_2));
            bits.push(wire_1);
            carry = Some(wire_2);
        }
    }

    bits.push(carry.unwrap());
    BigIntWires { bits }
}

pub fn add_constant_without_carry<C: CircuitContext>(
    circuit: &mut C,
    a: &BigIntWires,
    b: &BigUint,
) -> BigIntWires {
    let mut c = add_constant(circuit, a, b);
    c.pop();
    c
}

#[component]
pub fn sub_generic<C: CircuitContext>(
    circuit: &mut C,
    a: &BigIntWires,
    b: &BigIntWires,
) -> BigIntWires {
    assert_eq!(a.len(), b.len());
    let mut bits = Vec::with_capacity(a.len() + 1);

    let (result, mut borrow) =
        basic::half_subtracter(circuit, a.get(0).unwrap(), b.get(0).unwrap());

    bits.push(result);

    for i in 1..a.len() {
        let (result, new_borrow) =
            basic::full_subtracter(circuit, a.get(i).unwrap(), b.get(i).unwrap(), borrow);
        borrow = new_borrow;
        bits.push(result);
    }

    bits.push(borrow);

    BigIntWires { bits }
}

#[component]
pub fn sub_generic_without_borrow<C: CircuitContext>(
    circuit: &mut C,
    a: &BigIntWires,
    b: &BigIntWires,
) -> BigIntWires {
    let BigIntWires { mut bits } = sub_generic(circuit, a, b);
    bits.pop();
    BigIntWires { bits }
}

#[component]
pub fn double<C: CircuitContext>(circuit: &mut C, a: &BigIntWires) -> BigIntWires {
    let zero_wire = circuit.issue_wire();
    let a_0 = a.get(0).unwrap();
    circuit.add_gate(Gate::nimp(a_0, a_0, zero_wire));

    BigIntWires {
        bits: iter::once(zero_wire).chain(a.iter().copied()).collect(),
    }
}
#[component]
pub fn double_without_overflow<C: CircuitContext>(circuit: &mut C, a: &BigIntWires) -> BigIntWires {
    let zero_wire = circuit.issue_wire();
    let a_0 = a.get(0).unwrap();
    circuit.add_gate(Gate::nimp(a_0, a_0, zero_wire));

    BigIntWires {
        bits: iter::once(zero_wire)
            .chain(a.iter().take(a.len() - 1).copied())
            .collect(),
    }
}

pub fn half<C: CircuitContext>(_circuit: &mut C, a: &BigIntWires) -> BigIntWires {
    BigIntWires {
        bits: a
            .bits
            .iter()
            .skip(1)
            .copied()
            .chain(iter::once(FALSE_WIRE))
            .collect(),
    }
}

pub fn odd_part<C: CircuitContext>(circuit: &mut C, a: &BigIntWires) -> (BigIntWires, BigIntWires) {
    let mut select_bn = BigIntWires::new(circuit, a.len() - 1);
    select_bn.insert(0, a.get(0).unwrap());

    for i in 1..a.len() {
        circuit.add_gate(Gate::or(
            select_bn.get(i - 1).unwrap(),
            a.get(i).unwrap(),
            select_bn.get(i).unwrap(),
        ));
    }

    let mut k = BigIntWires::new(circuit, a.len() - 1);
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

    use std::{array, collections::HashMap};

    use test_log::test;

    use super::*;
    use crate::{
        circuit::{
            CircuitBuilder, CircuitInput,
            streaming::{
                CircuitMode, CircuitOutput, ComponentHandle, EncodeInput, Execute, IntoWireList,
                StreamingResult,
            },
        },
        gadgets::bigint::bits_from_biguint_with_len,
    };

    struct Input<const N: usize> {
        len: usize,
        bns: [BigUint; N],
    }

    impl<const N: usize> Input<N> {
        fn new(n_bits: usize, bns: [u64; N]) -> Self {
            Self {
                len: n_bits,
                bns: bns.map(BigUint::from),
            }
        }
    }

    impl<const N: usize> CircuitInput for Input<N> {
        type WireRepr = [BigIntWires; N];

        fn allocate<C: CircuitContext>(&self, ctx: &mut C) -> Self::WireRepr {
            array::from_fn(|_| BigIntWires::new(ctx, self.len))
        }

        fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
            repr.iter().flat_map(|a| a.iter().copied()).collect()
        }
    }

    impl<const N: usize> EncodeInput<Execute> for Input<N> {
        fn encode(self, repr: &Self::WireRepr, cache: &mut Execute) {
            self.bns.iter().zip(repr.iter()).for_each(|(bn, bn_wires)| {
                let bits = bits_from_biguint_with_len(bn, self.len).unwrap();
                bn_wires.iter().zip(bits).for_each(|(w, b)| {
                    cache.feed_wire(*w, b);
                });
            });
        }
    }

    fn test_two_input_operation(
        n_bits: usize,
        a_val: u64,
        b_val: u64,
        expected: u64,
        operation: impl FnOnce(&mut ComponentHandle<Execute>, &BigIntWires, &BigIntWires) -> BigIntWires,
    ) {
        let input = Input::new(n_bits, [a_val, b_val]);

        let StreamingResult {
            output_wires,
            output_wires_ids,
            ..
        } = CircuitBuilder::streaming_execute(input, |root, input| {
            let [a, b] = input;
            let result = operation(root, a, b);
            assert_eq!(result.bits.len(), n_bits + 1);

            result.into_wire_list()
        });

        let actual_fn = output_wires_ids
            .iter()
            .zip(output_wires.iter())
            .map(|(w, v)| (*w, *v))
            .collect::<HashMap<WireId, bool>>();

        let res = BigIntWires {
            bits: output_wires_ids,
        };

        let expected_fn = res.get_wire_bits_fn(&BigUint::from(expected)).unwrap();

        let actual = res.to_bitmask(|w| actual_fn.get(&w).copied().unwrap());
        let expected = res.to_bitmask(|w| expected_fn(w).unwrap());

        assert_eq!(expected, actual);
    }

    fn test_constant_operation(
        n_bits: usize,
        a_val: u64,
        b_val: u64,
        expected: u64,
        operation: impl FnOnce(&mut ComponentHandle<Execute>, &BigIntWires, &BigUint) -> BigIntWires,
    ) {
        let input = Input::new(n_bits, [a_val]);
        let b_big = BigUint::from(b_val);

        let StreamingResult {
            output_wires,
            output_wires_ids,
            ..
        } = CircuitBuilder::streaming_execute(input, |root, input| {
            let [a] = input;
            let result = operation(root, a, &b_big);

            result.into_wire_list()
        });

        let actual_fn = output_wires_ids
            .iter()
            .zip(output_wires.iter())
            .map(|(w, v)| (*w, *v))
            .collect::<HashMap<WireId, bool>>();

        let res = BigIntWires {
            bits: output_wires_ids,
        };

        let expected_fn = res.get_wire_bits_fn(&BigUint::from(expected)).unwrap();

        let actual = res.to_bitmask(|w| actual_fn.get(&w).copied().unwrap());
        let expected = res.to_bitmask(|w| expected_fn(w).unwrap());

        assert_eq!(expected, actual)
    }

    const NUM_BITS: usize = 4;

    #[test]
    fn test_add_generic_basic() {
        test_two_input_operation(NUM_BITS, 5, 3, 8, |ctx, a, b| add_generic(ctx, a, b));
    }

    #[test]
    fn test_add_generic_with_carry() {
        test_two_input_operation(NUM_BITS, 7, 9, 16, |ctx, a, b| add_generic(ctx, a, b));
    }

    #[test]
    fn test_add_generic_max_plus_one() {
        test_two_input_operation(NUM_BITS, 15, 1, 16, |ctx, a, b| add_generic(ctx, a, b));
    }

    #[test]
    fn test_add_generic_zero_zero() {
        test_two_input_operation(NUM_BITS, 0, 0, 0, |ctx, a, b| add_generic(ctx, a, b));
    }

    #[test]
    fn test_add_generic_one_one() {
        test_two_input_operation(NUM_BITS, 1, 1, 2, |ctx, a, b| add_generic(ctx, a, b));
    }

    #[test]
    fn test_add_constant_generic_basic() {
        test_constant_operation(NUM_BITS, 5, 3, 8, |ctx, a, b| add_constant(ctx, a, b));
    }

    #[test]
    fn test_add_constant_generic_with_carry() {
        test_constant_operation(NUM_BITS, 7, 9, 16, |ctx, a, b| add_constant(ctx, a, b));
    }

    #[test]
    fn test_add_constant_generic_max_plus_one() {
        test_constant_operation(NUM_BITS, 15, 1, 16, |ctx, a, b| add_constant(ctx, a, b));
    }

    #[test]
    fn test_add_constant_generic_zero_one() {
        test_constant_operation(NUM_BITS, 0, 1, 1, |ctx, a, b| add_constant(ctx, a, b));
    }

    #[test]
    fn test_add_constant_generic_one_one() {
        test_constant_operation(NUM_BITS, 1, 1, 2, |ctx, a, b| add_constant(ctx, a, b));
    }

    #[test]
    fn test_sub_generic_basic() {
        test_two_input_operation(NUM_BITS, 8, 3, 5, |ctx, a, b| sub_generic(ctx, a, b));
    }

    #[test]
    fn test_sub_generic_zero_zero() {
        test_two_input_operation(NUM_BITS, 0, 0, 0, |ctx, a, b| sub_generic(ctx, a, b));
    }

    #[test]
    fn test_sub_generic_max_minus_one() {
        test_two_input_operation(NUM_BITS, 15, 1, 14, |ctx, a, b| sub_generic(ctx, a, b));
    }

    #[test]
    fn test_sub_generic_same_values() {
        test_two_input_operation(NUM_BITS, 7, 7, 0, |ctx, a, b| sub_generic(ctx, a, b));
    }

    fn test_single_input_operation(
        n_bits: usize,
        a_val: u64,
        expected: u64,
        operation: impl FnOnce(&mut ComponentHandle<Execute>, &BigIntWires) -> BigIntWires,
    ) {
        let input = Input::new(n_bits, [a_val]);

        let StreamingResult {
            output_wires,
            output_wires_ids,
            ..
        } = CircuitBuilder::streaming_execute(input, |root, input| {
            let [a] = input;

            let result = operation(root, a);
            assert_eq!(result.bits.len(), n_bits);

            result.into_wire_list()
        });

        let actual_fn = output_wires_ids
            .iter()
            .zip(output_wires.iter())
            .map(|(w, v)| (*w, *v))
            .collect::<HashMap<WireId, bool>>();

        let res = BigIntWires {
            bits: output_wires_ids,
        };

        let expected_fn = res.get_wire_bits_fn(&BigUint::from(expected)).unwrap();

        let actual = res.to_bitmask(|w| actual_fn.get(&w).copied().unwrap());
        let expected = res.to_bitmask(|w| expected_fn(w).unwrap());

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_half_even_number() {
        test_single_input_operation(NUM_BITS, 8, 4, |ctx, a| half(ctx, a));
    }

    #[test]
    fn test_half_odd_number() {
        test_single_input_operation(NUM_BITS, 9, 4, |ctx, a| half(ctx, a));
    }

    #[test]
    fn test_half_zero() {
        test_single_input_operation(NUM_BITS, 0, 0, |ctx, a| half(ctx, a));
    }

    #[test]
    fn test_half_one() {
        test_single_input_operation(NUM_BITS, 1, 0, |ctx, a| half(ctx, a));
    }

    #[test]
    fn test_half_max_value() {
        test_single_input_operation(NUM_BITS, 15, 7, |ctx, a| half(ctx, a));
    }

    #[test]
    fn test_odd_part_power_of_two() {
        let expected_odd = BigUint::from(1u64); // 8 >> 3
        let expected_k = BigUint::from(8u64); // 1 << 3

        let input = Input::new(8, [8]);

        struct DivOut {
            odd: BigUint,
            k: BigUint,
        }

        impl CircuitOutput<Execute> for DivOut {
            type WireRepr = [BigIntWires; 2];

            fn decode(wires: Self::WireRepr, cache: &Execute) -> Self {
                let [odd, k] = wires;

                let odd = BigUint::decode(odd, cache);
                let k = BigUint::decode(k, cache);

                Self { odd, k }
            }
        }

        let result = CircuitBuilder::<Execute>::streaming_process::<Input<_>, _, DivOut>(
            input,
            Execute::default(),
            |root, input| {
                let [a] = input;

                let (odd_result, k_result) = odd_part(root, a);

                [odd_result, k_result]
            },
        );

        assert_eq!(result.output_wires.odd, expected_odd);
        assert_eq!(result.output_wires.k, expected_k);
    }
}
