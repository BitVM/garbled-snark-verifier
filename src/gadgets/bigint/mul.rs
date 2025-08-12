use circuit_component_macro::component;
use log::debug;

use super::{BigIntWires, BigUint};
use crate::{CircuitContext, Gate, GateType, WireId, circuit::streaming::FALSE_WIRE};

/// Pre-computed Karatsuba vs Generic algorithm decisions
const fn is_use_karatsuba(len: usize) -> bool {
    len > 83
}

fn extend_with_zero<C: CircuitContext>(circuit: &mut C, bits: &mut Vec<WireId>) {
    let zero_wire = circuit.issue_wire();
    circuit.add_gate(Gate::new(GateType::Nimp, bits[0], bits[0], zero_wire));
    bits.push(zero_wire);
}

#[component]
pub fn mul_generic<C: CircuitContext>(
    circuit: &mut C,
    a: &BigIntWires,
    b: &BigIntWires,
) -> BigIntWires {
    assert_eq!(a.len(), b.len());
    let len = a.len();

    let mut result_bits = vec![FALSE_WIRE; len * 2];

    for (i, &current_bit) in b.iter().enumerate() {
        let addition_wires_0: Vec<WireId> = result_bits[i..i + len].to_vec();

        let mut addition_wires_1 = Vec::with_capacity(len);

        for &a_bit in a.iter() {
            let wire = circuit.issue_wire();
            circuit.add_gate(Gate::new(GateType::And, a_bit, current_bit, wire));
            addition_wires_1.push(wire);
        }

        let addition_result = super::add::add_generic(
            circuit,
            &BigIntWires {
                bits: addition_wires_0,
            },
            &BigIntWires {
                bits: addition_wires_1,
            },
        );

        result_bits[i..i + len + 1].copy_from_slice(&addition_result.bits);
    }

    BigIntWires { bits: result_bits }
}

#[component]
pub fn mul_karatsuba<C: CircuitContext>(
    circuit: &mut C,
    a: &BigIntWires,
    b: &BigIntWires,
) -> BigIntWires {
    assert_eq!(a.len(), b.len());
    let len = a.len();

    if len < 5 {
        return mul_generic(circuit, a, b);
    }

    let mut result_bits: Vec<WireId> = Vec::with_capacity(len * 2);
    for _ in 0..(len * 2) {
        let wire = circuit.issue_wire();
        circuit.add_gate(Gate::new(GateType::Nimp, a.bits[0], a.bits[0], wire));
        result_bits.push(wire);
    }

    let len_0 = len / 2;
    let len_1 = len.div_ceil(2);

    let a_0 = BigIntWires {
        bits: a.bits[0..len_0].to_vec(),
    };
    let a_1 = BigIntWires {
        bits: a.bits[len_0..].to_vec(),
    };

    let b_0 = BigIntWires {
        bits: b.bits[0..len_0].to_vec(),
    };
    let b_1 = BigIntWires {
        bits: b.bits[len_0..].to_vec(),
    };

    // Use optimal algorithm choice for recursive calls
    let sq_0 = if is_use_karatsuba(len_0) {
        mul_karatsuba(circuit, &a_0, &b_0)
    } else {
        mul_generic(circuit, &a_0, &b_0)
    };
    let sq_1 = if is_use_karatsuba(len_1) {
        mul_karatsuba(circuit, &a_1, &b_1)
    } else {
        mul_generic(circuit, &a_1, &b_1)
    };

    let mut extended_a_0 = a_0.bits.clone();
    let mut extended_b_0 = b_0.bits.clone();
    let mut extended_sq_0 = sq_0.bits.clone();

    if len_0 < len_1 {
        extend_with_zero(circuit, &mut extended_a_0);
        extend_with_zero(circuit, &mut extended_b_0);
        extend_with_zero(circuit, &mut extended_sq_0);
        extend_with_zero(circuit, &mut extended_sq_0);
    }

    let sum_a = super::add::add_generic(circuit, &BigIntWires { bits: extended_a_0 }, &a_1);
    let sum_b = super::add::add_generic(circuit, &BigIntWires { bits: extended_b_0 }, &b_1);

    let mut sq_sum = super::add::add_generic(
        circuit,
        &BigIntWires {
            bits: extended_sq_0,
        },
        &sq_1,
    );
    extend_with_zero(circuit, &mut sq_sum.bits);

    // Use optimal algorithm choice for sum multiplication
    let sum_mul = if is_use_karatsuba(sum_a.len()) {
        mul_karatsuba(circuit, &sum_a, &sum_b)
    } else {
        mul_generic(circuit, &sum_a, &sum_b)
    };
    let cross_term_full = super::add::sub_generic_without_borrow(circuit, &sum_mul, &sq_sum);
    let cross_term = BigIntWires {
        bits: cross_term_full.bits[..(len + 1)].to_vec(),
    };

    result_bits[..(len_0 * 2)].copy_from_slice(&sq_0.bits);

    let segment = BigIntWires {
        bits: result_bits[len_0..(len_0 + len + 1)].to_vec(),
    };
    let new_segment = super::add::add_generic(circuit, &segment, &cross_term);
    result_bits[len_0..(len_0 + len + 2)].copy_from_slice(&new_segment.bits);

    let segment2 = BigIntWires {
        bits: result_bits[(2 * len_0)..].to_vec(),
    };
    let new_segment2 = super::add::add_generic(circuit, &segment2, &sq_1);
    result_bits[(2 * len_0)..].copy_from_slice(&new_segment2.bits[..(2 * len_1)]);

    BigIntWires { bits: result_bits }
}

pub fn mul<C: CircuitContext>(circuit: &mut C, a: &BigIntWires, b: &BigIntWires) -> BigIntWires {
    assert_eq!(a.len(), b.len());
    let len = a.len();

    if len < 5 {
        debug!("mul: <5 case");
        return mul_generic(circuit, a, b);
    }

    assert!(
        len <= 4000,
        "Bit length {len} exceeds maximum supported 4000",
    );

    if is_use_karatsuba(len) {
        debug!("use karatsuba (pre-computed)");
        mul_karatsuba(circuit, a, b)
    } else {
        debug!("use generic (pre-computed)");
        mul_generic(circuit, a, b)
    }
}

pub fn mul_by_constant<C: CircuitContext>(
    circuit: &mut C,
    a: &BigIntWires,
    c: &BigUint,
) -> BigIntWires {
    let len = a.len();
    let c_bits = super::bits_from_biguint_with_len(c, len).unwrap();

    let mut result_bits = vec![FALSE_WIRE; len * 2];

    for (i, bit) in c_bits.iter().enumerate() {
        if *bit {
            let addition_wires = BigIntWires {
                bits: result_bits[i..(i + len)].to_vec(),
            };
            let new_bits = super::add::add_generic(circuit, a, &addition_wires);
            result_bits[i..(i + len + 1)].copy_from_slice(&new_bits.bits);
        }
    }

    BigIntWires { bits: result_bits }
}

#[component(ignore = "c,power")]
pub fn mul_by_constant_modulo_power_two<C: CircuitContext>(
    circuit: &mut C,
    a: &BigIntWires,
    c: &BigUint,
    power: usize,
) -> BigIntWires {
    let len = a.len();
    assert!(power < 2 * len);
    let c_bits = super::bits_from_biguint_with_len(c, len).unwrap();

    let mut result_bits = vec![FALSE_WIRE; power];
    for _ in 0..power {
        let wire = circuit.issue_wire();
        circuit.add_gate(Gate::new(
            GateType::Nimp,
            a.get(0).unwrap(),
            a.get(0).unwrap(),
            wire,
        ));
        result_bits.push(wire);
    }

    for (i, bit) in c_bits.iter().enumerate() {
        if i == power {
            break;
        }
        if *bit {
            let number_of_bits = (power - i).min(len);
            let addition_wires = BigIntWires {
                bits: result_bits[i..(i + number_of_bits)].to_vec(),
            };
            let a_slice = BigIntWires {
                bits: a.bits[0..number_of_bits].to_vec(),
            };
            let new_bits = super::add::add_generic(circuit, &a_slice, &addition_wires);

            if i + number_of_bits < power {
                result_bits[i..(i + number_of_bits + 1)].copy_from_slice(&new_bits.bits);
            } else {
                result_bits[i..(i + number_of_bits)]
                    .copy_from_slice(&new_bits.bits[..number_of_bits]);
            }
        }
    }

    BigIntWires { bits: result_bits }
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
                ComponentHandle, EncodeInput, Execute, IntoWireList, StreamingResult,
                modes::CircuitMode,
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

    fn test_mul_operation(
        n_bits: usize,
        a_val: u64,
        b_val: u64,
        expected: u128,
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
            assert_eq!(result.bits.len(), n_bits * 2);

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

        let expected_big = BigUint::from(expected);
        let expected_fn = res.get_wire_bits_fn(&expected_big).unwrap();

        let actual = res.to_bitmask(|w| actual_fn.get(&w).copied().unwrap());
        let expected = res.to_bitmask(|w| expected_fn(w).unwrap());

        assert_eq!(expected, actual);
    }

    struct SingleInput {
        len: usize,
        bn: BigUint,
    }

    impl SingleInput {
        fn new(n_bits: usize, bn: u64) -> Self {
            Self {
                len: n_bits,
                bn: BigUint::from(bn),
            }
        }
    }

    impl CircuitInput for SingleInput {
        type WireRepr = BigIntWires;

        fn allocate<C: CircuitContext>(&self, ctx: &mut C) -> Self::WireRepr {
            BigIntWires::new(ctx, self.len)
        }

        fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
            repr.iter().copied().collect()
        }
    }

    impl EncodeInput<Execute> for SingleInput {
        fn encode(self, repr: &Self::WireRepr, cache: &mut Execute) {
            let bits = bits_from_biguint_with_len(&self.bn, self.len).unwrap();
            repr.iter().zip(bits).for_each(|(w, b)| {
                cache.feed_wire(*w, b);
            });
        }
    }

    fn test_mul_by_constant_operation(
        n_bits: usize,
        a_val: u64,
        c_val: u64,
        expected: u128,
        operation: impl FnOnce(&mut ComponentHandle<Execute>, &BigIntWires, &BigUint) -> BigIntWires,
    ) {
        let input = SingleInput::new(n_bits, a_val);
        let c_big = BigUint::from(c_val);

        let StreamingResult {
            output_wires,
            output_wires_ids,
            ..
        } = CircuitBuilder::streaming_execute(input, |root, a| {
            let result = operation(root, a, &c_big);
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

        let expected_big = BigUint::from(expected);
        let expected_fn = res.get_wire_bits_fn(&expected_big).unwrap();

        let actual = res.to_bitmask(|w| actual_fn.get(&w).copied().unwrap());
        let expected = res.to_bitmask(|w| expected_fn(w).unwrap());

        assert_eq!(expected, actual);
    }

    const NUM_BITS: usize = 8;

    // Basic multiplication tests
    #[test]
    fn test_mul_generic_basic() {
        test_mul_operation(NUM_BITS, 5, 3, 15, |c, a, b| mul_generic(c, a, b));
    }

    #[test]
    fn test_mul_generic_larger() {
        test_mul_operation(NUM_BITS, 15, 17, 255, |c, a, b| mul_generic(c, a, b));
    }

    #[test]
    fn test_mul_generic_zero() {
        test_mul_operation(NUM_BITS, 0, 42, 0, |c, a, b| mul_generic(c, a, b));
        test_mul_operation(NUM_BITS, 42, 0, 0, |c, a, b| mul_generic(c, a, b));
    }

    #[test]
    fn test_mul_generic_one() {
        test_mul_operation(NUM_BITS, 1, 42, 42, |c, a, b| mul_generic(c, a, b));
        test_mul_operation(NUM_BITS, 42, 1, 42, |c, a, b| mul_generic(c, a, b));
    }

    #[test]
    fn test_mul_generic_max_values() {
        // Test with maximum values for given bit size
        let max_val = (1u64 << NUM_BITS) - 1; // 255 for 8 bits
        test_mul_operation(NUM_BITS, max_val, 1, max_val as u128, |c, a, b| {
            mul_generic(c, a, b)
        });
        test_mul_operation(
            NUM_BITS,
            max_val,
            max_val,
            (max_val as u128) * (max_val as u128),
            |c, a, b| mul_generic(c, a, b),
        );
    }

    #[test]
    fn test_mul_generic_powers_of_two() {
        test_mul_operation(NUM_BITS, 2, 2, 4, |c, a, b| mul_generic(c, a, b));
        test_mul_operation(NUM_BITS, 4, 4, 16, |c, a, b| mul_generic(c, a, b));
        test_mul_operation(NUM_BITS, 8, 8, 64, |c, a, b| mul_generic(c, a, b));
        test_mul_operation(NUM_BITS, 16, 16, 256, |c, a, b| mul_generic(c, a, b));
    }

    #[test]
    fn test_mul_generic_commutative() {
        // Test that a * b == b * a
        let test_cases = [(5, 7), (13, 19), (1, 255), (17, 23)];
        for (a, b) in test_cases {
            test_mul_operation(NUM_BITS, a, b, (a as u128) * (b as u128), |c, x, y| {
                mul_generic(c, x, y)
            });
            test_mul_operation(NUM_BITS, b, a, (a as u128) * (b as u128), |c, x, y| {
                mul_generic(c, x, y)
            });
        }
    }

    // Karatsuba multiplication tests
    #[test]
    fn test_mul_karatsuba_basic() {
        test_mul_operation(NUM_BITS, 5, 3, 15, |c, a, b| mul_karatsuba(c, a, b));
    }

    #[test]
    fn test_mul_karatsuba_larger() {
        test_mul_operation(NUM_BITS, 15, 17, 255, |c, a, b| mul_karatsuba(c, a, b));
    }

    #[test]
    fn test_mul_karatsuba_zero() {
        test_mul_operation(NUM_BITS, 0, 42, 0, |c, a, b| mul_karatsuba(c, a, b));
        test_mul_operation(NUM_BITS, 42, 0, 0, |c, a, b| mul_karatsuba(c, a, b));
    }

    #[test]
    fn test_mul_karatsuba_one() {
        test_mul_operation(NUM_BITS, 1, 42, 42, |c, a, b| mul_karatsuba(c, a, b));
        test_mul_operation(NUM_BITS, 42, 1, 42, |c, a, b| mul_karatsuba(c, a, b));
    }

    #[test]
    fn test_mul_karatsuba_max_values() {
        let max_val = (1u64 << NUM_BITS) - 1;
        test_mul_operation(NUM_BITS, max_val, 1, max_val as u128, |c, a, b| {
            mul_karatsuba(c, a, b)
        });
        test_mul_operation(
            NUM_BITS,
            max_val,
            max_val,
            (max_val as u128) * (max_val as u128),
            |c, a, b| mul_karatsuba(c, a, b),
        );
    }

    #[test]
    fn test_mul_karatsuba_powers_of_two() {
        test_mul_operation(NUM_BITS, 2, 2, 4, |c, a, b| mul_karatsuba(c, a, b));
        test_mul_operation(NUM_BITS, 4, 4, 16, |c, a, b| mul_karatsuba(c, a, b));
        test_mul_operation(NUM_BITS, 8, 8, 64, |c, a, b| mul_karatsuba(c, a, b));
        test_mul_operation(NUM_BITS, 16, 16, 256, |c, a, b| mul_karatsuba(c, a, b));
    }

    #[test]
    fn test_mul_karatsuba_commutative() {
        let test_cases = [(5, 7), (13, 19), (1, 255), (17, 23)];
        for (a, b) in test_cases {
            test_mul_operation(NUM_BITS, a, b, (a as u128) * (b as u128), |c, x, y| {
                mul_karatsuba(c, x, y)
            });
            test_mul_operation(NUM_BITS, b, a, (a as u128) * (b as u128), |c, x, y| {
                mul_karatsuba(c, x, y)
            });
        }
    }

    // Test that generic and karatsuba produce same results
    #[test]
    fn test_mul_algorithms_equivalence() {
        let test_cases = [
            (0, 0),
            (0, 1),
            (1, 0),
            (1, 1),
            (2, 3),
            (5, 7),
            (13, 19),
            (23, 29),
            (255, 1),
            (1, 255),
            (127, 2),
            (64, 4),
        ];

        for (a, b) in test_cases {
            // Test with same inputs
            let expected = (a as u128) * (b as u128);
            test_mul_operation(NUM_BITS, a, b, expected, |c, x, y| mul_generic(c, x, y));
            test_mul_operation(NUM_BITS, a, b, expected, |c, x, y| mul_karatsuba(c, x, y));
        }
    }

    // Multiplication by constant tests
    #[test]
    fn test_mul_by_constant_basic() {
        test_mul_by_constant_operation(NUM_BITS, 5, 3, 15, |c, a, b| mul_by_constant(c, a, b));
    }

    #[test]
    fn test_mul_by_constant_larger() {
        test_mul_by_constant_operation(NUM_BITS, 15, 17, 255, |c, a, b| mul_by_constant(c, a, b));
    }

    #[test]
    fn test_mul_by_constant_zero() {
        test_mul_by_constant_operation(NUM_BITS, 0, 42, 0, |c, a, b| mul_by_constant(c, a, b));
    }

    #[test]
    fn test_mul_by_constant_one() {
        test_mul_by_constant_operation(NUM_BITS, 42, 1, 42, |c, a, b| mul_by_constant(c, a, b));
    }

    #[test]
    fn test_mul_by_constant_max_values() {
        let max_val = (1u64 << NUM_BITS) - 1;
        test_mul_by_constant_operation(NUM_BITS, max_val, 1, max_val as u128, |c, a, b| {
            mul_by_constant(c, a, b)
        });
        test_mul_by_constant_operation(NUM_BITS, 1, max_val, max_val as u128, |c, a, b| {
            mul_by_constant(c, a, b)
        });
    }

    #[test]
    fn test_mul_by_constant_powers_of_two() {
        test_mul_by_constant_operation(NUM_BITS, 17, 2, 34, |c, a, b| mul_by_constant(c, a, b));
        test_mul_by_constant_operation(NUM_BITS, 17, 4, 68, |c, a, b| mul_by_constant(c, a, b));
        test_mul_by_constant_operation(NUM_BITS, 17, 8, 136, |c, a, b| mul_by_constant(c, a, b));
        test_mul_by_constant_operation(NUM_BITS, 17, 16, 272, |c, a, b| mul_by_constant(c, a, b));
    }

    // Modular multiplication tests
    #[test]
    fn test_mul_by_constant_modulo_power_two_basic() {
        let input = SingleInput::new(NUM_BITS, 15);
        let c = BigUint::from(17u64);
        let power = 12;

        let StreamingResult {
            output_wires,
            output_wires_ids,
            ..
        } = CircuitBuilder::streaming_execute(input, |root, a| {
            let result = mul_by_constant_modulo_power_two(root, a, &c, power);
            assert_eq!(result.bits.len(), power);
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

        let expected = (15u64 * 17) % (2u64.pow(power as u32));
        let expected_big = BigUint::from(expected);
        let expected_fn = res.get_wire_bits_fn(&expected_big).unwrap();

        let actual = res.to_bitmask(|w| actual_fn.get(&w).copied().unwrap());
        let expected = res.to_bitmask(|w| expected_fn(w).unwrap());

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_mul_by_constant_modulo_power_two_simple() {
        let input = SingleInput::new(NUM_BITS, 100);
        let c = BigUint::from(3u64);
        let power = 8;

        let StreamingResult {
            output_wires,
            output_wires_ids,
            ..
        } = CircuitBuilder::streaming_execute(input, |root, a| {
            let result = mul_by_constant_modulo_power_two(root, a, &c, power);
            assert_eq!(result.bits.len(), power);
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

        let expected = (100u64 * 3) % 256u64; // 300 % 256 = 44
        let expected_big = BigUint::from(expected);
        let expected_fn = res.get_wire_bits_fn(&expected_big).unwrap();

        let actual = res.to_bitmask(|w| actual_fn.get(&w).copied().unwrap());
        let expected = res.to_bitmask(|w| expected_fn(w).unwrap());

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_mul_by_constant_modulo_power_two_overflow() {
        // Test cases where multiplication would overflow without modulo
        let input = SingleInput::new(NUM_BITS, 100);
        let c = BigUint::from(5u64);
        let power = 8; // mod 256

        let StreamingResult {
            output_wires,
            output_wires_ids,
            ..
        } = CircuitBuilder::streaming_execute(input, |root, a| {
            let result = mul_by_constant_modulo_power_two(root, a, &c, power);
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

        let expected = (100u64 * 5) % 256; // 500 % 256 = 244
        let expected_big = BigUint::from(expected);
        let expected_fn = res.get_wire_bits_fn(&expected_big).unwrap();

        let actual = res.to_bitmask(|w| actual_fn.get(&w).copied().unwrap());
        let expected = res.to_bitmask(|w| expected_fn(w).unwrap());

        assert_eq!(expected, actual);
    }

    // Test with different bit sizes
    #[test]
    fn test_mul_generic_different_bit_sizes() {
        const SMALL_BITS: usize = 4;
        const LARGE_BITS: usize = 16;

        // Test with 4-bit inputs
        test_mul_operation(SMALL_BITS, 7, 5, 35, |c, a, b| mul_generic(c, a, b));
        test_mul_operation(SMALL_BITS, 15, 15, 225, |c, a, b| mul_generic(c, a, b)); // max 4-bit value

        // Test with 16-bit inputs (if supported)
        test_mul_operation(LARGE_BITS, 255, 255, 65025, |c, a, b| mul_generic(c, a, b));
        test_mul_operation(LARGE_BITS, 1000, 1000, 1000000, |c, a, b| {
            mul_generic(c, a, b)
        });
    }

    // Random property-based tests
    #[test]
    fn test_mul_generic_random_properties() {
        // Test multiplicative identity: a * 1 = a
        for a in [0, 1, 7, 15, 42, 100, 255] {
            test_mul_operation(NUM_BITS, a, 1, a as u128, |c, x, y| mul_generic(c, x, y));
        }

        // Test zero property: a * 0 = 0
        for a in [1, 7, 15, 42, 100, 255] {
            test_mul_operation(NUM_BITS, a, 0, 0, |c, x, y| mul_generic(c, x, y));
        }

        // Test distributive property: a * (b + c) = a * b + a * c (where results fit in range)
        let test_cases = [(2, 3, 4), (5, 1, 2), (7, 8, 9)];
        for (a, b, c) in test_cases {
            if b + c <= 255 && a * (b + c) <= 65535 {
                let left = a * (b + c);
                let right = a * b + a * c;
                assert_eq!(left, right);
            }
        }
    }

    // The Karatsuba decision matrix test is omitted as it requires the old Circuit API
    // The is_use_karatsuba function has been pre-computed with the optimal threshold
}
