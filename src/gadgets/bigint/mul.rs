use circuit_component_macro::bn_component;
use tracing::{debug, trace};

use super::{BigIntWires, BigUint, add};
use crate::{CircuitContext, Gate, GateType, WireId, circuit::FALSE_WIRE};

/// Pre-computed Karatsuba vs Naive algorithm decisions
const fn is_use_karatsuba(len: usize) -> bool {
    match len {
        21 => false,
        other => other > 19,
    }
}

fn extend_with_zero<C: CircuitContext>(_circuit: &mut C, bits: &mut Vec<WireId>) {
    bits.push(FALSE_WIRE);
}

#[bn_component(arity = "a.len() * 2")]
pub fn mul_naive<C: CircuitContext>(
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

        let addition_result = add::add(
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

#[bn_component(arity = "a.len() * 2")]
pub fn mul_karatsuba<C: CircuitContext>(
    circuit: &mut C,
    a: &BigIntWires,
    b: &BigIntWires,
) -> BigIntWires {
    assert_eq!(a.len(), b.len());
    let len = a.len();

    if len < 5 {
        return mul_naive(circuit, a, b);
    }

    let mut result_bits = vec![FALSE_WIRE; len * 2];

    let len_0 = len / 2;
    let len_1 = len.div_ceil(2);

    let (a_0, a_1) = (*a).clone().split_at(len_0);
    let (b_0, b_1) = (*b).clone().split_at(len_0);

    // Use optimal algorithm choice for recursive calls
    debug!(
        "  Computing sq_0: len_0={}, use_karatsuba={}",
        len_0,
        is_use_karatsuba(len_0)
    );

    let sq_0 = if is_use_karatsuba(len_0) {
        mul_karatsuba(circuit, &a_0, &b_0)
    } else {
        mul_naive(circuit, &a_0, &b_0)
    };

    trace!(
        "  sq_0 result (first 8): {:?}",
        &sq_0.bits[0..sq_0.bits.len().min(8)]
    );

    debug!(
        "  Computing sq_1: len_1={}, use_karatsuba={}",
        len_1,
        is_use_karatsuba(len_1)
    );

    let sq_1 = if is_use_karatsuba(len_1) {
        mul_karatsuba(circuit, &a_1, &b_1)
    } else {
        mul_naive(circuit, &a_1, &b_1)
    };

    trace!(
        "  sq_1 result (first 8): {:?}",
        &sq_1.bits[0..sq_1.bits.len().min(8)]
    );

    let mut extended_a_0 = a_0.bits.clone();
    let mut extended_b_0 = b_0.bits.clone();
    let mut extended_sq_0 = sq_0.bits.clone();

    if len_0 < len_1 {
        extend_with_zero(circuit, &mut extended_a_0);
        extend_with_zero(circuit, &mut extended_b_0);
        extend_with_zero(circuit, &mut extended_sq_0);
        extend_with_zero(circuit, &mut extended_sq_0);
    }

    let sum_a = add::add(circuit, &BigIntWires { bits: extended_a_0 }, &a_1);
    let sum_b = add::add(circuit, &BigIntWires { bits: extended_b_0 }, &b_1);

    let mut sq_sum = add::add(
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
        mul_naive(circuit, &sum_a, &sum_b)
    };

    let cross_term_full = add::sub_without_borrow(circuit, &sum_mul, &sq_sum);
    let cross_term = BigIntWires {
        bits: cross_term_full.bits[..(len + 1)].to_vec(),
    };

    trace!(
        "  cross_term (first 8): {:?}",
        &cross_term.bits[0..cross_term.bits.len().min(8)]
    );

    result_bits[..(len_0 * 2)].copy_from_slice(&sq_0.bits);
    trace!(
        "  After copying sq_0 to result[0..{}]: {:?}",
        len_0 * 2,
        &result_bits[0..16.min(result_bits.len())]
    );

    let segment = BigIntWires {
        bits: result_bits[len_0..(len_0 + len + 1)].to_vec(),
    };
    trace!("  segment for cross_term addition: {:?}", &segment.bits);
    let new_segment = add::add(circuit, &segment, &cross_term);
    trace!("  new_segment after addition: {:?}", &new_segment.bits);
    result_bits[len_0..(len_0 + len + 2)].copy_from_slice(&new_segment.bits);
    trace!(
        "  After adding cross_term: {:?}",
        &result_bits[0..16.min(result_bits.len())]
    );

    let segment2 = BigIntWires {
        bits: result_bits[(2 * len_0)..].to_vec(),
    };
    trace!("  segment2 for sq_1 addition: {:?}", &segment2.bits);
    let new_segment2 = add::add(circuit, &segment2, &sq_1);
    trace!("  new_segment2 after addition: {:?}", &new_segment2.bits);
    result_bits[(2 * len_0)..].copy_from_slice(&new_segment2.bits[..(2 * len_1)]);
    trace!("  Final result_bits: {:?}", &result_bits);

    BigIntWires { bits: result_bits }
}

pub fn mul<C: CircuitContext>(circuit: &mut C, a: &BigIntWires, b: &BigIntWires) -> BigIntWires {
    assert_eq!(a.len(), b.len());
    let len = a.len();

    if len < 5 {
        debug!("mul: <5 case");
        return mul_naive(circuit, a, b);
    }

    assert!(
        len <= 4000,
        "Bit length {len} exceeds maximum supported 4000",
    );

    if is_use_karatsuba(len) {
        debug!("use karatsuba (pre-computed)");
        mul_karatsuba(circuit, a, b)
    } else {
        debug!("use naive (pre-computed)");
        mul_naive(circuit, a, b)
    }
}

#[bn_component(arity = "a.len() * 2", offcircuit_args = "c")]
pub fn mul_by_constant<C: CircuitContext>(
    circuit: &mut C,
    a: &BigIntWires,
    c: &BigUint,
) -> BigIntWires {
    let len = a.len();

    // Running accumulator: 2*len bits, starts at zero.
    let mut acc = vec![FALSE_WIRE; len * 2];

    super::bits_from_biguint_with_len(c, len)
        .expect("constant must fit into `len` bits")
        .into_iter()
        .enumerate()
        .filter_map(|(i, bit)| if bit { Some(i) } else { None })
        .for_each(|i| {
            let addition_wires = acc[i..(i + len)].to_vec();

            let new_bits = add::add(
                circuit,
                a,
                &BigIntWires {
                    bits: addition_wires,
                },
            );

            acc[i..(i + len + 1)].clone_from_slice(&new_bits.bits[..((i + len - i) + 1)]);
        });

    BigIntWires { bits: acc }
}

#[bn_component(arity = "power", offcircuit_args = "c,power")]
pub fn mul_by_constant_modulo_power_two<C: CircuitContext>(
    circuit: &mut C,
    a: &BigIntWires,
    c: &BigUint,
    power: usize,
) -> BigIntWires {
    const PER_CHUNK: usize = 8;

    let len = a.len();
    assert!(power < 2 * len, "power must be < 2*len");

    // Collect indices of 1-bits, but only those that can affect the lower `power` bits.
    let ones: Vec<usize> = super::bits_from_biguint_with_len(c, len)
        .expect("constant must fit into `len` bits")
        .into_iter()
        .enumerate()
        .filter_map(|(i, bit)| (i < power && bit).then_some(i))
        .collect();

    // Running accumulator of size `power` (we work modulo 2^power).
    let mut result_bits = vec![FALSE_WIRE; power];

    if ones.is_empty() {
        return BigIntWires { bits: result_bits };
    }

    // Process the 1-bits in chunks to keep each child frame small.
    for (chunk_idx, chunk) in ones.chunks(PER_CHUNK).enumerate() {
        // Move current accumulator into the child and also pass `a` wires.
        let prev = result_bits;

        // Own the chunk indices to avoid lifetime fuss.
        let chunk_indices: Vec<usize> = chunk.to_vec();

        let input_wires_len = a.len() + prev.len();
        let a_len_bytes = a.len().to_le_bytes();
        let power_bytes = power.to_le_bytes();
        let chunk_idx_bytes = chunk_idx.to_le_bytes();

        result_bits = circuit.with_named_child(
            crate::component_key!(
                "mul_by_const_mod_2p",
                a_len = &a_len_bytes[..],
                power = &power_bytes[..],
                chunk_idx = &chunk_idx_bytes[..];
                power,
                input_wires_len
            ),
            (a.bits.clone(), prev),
            move |ctx, inputs| {
                let (a, mut res) = inputs.clone();
                let a = BigIntWires { bits: a };

                for &i in &chunk_indices {
                    // We can only add as many bits as fit before `power`.
                    let number_of_bits = (power - i).min(len);
                    if number_of_bits == 0 {
                        continue; // nothing contributes beyond power
                    }

                    // Add low `number_of_bits` of `a` into res[i..] (i.e. (a & ((1<<nb)-1)) << i)
                    let a_slice = BigIntWires {
                        bits: a.bits[0..number_of_bits].to_vec(),
                    };
                    let addition_wires = BigIntWires {
                        bits: res[i..(i + number_of_bits)].to_vec(),
                    };

                    let new_bits = add::add(ctx, &a_slice, &addition_wires);

                    // Write back; carry may spill one extra bit if it still lies under `power`.
                    if i + number_of_bits < power {
                        res[i..(i + number_of_bits + 1)].copy_from_slice(&new_bits.bits);
                    } else {
                        // The +1 would exceed `power`; drop the final carry bit.
                        res[i..(i + number_of_bits)]
                            .copy_from_slice(&new_bits.bits[..number_of_bits]);
                    }
                }

                res
            },
            power,
        );
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
            CircuitBuilder, CircuitInput, EncodeInput, StreamingResult, WiresObject,
            modes::{CircuitMode, Execute, ExecuteMode},
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

        fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
            array::from_fn(|_| BigIntWires::new(&mut issue, self.len))
        }

        fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
            repr.iter().flat_map(|a| a.iter().copied()).collect()
        }
    }

    impl<const N: usize, M: CircuitMode<WireValue = bool>> EncodeInput<M> for Input<N> {
        fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
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
        operation: impl Fn(&mut Execute, &BigIntWires, &BigIntWires) -> BigIntWires,
    ) {
        debug!(
            "test_mul_operation: {} * {} = {} (n_bits={})",
            a_val, b_val, expected, n_bits
        );

        let input = Input::new(n_bits, [a_val, b_val]);

        let StreamingResult {
            output_value: output_wires,
            output_wires_ids,
            ..
        }: crate::circuit::StreamingResult<ExecuteMode, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(input, 10_000, |root, input| {
                let [a, b] = input;
                trace!("Input A wire IDs: {:?}", &a.bits);
                trace!("Input B wire IDs: {:?}", &b.bits);

                let result = operation(root, a, b);

                debug!(
                    "Result wire IDs (first 16): {:?}",
                    &result.bits[0..result.bits.len().min(16)]
                );
                // ARITY CHECK: Verify that mul operations return n_bits * 2 wires
                assert_eq!(
                    result.bits.len(),
                    n_bits * 2,
                    "Arity check failed: expected {} wires, got {}",
                    n_bits * 2,
                    result.bits.len()
                );

                result.to_wires_vec()
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

        debug!("Expected bitmask: {}", expected);
        debug!("Actual bitmask:   {}", actual);

        // Log individual wire values for debugging
        for (i, wire_id) in res.bits.iter().enumerate().take(16) {
            let actual_val = actual_fn.get(wire_id).copied().unwrap_or(false);
            let expected_val = expected_fn(*wire_id).unwrap_or(false);
            trace!(
                "Wire[{}] (ID: {:?}): actual={}, expected={}",
                i, wire_id, actual_val, expected_val
            );
        }

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

        fn allocate(&self, issue: impl FnMut() -> WireId) -> Self::WireRepr {
            BigIntWires::new(issue, self.len)
        }

        fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
            repr.iter().copied().collect()
        }
    }

    impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for SingleInput {
        fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
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
        operation: impl Fn(&mut Execute, &BigIntWires, &BigUint) -> BigIntWires,
    ) {
        let input = SingleInput::new(n_bits, a_val);
        let c_big = BigUint::from(c_val);

        let StreamingResult {
            output_value: output_wires,
            output_wires_ids,
            ..
        }: crate::circuit::StreamingResult<ExecuteMode, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(input, 10_000, |root, a| {
                let result = operation(root, a, &c_big);
                result.to_wires_vec()
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

        debug!("Expected bitmask: {}", expected);
        debug!("Actual bitmask:   {}", actual);

        // Log individual wire values for debugging
        for (i, wire_id) in res.bits.iter().enumerate().take(16) {
            let actual_val = actual_fn.get(wire_id).copied().unwrap_or(false);
            let expected_val = expected_fn(*wire_id).unwrap_or(false);
            trace!(
                "Wire[{}] (ID: {:?}): actual={}, expected={}",
                i, wire_id, actual_val, expected_val
            );
        }

        assert_eq!(expected, actual);
    }

    const NUM_BITS: usize = 8;

    // Basic multiplication tests
    #[test]
    fn test_mul_naive_basic() {
        test_mul_operation(100, 5, 3, 15, mul_naive);
    }

    #[test]
    fn test_mul_naive_larger() {
        test_mul_operation(NUM_BITS, 15, 17, 255, mul_naive);
    }

    #[test]
    fn test_mul_naive_zero() {
        test_mul_operation(NUM_BITS, 0, 42, 0, mul_naive);
        test_mul_operation(NUM_BITS, 42, 0, 0, mul_naive);
    }

    #[test]
    fn test_mul_naive_one() {
        test_mul_operation(NUM_BITS, 1, 42, 42, mul_naive);
        test_mul_operation(NUM_BITS, 42, 1, 42, mul_naive);
    }

    #[test]
    fn test_mul_naive_max_values() {
        // Test with maximum values for given bit size
        let max_val = (1u64 << NUM_BITS) - 1; // 255 for 8 bits
        test_mul_operation(NUM_BITS, max_val, 1, max_val as u128, |c, a, b| {
            mul_naive(c, a, b)
        });
        test_mul_operation(
            NUM_BITS,
            max_val,
            max_val,
            (max_val as u128) * (max_val as u128),
            mul_naive,
        );
    }

    #[test]
    fn test_mul_naive_powers_of_two() {
        test_mul_operation(NUM_BITS, 2, 2, 4, mul_naive);
        test_mul_operation(NUM_BITS, 4, 4, 16, mul_naive);
        test_mul_operation(NUM_BITS, 8, 8, 64, mul_naive);
        test_mul_operation(NUM_BITS, 16, 16, 256, mul_naive);
    }

    #[test]
    fn test_mul_naive_commutative() {
        // Test that a * b == b * a
        let test_cases = [(5, 7), (13, 19), (1, 255), (17, 23)];
        for (a, b) in test_cases {
            test_mul_operation(NUM_BITS, a, b, (a as u128) * (b as u128), |c, x, y| {
                mul_naive(c, x, y)
            });
            test_mul_operation(NUM_BITS, b, a, (a as u128) * (b as u128), |c, x, y| {
                mul_naive(c, x, y)
            });
        }
    }

    // Karatsuba multiplication tests
    #[test]
    fn test_mul_karatsuba_basic() {
        test_mul_operation(NUM_BITS, 5, 5, 25, mul_karatsuba);
    }

    #[test]
    fn test_mul_karatsuba_larger() {
        test_mul_operation(NUM_BITS, 15, 17, 255, mul_karatsuba);
    }

    #[test]
    fn test_mul_karatsuba_zero() {
        test_mul_operation(NUM_BITS, 0, 42, 0, mul_karatsuba);
        test_mul_operation(NUM_BITS, 42, 0, 0, mul_karatsuba);
    }

    #[test]
    fn test_mul_karatsuba_one() {
        test_mul_operation(NUM_BITS, 1, 42, 42, mul_karatsuba);
        test_mul_operation(NUM_BITS, 42, 1, 42, mul_karatsuba);
    }

    #[test]
    fn test_mul_karatsuba_minimal() {
        // Minimal size that triggers Karatsuba (needs >= 5 bits)
        test_mul_operation(5, 1, 1, 1, mul_karatsuba);
        test_mul_operation(5, 1, 2, 2, mul_karatsuba);
        test_mul_operation(6, 1, 3, 3, mul_karatsuba);
        test_mul_operation(8, 1, 42, 42, mul_karatsuba);
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
            mul_karatsuba,
        );
    }

    #[test]
    fn test_mul_karatsuba_powers_of_two() {
        test_mul_operation(NUM_BITS, 2, 2, 4, mul_karatsuba);
        test_mul_operation(NUM_BITS, 4, 4, 16, mul_karatsuba);
        test_mul_operation(NUM_BITS, 8, 8, 64, mul_karatsuba);
        test_mul_operation(NUM_BITS, 16, 16, 256, mul_karatsuba);
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

    // Test that naive and karatsuba produce same results
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
            test_mul_operation(NUM_BITS, a, b, expected, mul_naive);
            test_mul_operation(NUM_BITS, a, b, expected, mul_karatsuba);
        }
    }

    // Multiplication by constant tests
    #[test]
    fn test_mul_by_constant_basic() {
        test_mul_by_constant_operation(NUM_BITS, 5, 3, 15, mul_by_constant);
    }

    #[test]
    fn test_mul_by_constant_larger() {
        test_mul_by_constant_operation(NUM_BITS, 15, 17, 255, mul_by_constant);
    }

    #[test]
    fn test_mul_by_constant_zero() {
        test_mul_by_constant_operation(NUM_BITS, 0, 42, 0, mul_by_constant);
    }

    #[test]
    fn test_mul_by_constant_one() {
        test_mul_by_constant_operation(NUM_BITS, 42, 1, 42, mul_by_constant);
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
        test_mul_by_constant_operation(NUM_BITS, 17, 2, 34, mul_by_constant);
        test_mul_by_constant_operation(NUM_BITS, 17, 4, 68, mul_by_constant);
        test_mul_by_constant_operation(NUM_BITS, 17, 8, 136, mul_by_constant);
        test_mul_by_constant_operation(NUM_BITS, 17, 16, 272, mul_by_constant);
    }

    // Modular multiplication tests
    #[test]
    fn test_mul_by_constant_modulo_power_two_basic() {
        let input = SingleInput::new(NUM_BITS, 15);
        let c = BigUint::from(17u64);
        let power = 12;

        let StreamingResult {
            output_value,
            output_wires_ids,
            ..
        }: crate::circuit::StreamingResult<ExecuteMode, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(input, 10_000, |root, a| {
                let result = mul_by_constant_modulo_power_two(root, a, &c, power);
                assert_eq!(result.bits.len(), power);
                result.to_wires_vec()
            });

        let actual_fn = output_wires_ids
            .iter()
            .zip(output_value.iter())
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

        debug!("Expected bitmask: {}", expected);
        debug!("Actual bitmask:   {}", actual);

        // Log individual wire values for debugging
        for (i, wire_id) in res.bits.iter().enumerate().take(16) {
            let actual_val = actual_fn.get(wire_id).copied().unwrap_or(false);
            let expected_val = expected_fn(*wire_id).unwrap_or(false);
            trace!(
                "Wire[{}] (ID: {:?}): actual={}, expected={}",
                i, wire_id, actual_val, expected_val
            );
        }

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_mul_by_constant_modulo_power_two_simple() {
        let input = SingleInput::new(NUM_BITS, 100);
        let c = BigUint::from(3u64);
        let power = 8;

        let StreamingResult {
            output_value,
            output_wires_ids,
            ..
        }: crate::circuit::StreamingResult<ExecuteMode, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(input, 10_000, |root, a| {
                let result = mul_by_constant_modulo_power_two(root, a, &c, power);
                assert_eq!(result.bits.len(), power);
                result.to_wires_vec()
            });

        let actual_fn = output_wires_ids
            .iter()
            .zip(output_value.iter())
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

        debug!("Expected bitmask: {}", expected);
        debug!("Actual bitmask:   {}", actual);

        // Log individual wire values for debugging
        for (i, wire_id) in res.bits.iter().enumerate().take(16) {
            let actual_val = actual_fn.get(wire_id).copied().unwrap_or(false);
            let expected_val = expected_fn(*wire_id).unwrap_or(false);
            trace!(
                "Wire[{}] (ID: {:?}): actual={}, expected={}",
                i, wire_id, actual_val, expected_val
            );
        }

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_mul_by_constant_modulo_power_two_overflow() {
        // Test cases where multiplication would overflow without modulo
        let input = SingleInput::new(NUM_BITS, 100);
        let c = BigUint::from(5u64);
        let power = 8; // mod 256

        let StreamingResult {
            output_value,
            output_wires_ids,
            ..
        }: crate::circuit::StreamingResult<ExecuteMode, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(input, 10_000, |root, a| {
                let result = mul_by_constant_modulo_power_two(root, a, &c, power);
                result.to_wires_vec()
            });

        let actual_fn = output_wires_ids
            .iter()
            .zip(output_value.iter())
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

        debug!("Expected bitmask: {}", expected);
        debug!("Actual bitmask:   {}", actual);

        // Log individual wire values for debugging
        for (i, wire_id) in res.bits.iter().enumerate().take(16) {
            let actual_val = actual_fn.get(wire_id).copied().unwrap_or(false);
            let expected_val = expected_fn(*wire_id).unwrap_or(false);
            trace!(
                "Wire[{}] (ID: {:?}): actual={}, expected={}",
                i, wire_id, actual_val, expected_val
            );
        }

        assert_eq!(expected, actual);
    }

    // Test with different bit sizes
    #[test]
    fn test_mul_naive_different_bit_sizes() {
        const SMALL_BITS: usize = 4;
        const LARGE_BITS: usize = 16;

        // Test with 4-bit inputs
        test_mul_operation(SMALL_BITS, 7, 5, 35, mul_naive);
        test_mul_operation(SMALL_BITS, 15, 15, 225, mul_naive); // max 4-bit value

        // Test with 16-bit inputs (if supported)
        test_mul_operation(LARGE_BITS, 255, 255, 65025, mul_naive);
        test_mul_operation(LARGE_BITS, 1000, 1000, 1000000, |c, a, b| {
            mul_naive(c, a, b)
        });
    }

    // Random property-based tests
    #[test]
    fn test_mul_naive_random_properties() {
        // Test multiplicative identity: a * 1 = a
        for a in [0, 1, 7, 15, 42, 100, 255] {
            test_mul_operation(NUM_BITS, a, 1, a as u128, mul_naive);
        }

        // Test zero property: a * 0 = 0
        for a in [1, 7, 15, 42, 100, 255] {
            test_mul_operation(NUM_BITS, a, 0, 0, mul_naive);
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

    /// Verify that the policy in `mul` selects the minimal total gate count
    /// compared to pure naive vs pure karatsuba implementations for lengths
    /// 1..=300. Length 0 is intentionally skipped because adders require at
    /// least 1 bit and would panic.
    #[test]
    fn karatsuba_policy_chooses_min_gate_count_up_to_300() {
        use crate::circuit::StreamingResult;

        fn gate_count_for<F>(n_bits: usize, op: F) -> u64
        where
            F: Fn(&mut Execute, &BigIntWires, &BigIntWires) -> BigIntWires,
        {
            // Input values don't affect gate count; fixed small numbers are fine.
            let input = Input::<2>::new(n_bits, [1, 1]);

            let result: StreamingResult<ExecuteMode, _, Vec<bool>> =
                CircuitBuilder::streaming_execute(input, 200_000, |root, input| {
                    let [a, b] = input;
                    let out = op(root, a, b);
                    out.to_wires_vec()
                });

            result.gate_count.total_gate_count()
        }

        for len in 1..=300 {
            let naive_gc = gate_count_for(len, super::mul_naive);
            let karatsuba_gc = gate_count_for(len, super::mul_karatsuba);
            let selected_gc = gate_count_for(len, super::mul);

            let best = naive_gc.min(karatsuba_gc);
            assert!(
                selected_gc == best,
                "len={}: selected={} naive={} karatsuba={}",
                len,
                selected_gc,
                naive_gc,
                karatsuba_gc
            );
        }
    }
}
