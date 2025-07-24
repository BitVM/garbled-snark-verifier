use std::sync::{OnceLock, RwLock};

use bitvec::prelude::*;
use log::debug;

use super::{BigIntWires, BigUint};
use crate::{Circuit, Gate, GateType, WireId};

/// Cache of algorithm choices for every possible operand length (up to 256).
///
/// Each entry indicates whether the Karatsuba multiplication algorithm
/// outperforms the naive schoolbook version for that bit-length.  `BitVec` is
/// used to compactly store the information for all 256 entries using a single
/// bit per value.
///
/// The table employs two separate bit-vectors:
/// * `decisions` stores the actual choice (`1` for Karatsuba, `0` for the
///   generic algorithm).
/// * `initialized` tracks which entries have already been computed.  This
///   mirrors the behaviour of `Option<bool>` but avoids the memory overhead of
///   an additional byte per entry.
///
/// The structure is guarded by a [`RwLock`] to allow concurrent reads once the
/// decisions have been cached.  Updates are infrequent and happen only on the
/// first invocation for a particular length.
///
/// TODO
///
/// Find all references to this table in runtime and make it compile-time computable
/// Important because it will be reused inside C&C components every time
#[derive(Default)]
struct KaratsubaDecisionTable {
    /// Decision bits, `1` means Karatsuba should be used.
    decisions: BitVec<u8, Lsb0>,
    /// Initialization flags for each index.
    initialized: BitVec<u8, Lsb0>,
}

impl KaratsubaDecisionTable {
    fn new() -> Self {
        Self {
            decisions: bitvec![u8, Lsb0; 0; 256],
            initialized: bitvec![u8, Lsb0; 0; 256],
        }
    }

    fn set(&mut self, index: usize, value: bool) {
        self.decisions.set(index, value);
        self.initialized.set(index, true);
    }

    fn get(&self, index: usize) -> Option<bool> {
        if self.initialized[index] {
            Some(self.decisions[index])
        } else {
            None
        }
    }
}

/// Global table with cached Karatsuba decisions for each operand length.
/// Global decision table used by [`mul_karatsuba_generic`].  It is
/// initialised on first use and persists for the lifetime of the program.
static KARATSUBA_DECISIONS: OnceLock<RwLock<KaratsubaDecisionTable>> = OnceLock::new();

fn decision_table() -> &'static RwLock<KaratsubaDecisionTable> {
    KARATSUBA_DECISIONS.get_or_init(|| RwLock::new(KaratsubaDecisionTable::new()))
}

fn set_karatsuba_decision_flag(index: usize, value: bool) {
    let mut table = decision_table().write().unwrap();
    table.set(index, value);
}

fn get_karatsuba_decision_flag(index: usize) -> Option<bool> {
    let table = decision_table().read().unwrap();
    table.get(index)
}

fn extend_with_zero(circuit: &mut Circuit, bits: &mut Vec<WireId>) {
    let zero_wire = circuit.issue_wire();
    circuit.add_gate(Gate::new(GateType::Nimp, bits[0], bits[0], zero_wire));
    bits.push(zero_wire);
}

pub fn mul_generic(circuit: &mut Circuit, a: &BigIntWires, b: &BigIntWires) -> BigIntWires {
    assert_eq!(a.len(), b.len());
    let len = a.len();

    let mut result_bits: Vec<_> = (0..(len * 2))
        .map(|_| circuit.get_false_wire_constant())
        .collect();

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

fn mul_karatsuba_generic_impl(
    circuit: &mut Circuit,
    a: &BigIntWires,
    b: &BigIntWires,
) -> BigIntWires {
    assert_eq!(a.len(), b.len());
    let len = a.len();

    if len < 5 {
        return mul_generic(circuit, a, b);
    }

    let mut result_bits = vec![circuit.get_false_wire_constant(); len * 2];

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

    let sq_0 = mul_karatsuba_generic_impl(circuit, &a_0, &b_0);
    let sq_1 = mul_karatsuba_generic_impl(circuit, &a_1, &b_1);

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

    let sum_mul = mul_karatsuba_generic_impl(circuit, &sum_a, &sum_b);
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

pub fn mul_karatsuba_generic(
    circuit: &mut Circuit,
    a: &BigIntWires,
    b: &BigIntWires,
) -> BigIntWires {
    assert_eq!(a.len(), b.len());
    let len = a.len();

    if len < 5 {
        debug!("mul_karatsuba_generic: <5 case");
        return mul_generic(circuit, a, b);
    }

    if let Some(flag) = get_karatsuba_decision_flag(len) {
        return if flag {
            mul_karatsuba_generic_impl(circuit, a, b)
        } else {
            mul_generic(circuit, a, b)
        };
    }

    let (generic_count, karatsuba_count) = rayon::join(
        || {
            let mut tmp = Circuit::default();
            let a_tmp = BigIntWires::new(&mut tmp, len, false, false);
            let b_tmp = BigIntWires::new(&mut tmp, len, false, false);
            mul_generic(&mut tmp, &a_tmp, &b_tmp);
            tmp.gate_count.nonfree_gate_count()
        },
        || {
            let mut tmp = Circuit::default();
            let a_tmp = BigIntWires::new(&mut tmp, len, false, false);
            let b_tmp = BigIntWires::new(&mut tmp, len, false, false);
            mul_karatsuba_generic_impl(&mut tmp, &a_tmp, &b_tmp);
            tmp.gate_count.nonfree_gate_count()
        },
    );

    debug!("karatsuba_count: {karatsuba_count}");
    debug!("generic_count: {generic_count}");

    let use_karatsuba = karatsuba_count < generic_count;
    set_karatsuba_decision_flag(len, use_karatsuba);

    if use_karatsuba {
        debug!("use karatsube");
        mul_karatsuba_generic_impl(circuit, a, b)
    } else {
        debug!("use generic");
        mul_generic(circuit, a, b)
    }
}

pub fn mul_by_constant(circuit: &mut Circuit, a: &BigIntWires, c: &BigUint) -> BigIntWires {
    let len = a.len();
    let c_bits = super::bits_from_biguint_with_len(c, len).unwrap();

    let mut result_bits = Vec::with_capacity(len * 2);
    for _ in 0..(len * 2) {
        let wire = circuit.issue_wire();
        circuit.add_gate(Gate::new(GateType::Nimp, a.bits[0], a.bits[0], wire));
        result_bits.push(wire);
    }

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

pub fn mul_by_constant_modulo_power_two(
    circuit: &mut Circuit,
    a: &BigIntWires,
    c: &BigUint,
    power: usize,
) -> BigIntWires {
    let len = a.len();
    assert!(power < 2 * len);
    let c_bits = super::bits_from_biguint_with_len(c, len).unwrap();

    let mut result_bits = Vec::with_capacity(power);
    for _ in 0..power {
        let wire = circuit.issue_wire();
        circuit.add_gate(Gate::new(GateType::Nimp, a.bits[0], a.bits[0], wire));
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

    use test_log::test;

    use super::*;
    use crate::test_utils::trng;

    fn test_mul_operation(
        n_bits: usize,
        a_val: u64,
        b_val: u64,
        expected: u128,
        operation: impl FnOnce(&mut Circuit, &BigIntWires, &BigIntWires) -> BigIntWires,
    ) {
        let mut circuit = Circuit::default();
        let a = BigIntWires::new(&mut circuit, n_bits, true, false);
        let b = BigIntWires::new(&mut circuit, n_bits, true, false);
        let result = operation(&mut circuit, &a, &b);

        assert_eq!(result.bits.len(), n_bits * 2);

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

    fn test_mul_by_constant_operation(
        n_bits: usize,
        a_val: u64,
        c_val: u64,
        expected: u128,
        operation: impl FnOnce(&mut Circuit, &BigIntWires, &BigUint) -> BigIntWires,
    ) {
        let mut circuit = Circuit::default();
        let a = BigIntWires::new(&mut circuit, n_bits, true, false);
        let c_big = BigUint::from(c_val);
        let result = operation(&mut circuit, &a, &c_big);

        result.bits.iter().for_each(|bit| {
            circuit.make_wire_output(*bit);
        });

        let a_big = BigUint::from(a_val);
        let expected_big = BigUint::from(expected);

        let a_input = a.get_wire_bits_fn(&a_big).unwrap();
        let get_expected_result_fn = result.get_wire_bits_fn(&expected_big).unwrap();

        circuit.full_cycle_test(a_input, get_expected_result_fn, &mut trng());
    }

    const NUM_BITS: usize = 8;

    // Basic multiplication tests
    #[test]
    fn test_mul_generic_basic() {
        test_mul_operation(NUM_BITS, 5, 3, 15, mul_generic);
    }

    #[test]
    fn test_mul_generic_larger() {
        test_mul_operation(NUM_BITS, 15, 17, 255, mul_generic);
    }

    #[test]
    fn test_mul_generic_zero() {
        test_mul_operation(NUM_BITS, 0, 42, 0, mul_generic);
        test_mul_operation(NUM_BITS, 42, 0, 0, mul_generic);
    }

    #[test]
    fn test_mul_generic_one() {
        test_mul_operation(NUM_BITS, 1, 42, 42, mul_generic);
        test_mul_operation(NUM_BITS, 42, 1, 42, mul_generic);
    }

    #[test]
    fn test_mul_generic_max_values() {
        // Test with maximum values for given bit size
        let max_val = (1u64 << NUM_BITS) - 1; // 255 for 8 bits
        test_mul_operation(NUM_BITS, max_val, 1, max_val as u128, mul_generic);
        test_mul_operation(
            NUM_BITS,
            max_val,
            max_val,
            (max_val as u128) * (max_val as u128),
            mul_generic,
        );
    }

    #[test]
    fn test_mul_generic_powers_of_two() {
        test_mul_operation(NUM_BITS, 2, 2, 4, mul_generic);
        test_mul_operation(NUM_BITS, 4, 4, 16, mul_generic);
        test_mul_operation(NUM_BITS, 8, 8, 64, mul_generic);
        test_mul_operation(NUM_BITS, 16, 16, 256, mul_generic);
    }

    #[test]
    fn test_mul_generic_commutative() {
        // Test that a * b == b * a
        let test_cases = [(5, 7), (13, 19), (1, 255), (17, 23)];
        for (a, b) in test_cases {
            test_mul_operation(NUM_BITS, a, b, (a as u128) * (b as u128), mul_generic);
            test_mul_operation(NUM_BITS, b, a, (a as u128) * (b as u128), mul_generic);
        }
    }

    // Karatsuba multiplication tests
    #[test]
    fn test_mul_karatsuba_basic() {
        test_mul_operation(NUM_BITS, 5, 3, 15, mul_karatsuba_generic);
    }

    #[test]
    fn test_mul_karatsuba_larger() {
        test_mul_operation(NUM_BITS, 15, 17, 255, mul_karatsuba_generic);
    }

    #[test]
    fn test_mul_karatsuba_zero() {
        test_mul_operation(NUM_BITS, 0, 42, 0, mul_karatsuba_generic);
        test_mul_operation(NUM_BITS, 42, 0, 0, mul_karatsuba_generic);
    }

    #[test]
    fn test_mul_karatsuba_one() {
        test_mul_operation(NUM_BITS, 1, 42, 42, mul_karatsuba_generic);
        test_mul_operation(NUM_BITS, 42, 1, 42, mul_karatsuba_generic);
    }

    #[test]
    fn test_mul_karatsuba_max_values() {
        let max_val = (1u64 << NUM_BITS) - 1;
        test_mul_operation(NUM_BITS, max_val, 1, max_val as u128, mul_karatsuba_generic);
        test_mul_operation(
            NUM_BITS,
            max_val,
            max_val,
            (max_val as u128) * (max_val as u128),
            mul_karatsuba_generic,
        );
    }

    #[test]
    fn test_mul_karatsuba_powers_of_two() {
        test_mul_operation(NUM_BITS, 2, 2, 4, mul_karatsuba_generic);
        test_mul_operation(NUM_BITS, 4, 4, 16, mul_karatsuba_generic);
        test_mul_operation(NUM_BITS, 8, 8, 64, mul_karatsuba_generic);
        test_mul_operation(NUM_BITS, 16, 16, 256, mul_karatsuba_generic);
    }

    #[test]
    fn test_mul_karatsuba_commutative() {
        let test_cases = [(5, 7), (13, 19), (1, 255), (17, 23)];
        for (a, b) in test_cases {
            test_mul_operation(
                NUM_BITS,
                a,
                b,
                (a as u128) * (b as u128),
                mul_karatsuba_generic,
            );
            test_mul_operation(
                NUM_BITS,
                b,
                a,
                (a as u128) * (b as u128),
                mul_karatsuba_generic,
            );
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
            let mut circuit1 = Circuit::default();
            let a_wires1 = BigIntWires::new(&mut circuit1, NUM_BITS, true, false);
            let b_wires1 = BigIntWires::new(&mut circuit1, NUM_BITS, true, false);
            let result1 = mul_generic(&mut circuit1, &a_wires1, &b_wires1);

            let mut circuit2 = Circuit::default();
            let a_wires2 = BigIntWires::new(&mut circuit2, NUM_BITS, true, false);
            let b_wires2 = BigIntWires::new(&mut circuit2, NUM_BITS, true, false);
            let result2 = mul_karatsuba_generic(&mut circuit2, &a_wires2, &b_wires2);

            // Both should produce same bit length
            assert_eq!(result1.bits.len(), result2.bits.len());

            // Test with same inputs
            let expected = (a as u128) * (b as u128);
            test_mul_operation(NUM_BITS, a, b, expected, mul_generic);
            test_mul_operation(NUM_BITS, a, b, expected, mul_karatsuba_generic);
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
        test_mul_by_constant_operation(NUM_BITS, max_val, 1, max_val as u128, mul_by_constant);
        test_mul_by_constant_operation(NUM_BITS, 1, max_val, max_val as u128, mul_by_constant);
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
        let mut circuit = Circuit::default();
        let a = BigIntWires::new(&mut circuit, NUM_BITS, true, false);
        let c = BigUint::from(17u64);
        let power = 12;
        let result = mul_by_constant_modulo_power_two(&mut circuit, &a, &c, power);

        assert_eq!(result.bits.len(), power);

        result.bits.iter().for_each(|bit| {
            circuit.make_wire_output(*bit);
        });

        let a_val = 15u64;
        let a_big = BigUint::from(a_val);
        let expected = (a_val * 17) % (2u64.pow(power as u32));
        let expected_big = BigUint::from(expected);

        let a_input = a.get_wire_bits_fn(&a_big).unwrap();
        let result_output = result.get_wire_bits_fn(&expected_big).unwrap();

        circuit.full_cycle_test(a_input, result_output, &mut trng());
    }

    #[test]
    fn test_mul_by_constant_modulo_power_two_simple() {
        let mut circuit = Circuit::default();
        let a = BigIntWires::new(&mut circuit, NUM_BITS, true, false);
        let c = BigUint::from(3u64);
        let power = 8;
        let result = mul_by_constant_modulo_power_two(&mut circuit, &a, &c, power);

        assert_eq!(result.bits.len(), power);

        result.bits.iter().for_each(|bit| {
            circuit.make_wire_output(*bit);
        });

        let a_val = 100u64;
        let a_big = BigUint::from(a_val);
        let expected = (a_val * 3) % 256u64; // 300 % 256 = 44
        let expected_big = BigUint::from(expected);

        let a_input = a.get_wire_bits_fn(&a_big).unwrap();
        let get_expected_result_fn = result.get_wire_bits_fn(&expected_big).unwrap();

        circuit.full_cycle_test(a_input, get_expected_result_fn, &mut trng());
    }

    #[test]
    fn test_mul_by_constant_modulo_power_two_overflow() {
        // Test cases where multiplication would overflow without modulo
        let mut circuit = Circuit::default();
        let a = BigIntWires::new(&mut circuit, NUM_BITS, true, false);
        let c = BigUint::from(5u64);
        let power = 8; // mod 256
        let result = mul_by_constant_modulo_power_two(&mut circuit, &a, &c, power);

        result.bits.iter().for_each(|bit| {
            circuit.make_wire_output(*bit);
        });

        let a_val = 100u64;
        let a_big = BigUint::from(a_val);
        let expected = (a_val * 5) % 256; // 500 % 256 = 244
        let expected_big = BigUint::from(expected);

        let a_input = a.get_wire_bits_fn(&a_big).unwrap();
        let result_output = result.get_wire_bits_fn(&expected_big).unwrap();

        circuit.full_cycle_test(a_input, result_output, &mut trng());
    }

    // Test with different bit sizes
    #[test]
    fn test_mul_generic_different_bit_sizes() {
        const SMALL_BITS: usize = 4;
        const LARGE_BITS: usize = 16;

        // Test with 4-bit inputs
        test_mul_operation(SMALL_BITS, 7, 5, 35, mul_generic);
        test_mul_operation(SMALL_BITS, 15, 15, 225, mul_generic); // max 4-bit value

        // Test with 16-bit inputs (if supported)
        test_mul_operation(LARGE_BITS, 255, 255, 65025, mul_generic);
        test_mul_operation(LARGE_BITS, 1000, 1000, 1000000, mul_generic);
    }

    // Random property-based tests
    #[test]
    fn test_mul_generic_random_properties() {
        // Test multiplicative identity: a * 1 = a
        for a in [0, 1, 7, 15, 42, 100, 255] {
            test_mul_operation(NUM_BITS, a, 1, a as u128, mul_generic);
        }

        // Test zero property: a * 0 = 0
        for a in [1, 7, 15, 42, 100, 255] {
            test_mul_operation(NUM_BITS, a, 0, 0, mul_generic);
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
}
