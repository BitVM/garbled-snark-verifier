use super::BigIntImpl;
use crate::{
    bag::*,
    circuits::bigint::{
        add::{add_generic, sub_generic_without_borrow},
        cmp::self_or_zero_generic,
        utils::{bits_from_biguint, n_wires},
    },
};
use num_bigint::BigUint;

use once_cell::sync::Lazy;
use std::sync::Mutex;

static KARATSUBA_DECISIONS: Lazy<Mutex<[Option<bool>; 256]>> =
    Lazy::new(|| Mutex::new([None; 256]));

fn extend_with_false(wires: &mut Wires) {
    let zero_wire = new_wirex();
    zero_wire.borrow_mut().set(false);
    wires.push(zero_wire);
}

fn set_karatsuba_decision_flag(index: usize, value: bool) {
    let mut flags = KARATSUBA_DECISIONS.lock().unwrap();
    flags[index] = Some(value);
}

fn get_karatsuba_decision_flag(index: usize) -> Option<bool> {
    let flags = KARATSUBA_DECISIONS.lock().unwrap();
    flags[index]
}

pub fn mul_generic(a_wires: &Wires, b_wires: &Wires, len: usize) -> Circuit {
    assert_eq!(a_wires.len(), len);
    assert_eq!(b_wires.len(), len);

    let mut circuit = Circuit::empty();
    for _ in 0..(len * 2) {
        let wire = new_wirex();
        wire.borrow_mut().set(false);
        circuit.add_wire(wire)
    } //this part can be optimized later 

    for (i, current_bit) in b_wires.iter().enumerate().take(len) {
        let mut addition_wires_0 = vec![];
        for j in i..(i + len) {
            addition_wires_0.push(circuit.0[j].clone());
        }
        let addition_wires_1 = circuit.extend(self_or_zero_generic(
            a_wires.clone(),
            current_bit.clone(),
            len,
        ));
        let new_bits = circuit.extend(add_generic(addition_wires_0, addition_wires_1, len));
        circuit.0[i..(i + len + 1)].clone_from_slice(&new_bits);
    }
    circuit
}

// decider[i] = 0, not calculated, 1 = karatsuba, 0 = brute force
// this is a version of karatsuba I've just made up without any specific reference, there's probably a lot of room for improvement
pub fn mul_karatsuba_generic(a_wires: &Wires, b_wires: &Wires, len: usize) -> Circuit {
    assert_eq!(a_wires.len(), len);
    assert_eq!(b_wires.len(), len);
    if len < 5 {
        return mul_generic(a_wires, b_wires, len);
    }
    let mut min_circuit = Circuit::empty();
    let karatsuba_flag = get_karatsuba_decision_flag(len);
    if karatsuba_flag.is_none() || !karatsuba_flag.unwrap() {
        min_circuit = mul_generic(a_wires, b_wires, len);
    }

    if karatsuba_flag.is_none() || karatsuba_flag.unwrap() {
        let mut circuit = Circuit::empty();
        circuit.0 = n_wires(len * 2);
        for i in 0..len * 2 {
            circuit.0[i].borrow_mut().set(false);
        }

        let len_0 = len / 2;
        let len_1 = len.div_ceil(2);

        let a_0 = a_wires[0..len_0].to_vec();
        let a_1 = a_wires[len_0..].to_vec();

        let b_0 = b_wires[0..len_0].to_vec();
        let b_1 = b_wires[len_0..].to_vec();

        let sq_0 = circuit.extend(mul_karatsuba_generic(&a_0, &b_0, len_0));
        let sq_1 = circuit.extend(mul_karatsuba_generic(&a_1, &b_1, len_1));
        let mut extended_sq_0 = sq_0.clone();
        let mut extended_a_0 = a_0.clone();
        let mut extended_b_0 = b_0.clone();
        if len_0 < len_1 {
            extend_with_false(&mut extended_a_0);
            extend_with_false(&mut extended_b_0);
            extend_with_false(&mut extended_sq_0);
            extend_with_false(&mut extended_sq_0);
            //extended_a_0.push(zero_wire.clone());
            //extended_b_0.push(zero_wire.clone());
            //extended_sq_0.push(zero_wire.clone());
            //extended_sq_0.push(zero_wire.clone());
        }

        let sum_a = circuit.extend(add_generic(extended_a_0, a_1, len_1));
        let sum_b = circuit.extend(add_generic(extended_b_0, b_1, len_1));
        let mut sq_sum = circuit.extend(add_generic(extended_sq_0, sq_1.clone(), len_1 * 2));
        extend_with_false(&mut sq_sum);
        //sq_sum.push(zero_wire.clone());

        let sum_mul = circuit.extend(mul_karatsuba_generic(&sum_a, &sum_b, len_1 + 1));
        let cross_term =
            circuit.extend(sub_generic_without_borrow(sum_mul, sq_sum, (len_1 + 1) * 2))
                [..(len + 1)]
                .to_vec(); //len_0 + len_1 = len

        circuit.0[..(len_0 * 2)].clone_from_slice(&sq_0);

        {
            let segment = circuit.0[len_0..(len_0 + len + 1)].to_vec();
            let new_segment = circuit.extend(add_generic(segment, cross_term, len + 1));
            circuit.0[len_0..(len_0 + len + 2)].clone_from_slice(&new_segment);
        }

        {
            let segment = circuit.0[(2 * len_0)..].to_vec();
            let new_segment = circuit.extend(add_generic(segment, sq_1, len_1 * 2));
            circuit.0[(2 * len_0)..].clone_from_slice(&new_segment[..(2 * len_1)]);
        }

        if circuit.gate_count() < min_circuit.gate_count() || min_circuit.gate_count() == 0 {
            set_karatsuba_decision_flag(len, true);
            min_circuit = circuit;
        }
    }

    if get_karatsuba_decision_flag(len).is_none() {
        set_karatsuba_decision_flag(len, false);
    }

    min_circuit
}

impl<const N_BITS: usize> BigIntImpl<N_BITS> {
    pub fn mul(a_wires: Wires, b_wires: Wires) -> Circuit {
        mul_generic(&a_wires, &b_wires, N_BITS)
    }

    pub fn mul_karatsuba(a_wires: Wires, b_wires: Wires) -> Circuit {
        mul_karatsuba_generic(&a_wires, &b_wires, N_BITS)
    }

    pub fn mul_by_constant(a_wires: Wires, c: BigUint) -> Circuit {
        assert_eq!(a_wires.len(), N_BITS);
        let mut c_bits = bits_from_biguint(&c);
        c_bits.truncate(N_BITS);

        let mut circuit = Circuit::empty();

        for _ in 0..(N_BITS * 2) {
            let wire = new_wirex();
            wire.borrow_mut().set(false);
            circuit.add_wire(wire)
        } //this part can be optimized later 

        for (i, bit) in c_bits.iter().enumerate() {
            if *bit {
                let mut addition_wires = vec![];
                for j in i..(i + N_BITS) {
                    addition_wires.push(circuit.0[j].clone());
                }
                let new_bits = circuit.extend(Self::add(a_wires.clone(), addition_wires));
                circuit.0[i..(i + N_BITS + 1)]
                    .clone_from_slice(&new_bits[..((i + N_BITS - i) + 1)]);
            }
        }

        //this is buggy at the moment because of borrowing, an optimization for later maybe?
        /*
        let d = change_to_neg_pos_decomposition(c_bits);
        for (i, coeff) in d.iter().enumerate().rev() {
            if *coeff == 0 {
                continue;
            }
             let mut operation_wires = vec![];
            for j in i..(i + N_BITS) {
                operation_wires.push(circuit.0[j].clone());
            }
            let new_bits;
            if *coeff == 1 {
                new_bits = circuit.extend(Self::add(a_wires.clone(), operation_wires));
            } else {
                new_bits = circuit.extend(Self::optimized_sub(a_wires.clone(), operation_wires, false));
            }
            for j in i..=(i + N_BITS - (*coeff == -1) as usize) {
                circuit.0[j] = new_bits[j - i].clone();
            }
        }
        */
        circuit
    }

    pub fn mul_by_constant_modulo_power_two(a_wires: Wires, c: BigUint, power: usize) -> Circuit {
        assert_eq!(a_wires.len(), N_BITS);
        assert!(power < 2 * N_BITS);
        let mut c_bits = bits_from_biguint(&c);
        c_bits.truncate(N_BITS);

        let mut circuit = Circuit::empty();

        for _ in 0..power {
            let wire = new_wirex();
            wire.borrow_mut().set(false);
            circuit.add_wire(wire)
        } //this part can be optimized later 

        for (i, bit) in c_bits.iter().enumerate() {
            if i == power {
                break;
            }
            if *bit {
                let mut addition_wires = vec![];
                let number_of_bits = (power - i).min(N_BITS);
                for j in i..(i + number_of_bits) {
                    addition_wires.push(circuit.0[j].clone());
                }
                let new_bits = circuit.extend(add_generic(
                    a_wires[0..number_of_bits].to_vec(),
                    addition_wires,
                    number_of_bits,
                ));
                if i + number_of_bits < power {
                    circuit.0[i..(i + number_of_bits + 1)].clone_from_slice(&new_bits);
                } else {
                    circuit.0[i..(i + number_of_bits)]
                        .clone_from_slice(&new_bits[..number_of_bits]);
                }
            }
        }
        circuit
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use num_bigint::BigUint;

    use crate::circuits::bigint::{
        BigIntImpl, U254,
        utils::{biguint_from_bits, random_biguint_n_bits},
    };

    //tests are currently only for 254 bits

    #[test]
    fn test_mul() {
        for _ in 0..10 {
            let a = random_biguint_n_bits(254);
            let b = random_biguint_n_bits(254);
            let circuit = U254::mul(
                U254::wires_set_from_number(&a),
                U254::wires_set_from_number(&b),
            );
            let c = &a * &b;
            circuit.gate_counts().print();

            for mut gate in circuit.1 {
                gate.evaluate();
            }

            let result = biguint_from_bits(
                circuit
                    .0
                    .iter()
                    .map(|output_wire| output_wire.borrow().get_value())
                    .collect(),
            );
            assert_eq!(result, c);
        }
    }

    #[test]
    fn test_karatsuba() {
        for _ in 0..10 {
            let a = random_biguint_n_bits(254);
            let b = random_biguint_n_bits(254);
            let circuit = U254::mul_karatsuba(
                U254::wires_set_from_number(&a),
                U254::wires_set_from_number(&b),
            );
            let c = &a * &b;
            circuit.gate_counts().print();

            for mut gate in circuit.1 {
                gate.evaluate();
            }

            let result = biguint_from_bits(
                circuit
                    .0
                    .iter()
                    .map(|output_wire| output_wire.borrow().get_value())
                    .collect(),
            );
            assert_eq!(result, c);
        }
    }

    #[test]
    fn test_karatsuba_small() {
        const S: usize = 64;
        for _ in 0..1 {
            let a = random_biguint_n_bits(S);
            let b = random_biguint_n_bits(S);
            pub type T = BigIntImpl<S>;

            let circuit =
                T::mul_karatsuba(T::wires_set_from_number(&a), T::wires_set_from_number(&b));
            let c = &a * &b;
            circuit.gate_counts().print();

            for mut gate in circuit.1 {
                gate.evaluate();
            }

            let result = biguint_from_bits(
                circuit
                    .0
                    .iter()
                    .map(|output_wire| output_wire.borrow().get_value())
                    .collect(),
            );
            assert_eq!(result, c);
        }
    }

    #[test]
    fn test_mul_by_constant() {
        for _ in 0..10 {
            let a = random_biguint_n_bits(254);
            let b = random_biguint_n_bits(254);
            let circuit = U254::mul_by_constant(U254::wires_set_from_number(&a), b.clone());
            let c = &a * &b;
            circuit.gate_counts().print();

            for mut gate in circuit.1 {
                gate.evaluate();
            }

            let result = biguint_from_bits(
                circuit
                    .0
                    .iter()
                    .map(|output_wire| output_wire.borrow().get_value())
                    .collect(),
            );
            assert_eq!(result, c);
        }
    }

    #[test]
    fn test_mul_by_constant_modulo_power_two() {
        for power in [127, 254] {
            //two randomish values
            let a = random_biguint_n_bits(254);
            let b = random_biguint_n_bits(254);
            let circuit = U254::mul_by_constant_modulo_power_two(
                U254::wires_set_from_number(&a),
                b.clone(),
                power,
            );
            let c = &a * &b % BigUint::from_str("2").unwrap().pow(power as u32);
            circuit.gate_counts().print();

            for mut gate in circuit.1 {
                gate.evaluate();
            }

            let result = biguint_from_bits(
                circuit
                    .0
                    .iter()
                    .map(|output_wire| output_wire.borrow().get_value())
                    .collect(),
            );
            assert_eq!(result, c);
        }
    }
}
