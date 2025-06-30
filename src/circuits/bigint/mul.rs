use num_bigint::BigUint;

use super::BigIntImpl;
use crate::{bag::*, circuits::bigint::utils::bits_from_biguint};

impl<const N_BITS: usize> BigIntImpl<N_BITS> {
    pub fn mul(a_wires: Vec<Rc<RefCell<Wire>>>, b_wires: Vec<Rc<RefCell<Wire>>>) -> Circuit {
        assert_eq!(a_wires.len(), N_BITS);
        assert_eq!(b_wires.len(), N_BITS);

        let mut circuit = Circuit::empty();
        for _ in 0..(N_BITS * 2) {
            let wire = new_wirex();
            wire.borrow_mut().set(false);
            circuit.add_wire(wire)
        } //this part can be optimized later 

        for i in 0..N_BITS {
            let mut addition_wires_0 = vec![];
            for j in i..(i + N_BITS) {
                addition_wires_0.push(circuit.0[j].clone());
            }
            let addition_wires_1 =
                circuit.extend(Self::self_or_zero(a_wires.clone(), b_wires[i].clone()));
            let new_bits = circuit.extend(Self::add(addition_wires_0, addition_wires_1));
            circuit.0[i..(i + N_BITS + 1)].clone_from_slice(&new_bits[..((i + N_BITS - i) + 1)]);
        }
        circuit
    }

    pub fn mul_by_constant(a_wires: Vec<Rc<RefCell<Wire>>>, c: BigUint) -> Circuit {
        assert_eq!(a_wires.len(), N_BITS);
        let mut c_bits = bits_from_biguint(c);
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

    pub fn mul_by_constant_modulo_power_two(
        a_wires: Vec<Rc<RefCell<Wire>>>,
        c: BigUint,
        power: usize,
    ) -> Circuit {
        assert_eq!(a_wires.len(), N_BITS);
        assert!(power < 2 * N_BITS);
        let mut c_bits = bits_from_biguint(c);
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
                let new_bits = circuit.extend(Self::add_generic(
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
        U254,
        utils::{biguint_from_bits, random_biguint_n_bits},
    };

    //tests are currently only for 254 bits

    #[test]
    fn test_mul() {
        for _ in 0..10 {
            let a = random_biguint_n_bits(254);
            let b = random_biguint_n_bits(254);
            let circuit = U254::mul(
                U254::wires_set_from_number(a.clone()),
                U254::wires_set_from_number(b.clone()),
            );
            let c = a * b;
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
            let circuit = U254::mul_by_constant(U254::wires_set_from_number(a.clone()), b.clone());
            let c = a * b;
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
                U254::wires_set_from_number(a.clone()),
                b.clone(),
                power,
            );
            let c = a * b % BigUint::from_str("2").unwrap().pow(power as u32);
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
