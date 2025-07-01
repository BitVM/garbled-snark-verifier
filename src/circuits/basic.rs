use crate::bag::*;

pub fn half_adder(a: Wirex, b: Wirex) -> Circuit {
    let result = new_wirex();
    let carry = new_wirex();
    let gate_result = Gate::xor(a.clone(), b.clone(), result.clone());
    let gate_carry = Gate::and(a.clone(), b.clone(), carry.clone());
    Circuit::new(vec![result, carry], vec![gate_result, gate_carry])
}

pub fn full_adder(a: Wirex, b: Wirex, c: Wirex) -> Circuit {
    let ab_xor = new_wirex(); // d = a ⊕ b
    let ab_and = new_wirex(); // e = a ∧ b
    let sum = new_wirex(); // result = (a ⊕ b) ⊕ c
    let d_c_and = new_wirex(); // f = (a ⊕ b) ∧ c
    let carry = new_wirex(); // carry = (a ∧ b) ∨ ((a ⊕ b) ∧ c)

    // Gates
    let g1 = Gate::xor(a.clone(), b.clone(), ab_xor.clone()); // a ⊕ b
    let g2 = Gate::and(a.clone(), b.clone(), ab_and.clone()); // a ∧ b
    let g3 = Gate::xor(ab_xor.clone(), c.clone(), sum.clone()); // (a ⊕ b) ⊕ c
    let g4 = Gate::and(ab_xor.clone(), c.clone(), d_c_and.clone()); // (a ⊕ b) ∧ c
    let g5 = Gate::xor(ab_and.clone(), d_c_and.clone(), carry.clone()); // carry = e ⊕ f (use XOR instead of OR)

    Circuit::new(vec![sum, carry], vec![g1, g2, g3, g4, g5])
}

pub fn half_subtracter(a: Wirex, b: Wirex) -> Circuit {
    let result = new_wirex();
    let borrow = new_wirex();
    let not_a = new_wirex();
    let gate_not_a = Gate::not(a.clone(), not_a.clone());
    let gate_result = Gate::xor(a.clone(), b.clone(), result.clone());
    let gate_borrow = Gate::and(not_a.clone(), b.clone(), borrow.clone());
    Circuit::new(
        vec![result, borrow],
        vec![gate_not_a, gate_result, gate_borrow],
    )
}

pub fn full_subtracter(a: Wirex, b: Wirex, c: Wirex) -> Circuit {
    let d = new_wirex();
    let e = new_wirex();
    let f = new_wirex();
    let g = new_wirex();
    let h = new_wirex();
    let result = new_wirex();
    let borrow = new_wirex();

    let gate_1 = Gate::xor(a.clone(), b.clone(), d.clone());
    let gate_2 = Gate::xor(c.clone(), d.clone(), result.clone());
    let gate_3 = Gate::not(d.clone(), e.clone());
    let gate_4 = Gate::and(c.clone(), e.clone(), f.clone());
    let gate_5 = Gate::not(a.clone(), g.clone());
    let gate_6 = Gate::and(b.clone(), g.clone(), h.clone());
    let gate_7 = Gate::or(f.clone(), h.clone(), borrow.clone());
    Circuit::new(
        vec![result, borrow],
        vec![gate_1, gate_2, gate_3, gate_4, gate_5, gate_6, gate_7],
    )
}

pub fn selector(a: Wirex, b: Wirex, c: Wirex) -> Circuit {
    let d = new_wirex();
    let e = new_wirex();
    let f = new_wirex();
    let g = new_wirex();
    let gate_1 = Gate::not(c.clone(), e.clone());
    let gate_2 = Gate::nand(a.clone(), c.clone(), d.clone());
    let gate_3 = Gate::nand(e.clone(), b.clone(), f.clone());
    let gate_4 = Gate::nand(d.clone(), f.clone(), g.clone());
    Circuit::new(vec![g], vec![gate_1, gate_2, gate_3, gate_4])
}

pub fn multiplexer(a: Wires, s: Wires, w: usize) -> Circuit {
    let n = 2_usize.pow(w.try_into().unwrap());
    assert_eq!(a.len(), n);
    assert_eq!(s.len(), w);

    if w == 1 {
        return selector(a[1].clone(), a[0].clone(), s[0].clone());
    }

    let mut circuit = Circuit::empty();

    let a1 = a[0..(n / 2)].to_vec();
    let a2 = a[(n / 2)..n].to_vec();
    let su = s[0..w - 1].to_vec();
    let sv = s[w - 1].clone();

    let b1 = circuit.extend(multiplexer(a1, su.clone(), w - 1))[0].clone();
    let b2 = circuit.extend(multiplexer(a2, su.clone(), w - 1))[0].clone();

    let b = circuit.extend(selector(b2, b1, sv))[0].clone();

    circuit.add_wire(b);

    circuit
}

#[cfg(test)]
mod tests {
    use rand::{Rng, rng};

    use crate::{
        bag::*,
        circuits::basic::{
            full_adder, full_subtracter, half_adder, half_subtracter, multiplexer, selector,
        },
    };

    #[test]
    fn test_half_adder() {
        let result = [
            ((false, false), (false, false)),
            ((false, true), (true, false)),
            ((true, false), (true, false)),
            ((true, true), (false, true)),
        ];

        for ((a, b), (c, d)) in result {
            let a_wire = new_wirex();
            a_wire.borrow_mut().set(a);

            let b_wire = new_wirex();
            b_wire.borrow_mut().set(b);

            let circuit = half_adder(a_wire, b_wire);

            for mut gate in circuit.gates() {
                gate.evaluate();
            }

            let (c_wire, d_wire) = (circuit.wires[0].clone(), circuit.wires[1].clone());

            assert_eq!(c_wire.borrow().get_value(), c);
            assert_eq!(d_wire.borrow().get_value(), d);
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
            let a_wire = new_wirex();
            a_wire.borrow_mut().set(a);

            let b_wire = new_wirex();
            b_wire.borrow_mut().set(b);

            let c_wire = new_wirex();
            c_wire.borrow_mut().set(c);

            let circuit = full_adder(a_wire, b_wire, c_wire);

            for mut gate in circuit.gates() {
                gate.evaluate();
            }

            let (d_wire, e_wire) = (circuit.wires[0].clone(), circuit.wires[1].clone());

            assert_eq!(d_wire.borrow().get_value(), d);
            assert_eq!(e_wire.borrow().get_value(), e);
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
            let a_wire = new_wirex();
            a_wire.borrow_mut().set(a);

            let b_wire = new_wirex();
            b_wire.borrow_mut().set(b);

            let circuit = half_subtracter(a_wire, b_wire);

            for mut gate in circuit.gates() {
                gate.evaluate();
            }

            let (c_wire, d_wire) = (circuit.wires[0].clone(), circuit.wires[1].clone());

            assert_eq!(c_wire.borrow().get_value(), c);
            assert_eq!(d_wire.borrow().get_value(), d);
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
            let a_wire = new_wirex();
            a_wire.borrow_mut().set(a);

            let b_wire = new_wirex();
            b_wire.borrow_mut().set(b);

            let c_wire = new_wirex();
            c_wire.borrow_mut().set(c);

            let circuit = full_subtracter(a_wire, b_wire, c_wire);

            for mut gate in circuit.gates() {
                gate.evaluate();
            }

            let (d_wire, e_wire) = (circuit.wires[0].clone(), circuit.wires[1].clone());

            assert_eq!(d_wire.borrow().get_value(), d);
            assert_eq!(e_wire.borrow().get_value(), e);
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
            let a_wire = new_wirex();
            a_wire.borrow_mut().set(a);

            let b_wire = new_wirex();
            b_wire.borrow_mut().set(b);

            let c_wire = new_wirex();
            c_wire.borrow_mut().set(c);

            let circuit = selector(a_wire, b_wire, c_wire);

            for mut gate in circuit.gates() {
                gate.evaluate();
            }

            let d_wire = circuit.wires[0].clone();

            assert_eq!(d_wire.borrow().get_value(), d);
        }
    }

    #[test]
    fn test_multiplexer() {
        let w = 5;
        let n = 2_usize.pow(w as u32);
        let a: Wires = (0..n).map(|_| new_wirex()).collect();
        let s: Wires = (0..w).map(|_| new_wirex()).collect();

        for wire in a.clone() {
            wire.borrow_mut().set(rng().random());
        }

        let mut u = 0;
        for wire in s.iter().rev() {
            let x = rng().random();
            u = u + u + if x { 1 } else { 0 };
            wire.borrow_mut().set(x);
        }

        let circuit = multiplexer(a.clone(), s.clone(), w);
        circuit.gate_counts().print();

        for mut gate in circuit.gates() {
            gate.evaluate();
        }

        let result = circuit.wires[0].clone().borrow().get_value();
        let expected = a[u].clone().borrow().get_value();

        assert_eq!(result, expected);
    }
}
