use crate::bag::*;

pub fn half_adder(a: Wirex, b: Wirex) -> Circuit {
    let result = new_wirex();
    let carry = new_wirex();
    let gate_result = Gate::xor(a.clone(), b.clone(), result.clone());
    let gate_carry = Gate::and(a.clone(), b.clone(), carry.clone());
    Circuit::new(vec![result, carry], vec![gate_result, gate_carry])
}

pub fn full_adder(a: Wirex, b: Wirex, c: Wirex) -> Circuit {
    let axc = new_wirex();
    let bxc = new_wirex();
    let result = new_wirex();
    let t = new_wirex();
    let carry = new_wirex();

    let g1 = Gate::xor(a.clone(), c.clone(), axc.clone());
    let g2 = Gate::xor(b.clone(), c.clone(), bxc.clone());
    let g3 = Gate::xor(a.clone(), bxc.clone(), result.clone());
    let g4 = Gate::and(axc.clone(), bxc.clone(), t.clone());
    let g5 = Gate::xor(c.clone(), t.clone(), carry.clone());

    Circuit::new(vec![result, carry], vec![g1, g2, g3, g4, g5])
}

pub fn half_subtracter(a: Wirex, b: Wirex) -> Circuit {
    let result = new_wirex();
    let borrow = new_wirex();
    let gate_result = Gate::xor(a.clone(), b.clone(), result.clone());
    let gate_borrow = Gate::and_variant(a.clone(), b.clone(), borrow.clone(), [1, 0, 0]);
    Circuit::new(vec![result, borrow], vec![gate_result, gate_borrow])
}

pub fn full_subtracter(a: Wirex, b: Wirex, c: Wirex) -> Circuit {
    let bxa = new_wirex();
    let bxc = new_wirex();
    let result = new_wirex();
    let t = new_wirex();
    let carry = new_wirex();

    let g1 = Gate::xor(a.clone(), b.clone(), bxa.clone());
    let g2 = Gate::xor(b.clone(), c.clone(), bxc.clone());
    let g3 = Gate::xor(bxa.clone().clone(), c.clone(), result.clone());
    let g4 = Gate::and(bxa.clone(), bxc.clone(), t.clone());
    let g5 = Gate::xor(c.clone(), t.clone(), carry.clone());

    Circuit::new(vec![result, carry], vec![g1, g2, g3, g4, g5])
}

pub fn selector(a: Wirex, b: Wirex, c: Wirex) -> Circuit {
    let d = new_wirex();
    let f = new_wirex();
    let g = new_wirex();
    let gate_1 = Gate::nand(a.clone(), c.clone(), d.clone());
    let gate_2 = Gate::and_variant(c.clone(), b.clone(), f.clone(), [1, 0, 1]);
    let gate_3 = Gate::nand(d.clone(), f.clone(), g.clone());
    Circuit::new(vec![g], vec![gate_1, gate_2, gate_3])
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

            for mut gate in circuit.1 {
                gate.evaluate();
            }

            let (c_wire, d_wire) = (circuit.0[0].clone(), circuit.0[1].clone());

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

            for mut gate in circuit.1 {
                gate.evaluate();
            }

            let (d_wire, e_wire) = (circuit.0[0].clone(), circuit.0[1].clone());

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

            for mut gate in circuit.1 {
                gate.evaluate();
            }

            let (c_wire, d_wire) = (circuit.0[0].clone(), circuit.0[1].clone());

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

            for mut gate in circuit.1 {
                gate.evaluate();
            }

            let (d_wire, e_wire) = (circuit.0[0].clone(), circuit.0[1].clone());

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

            for mut gate in circuit.1 {
                gate.evaluate();
            }

            let d_wire = circuit.0[0].clone();

            assert_eq!(d_wire.borrow().get_value(), d);
        }
    }

    #[test]
    fn test_multiplexer() {
        let w = 5;
        let n = 2_usize.pow(w as u32);
        let a: Wires = (0..n).map(|_| new_wirex()).collect();
        let s: Wires = (0..w).map(|_| new_wirex()).collect();

        for wire in a.iter() {
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

        for mut gate in circuit.1 {
            gate.evaluate();
        }

        let result = circuit.0[0].clone().borrow().get_value();
        let expected = a[u].clone().borrow().get_value();

        assert_eq!(result, expected);
    }
}
