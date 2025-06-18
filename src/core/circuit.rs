use std::{
    collections::{HashMap, HashSet},
    hash::{Hash, Hasher},
    ptr,
};

use crate::{bag::*, core::gate::GateCount};

#[derive(Clone)]
pub struct Circuit(pub Wires, pub Vec<Gate>);

impl Circuit {
    pub fn empty() -> Self {
        Self(Vec::new(), Vec::new())
    }

    pub fn new(wires: Wires, gates: Vec<Gate>) -> Self {
        Self(wires, gates)
    }

    pub fn garbled_gates(&self) -> Vec<Vec<S>> {
        self.1.iter().map(|gate| gate.garbled()).collect()
    }

    pub fn extend(&mut self, circuit: Self) -> Wires {
        self.1.extend(circuit.1);
        circuit.0
    }

    pub fn add(&mut self, gate: Gate) {
        self.1.push(gate);
    }

    pub fn add_const(&mut self, value: bool, arbitrary_input: Wirex, output: Wirex) {
        if value {
            self.1.push(Gate::xnor(
                arbitrary_input.clone(),
                arbitrary_input.clone(),
                output,
            ));
        } else {
            self.1.push(Gate::xor(
                arbitrary_input.clone(),
                arbitrary_input.clone(),
                output,
            ));
        }
    }

    pub fn add_wire(&mut self, wire: Wirex) {
        self.0.push(wire);
    }

    pub fn add_wires(&mut self, wires: Wires) {
        self.0.extend(wires);
    }

    pub fn gate_count(&self) -> usize {
        self.1.len()
    }

    pub fn gate_counts(&self) -> GateCount {
        let mut and = 0;
        let mut or = 0;
        let mut xor = 0;
        let mut nand = 0;
        let mut not = 0;
        let mut xnor = 0;
        let mut nimp = 0;
        let mut nsor = 0;
        for gate in self.1.clone() {
            match gate.name.as_str() {
                "and" => and += 1,
                "or" => or += 1,
                "xor" => xor += 1,
                "nand" => nand += 1,
                "inv" | "not" => not += 1,
                "xnor" => xnor += 1,
                "nimp" => nimp += 1,
                "nsor" => nsor += 1,
                _ => panic!("this gate type is not allowed"),
            }
        }
        GateCount {
            and,
            or,
            xor,
            nand,
            not,
            xnor,
            nimp,
            nsor,
        }
    }

    /// Propagates constants throughout the circuit, removing gates where possible.
    pub fn optimize_consts(&mut self) {
        self.optimize_with_explicit_consts(Default::default());
    }

    /// Like optimize_consts, but with an option to consider certain inputs as constants (useful in testing)
    pub fn optimize_with_explicit_consts(&mut self, const_wires: Vec<(Wirex, bool)>) {
        /// A wrapper around a `Wire` that implements `Hash` based on the address of the `Wire`.
        #[derive(Clone, PartialEq, Eq)]
        pub struct HashedByAddr<T>(pub Rc<RefCell<T>>);
        impl<T> Hash for HashedByAddr<T> {
            fn hash<H: Hasher>(&self, state: &mut H) {
                let rc = &self.0;
                ptr::hash(&**rc, state)
            }
        }

        
        let const_wires: HashMap<HashedByAddr<Wire>, bool> = HashMap::from_iter(
            const_wires
                .into_iter()
                .map(|(wire, val)| (HashedByAddr(wire.clone()), val)),
        );

        let global_true = Rc::new(RefCell::new(Wire::new()));
        let global_false = Rc::new(RefCell::new(Wire::new()));

        let mut new_gates = Vec::new();
        new_gates.push(Gate::xor(
            self.1[0].wire_a.clone(),
            self.1[0].wire_a.clone(),
            global_false.clone(),
        ));
        new_gates.push(Gate::xnor(
            self.1[0].wire_a.clone(),
            self.1[0].wire_a.clone(),
            global_true.clone(),
        ));

        let mut wire_substitutions = HashMap::new();

        for (wire, val) in const_wires.iter() {
            if *val {
                wire_substitutions.insert(wire.clone(), global_true.clone());
            } else {
                wire_substitutions.insert(wire.clone(), global_false.clone());
            }
        }

        let output_wires =
            HashSet::<_>::from_iter(self.0.iter().map(|wire| HashedByAddr(wire.clone())));

        for gate in &mut self.1.iter() {
            let mut gate = gate.clone();

            if let Some(substitution) = wire_substitutions.get(&HashedByAddr(gate.wire_a.clone())) {
                gate.wire_a = substitution.clone();
            }
            if let Some(substitution) = wire_substitutions.get(&HashedByAddr(gate.wire_b.clone())) {
                gate.wire_b = substitution.clone();
            }

            // if this gate has an output that is an output if the circuit, we keep it so that
            // the output actually gets written to. This can be optimized, but in practice,
            // at the top-level circuit this case is not likely to occur, so probably not worth
            // it
            if output_wires.contains(&HashedByAddr(gate.wire_c.clone())) {
                new_gates.push(gate.clone());
                continue;
            }

            let const_val = |x: &Wirex| {
                if Rc::ptr_eq(x, &global_true) {
                    Some(true)
                } else if Rc::ptr_eq(x, &global_false) {
                    Some(false)
                } else {
                    None
                }
            };

            let val_a = const_val(&gate.wire_a);
            let val_b = const_val(&gate.wire_b);

            let mut set_value = |wire: Wirex, value: bool| {
                if value {
                    wire_substitutions.insert(HashedByAddr(wire), global_true.clone());
                } else {
                    wire_substitutions.insert(HashedByAddr(wire), global_false.clone());
                }
            };

            match (gate.name.as_str(), val_a, val_b) {
                ("and", Some(a), Some(b)) => {
                    set_value(gate.wire_c.clone(), a && b);
                }
                ("and", Some(false), _) | ("and", _, Some(false)) => {
                    set_value(gate.wire_c.clone(), false);
                }
                ("and", Some(true), _) => {
                    wire_substitutions
                        .insert(HashedByAddr(gate.wire_c.clone()), gate.wire_b.clone());
                }
                ("and", _, Some(true)) => {
                    wire_substitutions
                        .insert(HashedByAddr(gate.wire_c.clone()), gate.wire_a.clone());
                }
                ("or", Some(a), Some(b)) => {
                    set_value(gate.wire_c.clone(), a || b);
                }
                ("or", Some(true), _) | ("or", _, Some(true)) => {
                    set_value(gate.wire_c.clone(), true);
                }
                ("or", Some(false), _) => {
                    wire_substitutions
                        .insert(HashedByAddr(gate.wire_c.clone()), gate.wire_b.clone());
                }
                ("or", _, Some(false)) => {
                    wire_substitutions
                        .insert(HashedByAddr(gate.wire_c.clone()), gate.wire_a.clone());
                }
                ("xor", Some(a), Some(b)) => {
                    set_value(gate.wire_c.clone(), a ^ b);
                }
                ("xor", Some(false), _) => {
                    wire_substitutions
                        .insert(HashedByAddr(gate.wire_c.clone()), gate.wire_b.clone());
                }
                ("xor", _, Some(false)) => {
                    wire_substitutions
                        .insert(HashedByAddr(gate.wire_c.clone()), gate.wire_a.clone());
                }
                ("nand", Some(a), Some(b)) => {
                    set_value(gate.wire_c.clone(), !(a && b));
                }
                ("nand", Some(false), _) | ("nand", _, Some(false)) => {
                    set_value(gate.wire_c.clone(), true);
                }
                ("inv", Some(a), Some(_)) | ("not", Some(a), Some(_)) => {
                    set_value(gate.wire_c.clone(), !a);
                }
                ("xnor", Some(a), Some(b)) => {
                    set_value(gate.wire_c.clone(), !(a ^ b));
                }
                ("xnor", Some(true), _) => {
                    wire_substitutions
                        .insert(HashedByAddr(gate.wire_c.clone()), gate.wire_a.clone());
                }
                ("xnor", _, Some(true)) => {
                    wire_substitutions
                        .insert(HashedByAddr(gate.wire_c.clone()), gate.wire_b.clone());
                }
                ("nimp", Some(a), Some(b)) => {
                    set_value(gate.wire_c.clone(), a && !b);
                }
                ("nimp", _, Some(true)) => {
                    set_value(gate.wire_c.clone(), false);
                }
                ("nimp", Some(true), _) => {
                    wire_substitutions
                        .insert(HashedByAddr(gate.wire_c.clone()), gate.wire_b.clone());
                }

                // special cases: deterministic output from dynamic input
                ("xor", _, _) if Rc::ptr_eq(&gate.wire_a, &gate.wire_b) => {
                    set_value(gate.wire_c.clone(), false);
                }
                ("xnor", _, _) if Rc::ptr_eq(&gate.wire_a, &gate.wire_b) => {
                    set_value(gate.wire_c.clone(), true);
                }
                _ => {
                    new_gates.push(gate.clone());
                }
            }
        }

        if new_gates.len() < self.1.len() {
            println!(
                "Removed {} gates from the circuit",
                self.1.len() as isize - new_gates.len() as isize
            );
            self.1 = new_gates;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::core::{bristol::parser, s::S};
    use bitvm::bigint::U256;
    use bitvm::treepp::*;
    use rand::{Rng, rng};
    use serial_test::serial;
    use std::iter::zip;

    fn test_circuit(circuit_filename: &str, correct: bool) {
        println!("testing {:?}", circuit_filename);
        let (circuit, inputs, _outputs) = parser(circuit_filename);

        let mut garbled_gates = circuit.garbled_gates();
        let n = garbled_gates.len();

        if !correct {
            let u: u32 = rng().random();
            garbled_gates[(u as usize) % n] =
                vec![S::random(), S::random(), S::random(), S::random()];
        }

        for input in inputs {
            for input_wire in input {
                input_wire.borrow_mut().set(rng().random());
            }
        }

        println!(
            "testing {:?} garble",
            if correct { "correct" } else { "incorrect" }
        );

        for (i, (gate, garble)) in zip(circuit.1.clone(), garbled_gates).enumerate() {
            let a = gate.wire_a.borrow().get_label();
            let b = gate.wire_b.borrow().get_label();
            let bit_a = gate.wire_a.borrow().get_value();
            let bit_b = gate.wire_b.borrow().get_value();
            let bit_c = (gate.f())(bit_a, bit_b);
            let (garble_check, c) = gate.check_garble(garble.clone(), bit_c);
            let gate_script = gate.script(garble, garble_check);

            println!(
                "testing gate[{:?}], garble is {:?}",
                i,
                if garble_check { "correct" } else { "incorrect" }
            );

            let script = script! {
                { U256::push_hex(&hex::encode(a.0)) }
                { if bit_a {1} else {0} }
                { U256::push_hex(&hex::encode(b.0)) }
                { if bit_b {1} else {0} }
                { gate_script }
            };
            let result = execute_script(script);
            assert!(result.success);

            if garble_check {
                gate.wire_c.borrow_mut().set2(bit_c, c);
            } else {
                assert!(!correct);
                break;
            }
        }
    }

    fn test_circuit_find_incorrect(circuit_filename: &str, correct: bool) {
        println!("testing {:?}", circuit_filename);
        let (circuit, inputs, _outputs) = parser(circuit_filename);

        let mut garbled_gates = circuit.garbled_gates();
        let n = garbled_gates.len();

        if !correct {
            let u: u32 = rng().random();
            garbled_gates[(u as usize) % n] =
                vec![S::random(), S::random(), S::random(), S::random()];
        }

        for input in inputs {
            for input_wire in input {
                input_wire.borrow_mut().set(rng().random());
            }
        }

        println!(
            "testing {:?} garble",
            if correct { "correct" } else { "incorrect" }
        );

        for (i, (gate, garble)) in zip(circuit.1.clone(), garbled_gates).enumerate() {
            let a = gate.wire_a.borrow().get_label();
            let b = gate.wire_b.borrow().get_label();
            let bit_a = gate.wire_a.borrow().get_value();
            let bit_b = gate.wire_b.borrow().get_value();
            let bit_c = (gate.f())(bit_a, bit_b);
            let (garble_check, c) = gate.check_garble(garble.clone(), bit_c);

            println!(
                "testing gate[{:?}], garble is {:?}",
                i,
                if garble_check { "correct" } else { "incorrect" }
            );

            if garble_check {
                gate.wire_c.borrow_mut().set2(bit_c, c);
                continue;
            }
            assert!(!correct);

            let gate_script = gate.script(garble, garble_check);

            let script = script! {
                { U256::push_hex(&hex::encode(a.0)) }
                { if bit_a {1} else {0} }
                { U256::push_hex(&hex::encode(b.0)) }
                { if bit_b {1} else {0} }
                { gate_script }
            };
            let result = execute_script(script);
            assert!(result.success);

            break;
        }
    }

    #[test]
    #[serial]
    fn test_circuit_adder() {
        test_circuit("src/core/bristol-examples/adder64.txt", true);
        test_circuit("src/core/bristol-examples/adder64.txt", false);
    }

    #[test]
    #[serial]
    fn test_circuit_adder_find_incorrect() {
        test_circuit_find_incorrect("src/core/bristol-examples/adder64.txt", true);
        test_circuit_find_incorrect("src/core/bristol-examples/adder64.txt", false);
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_circuit_subtracter() {
        test_circuit("src/core/bristol-examples/subtracter64.txt", true);
        test_circuit("src/core/bristol-examples/subtracter64.txt", false);
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_circuit_subtracter_find_incorrect() {
        test_circuit_find_incorrect("src/core/bristol-examples/subtracter64.txt", true);
        test_circuit_find_incorrect("src/core/bristol-examples/subtracter64.txt", false);
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_circuit_multiplier() {
        test_circuit("src/core/bristol-examples/multiplier64.txt", true);
        test_circuit("src/core/bristol-examples/multiplier64.txt", false);
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_circuit_multiplier_find_incorrect() {
        test_circuit_find_incorrect("src/core/bristol-examples/multiplier64.txt", true);
        test_circuit_find_incorrect("src/core/bristol-examples/multiplier64.txt", false);
    }
}
