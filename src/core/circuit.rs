use crate::{bag::*, core::gate::GateCount};
use std::collections::HashMap;

pub type GatesMap = HashMap<u64, Gate>;

pub struct Circuit {
    pub wires: Wires,
    pub gates: GatesMap,
    wires2gates: HashMap<S, Vec<u64>>, // maps wire index to fan-out gates indexs
    gates_num: u64,
}

impl Circuit {
    pub fn empty() -> Self {
        Self {
            wires: Vec::new(),
            gates: HashMap::new(),
            wires2gates: HashMap::new(),
            gates_num: 0,
        }
    }

    pub fn new(wires: Wires, gates: Vec<Gate>) -> Self {
        let mut circuit = Self::empty();
        circuit.add_wires(wires);
        for gate in gates {
            circuit.add(gate);
        }
        circuit
    }

    pub fn garbled_gates(&self) -> Vec<Vec<S>> {
        self.gates.iter().map(|(_, gate)| gate.garbled()).collect()
    }

    /// add gates from a circuit, return the wires of the circuit
    pub fn extend(&mut self, circuit: Self) -> Wires {
        for (_, gate) in circuit.gates {
            self.add(gate);
        }
        circuit.wires
    }

    pub fn add(&mut self, gate: Gate) {
        for wire in [gate.wire_a.clone(), gate.wire_b.clone()] {
            let wire_index = wire.borrow().get_label0(); // use the label0 as index
            self.wires2gates
                .entry(wire_index)
                .or_insert_with(Vec::new)
                .push(self.gates_num);
        }
        self.gates.insert(self.gates_num, gate);
        self.gates_num += 1;
    }

    pub fn add_wire(&mut self, wire: Wirex) {
        self.wires.push(wire);
    }

    pub fn add_wires(&mut self, wires: Wires) {
        for wire in wires {
            self.add_wire(wire);
        }
    }

    pub fn gate_count(&self) -> usize {
        self.gates.len()
    }

    pub fn gates(&self) -> Vec<Gate> {
        self.gates.iter().map(|(_, gate)| gate.clone()).collect()
    }

    pub fn wires(&self) -> Wires {
        self.wires.clone()
    }

    pub fn fanout(&self) -> usize {
        let mut fanout = 0;
        for gates in self.wires2gates.values() {
            fanout += gates.len();
        }
        fanout
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
        for (_, gate) in self.gates.iter() {
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

        for (i, (gate, garble)) in zip(circuit.gates().clone(), garbled_gates).enumerate() {
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

        for (i, (gate, garble)) in zip(circuit.gates().clone(), garbled_gates).enumerate() {
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
