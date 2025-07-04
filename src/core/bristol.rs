use crate::bag::*;
use crate::core::gate::GateType;
use std::fs;

pub fn parser(filename: &str) -> (Circuit, Vec<Wires>, Vec<Wires>) {
    let data = fs::read_to_string(filename).expect("error");
    let mut lines = data.lines();

    let mut words = lines.next().unwrap().split_whitespace();
    let nog: usize = words.next().unwrap().parse().unwrap();
    let now: usize = words.next().unwrap().parse().unwrap();
    let mut wires = Vec::new();
    for _ in 0..now {
        wires.push(new_wirex());
    }

    let mut input_sizes = Vec::<usize>::new();
    let mut words = lines.next().unwrap().split_whitespace();
    for _ in 0..words.next().unwrap().parse().unwrap() {
        let x: usize = words.next().unwrap().parse().unwrap();
        input_sizes.push(x);
    }

    let mut output_sizes = Vec::<usize>::new();
    let mut words = lines.next().unwrap().split_whitespace();
    for _ in 0..words.next().unwrap().parse().unwrap() {
        let x: usize = words.next().unwrap().parse().unwrap();
        output_sizes.push(x);
    }

    let mut i = 0;
    let mut gates = Vec::new();
    while i < nog {
        let line = lines.next().unwrap();
        if line.is_empty() {
            continue;
        }
        let mut words = line.split_whitespace();
        let number_of_inputs: usize = words.next().unwrap().parse().unwrap();
        let number_of_outputs: usize = words.next().unwrap().parse().unwrap();
        let mut input_wires: Vec<usize> = Vec::new();
        for _ in 0..number_of_inputs {
            input_wires.push(words.next().unwrap().parse().unwrap());
        }
        let mut output_wires: Vec<usize> = Vec::new();
        for _ in 0..number_of_outputs {
            output_wires.push(words.next().unwrap().parse().unwrap());
        }
        let gate_type_str = words.next().unwrap().to_lowercase();
        let gate_type = match gate_type_str.as_str() {
            "and" => GateType::And,
            "or" => GateType::Or,
            "xor" => GateType::Xor,
            "nand" => GateType::Nand,
            "inv" | "not" => GateType::Not,
            "xnor" => GateType::Xnor,
            "nimp" => GateType::Nimp,
            _ => panic!("Unknown gate type: {}", gate_type_str),
        };
        let gate = Gate::new(
            wires[input_wires[0]].clone(),
            if number_of_inputs == 1 {
                wires[input_wires[0]].clone()
            } else {
                wires[input_wires[1]].clone()
            },
            wires[output_wires[0]].clone(),
            gate_type,
        );
        gates.push(gate);
        i += 1;
    }
    let c = Circuit::new(wires.clone(), gates);

    let mut inputs = Vec::new();
    let wires_copy = wires.clone();
    let mut wires_iter = wires_copy.iter();
    for input_size in input_sizes {
        let mut input = Vec::new();
        for _ in 0..input_size {
            input.push(wires_iter.next().unwrap().clone());
        }
        inputs.push(input);
    }

    let mut outputs = Vec::new();
    let mut wires_reversed = wires.clone();
    wires_reversed.reverse();
    let mut wires_iter = wires_reversed.iter();
    for output_size in output_sizes.iter().rev() {
        let mut output = Vec::new();
        for _ in 0..*output_size {
            output.push(wires_iter.next().unwrap().clone());
        }
        output.reverse();
        outputs.push(output);
    }
    outputs.reverse();

    (c, inputs, outputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, rng};

    #[test]
    fn test_bristol_adder() {
        let (circuit, inputs, outputs) = parser("src/core/bristol-examples/adder64.txt");
        let a: u64 = rng().random();
        let b: u64 = rng().random();
        for (i, wire) in inputs[0].iter().enumerate() {
            wire.borrow_mut().set((a >> i) & 1 == 1);
        }
        for (i, wire) in inputs[1].iter().enumerate() {
            wire.borrow_mut().set((b >> i) & 1 == 1);
        }
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let mut result_bits = Vec::new();
        for wire in outputs[0].clone() {
            result_bits.push(wire.borrow().get_value());
        }
        let mut c: u64 = 0;
        for bit in result_bits.iter().rev() {
            c = 2 * c + if *bit { 1 } else { 0 };
        }
        assert_eq!(c, a.wrapping_add(b));
    }

    #[test]
    fn test_bristol_multiplier() {
        let (circuit, inputs, outputs) = parser("src/core/bristol-examples/multiplier64.txt");
        let a: u64 = rng().random();
        let b: u64 = rng().random();
        for (i, wire) in inputs[0].iter().enumerate() {
            wire.borrow_mut().set((a >> i) & 1 == 1);
        }
        for (i, wire) in inputs[1].iter().enumerate() {
            wire.borrow_mut().set((b >> i) & 1 == 1);
        }
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let mut result_bits = Vec::new();
        for wire in outputs[0].clone() {
            result_bits.push(wire.borrow().get_value());
        }
        let mut c: u64 = 0;
        for bit in result_bits.iter().rev() {
            c = 2 * c + if *bit { 1 } else { 0 };
        }
        assert_eq!(c, a.wrapping_mul(b));
    }

    #[test]
    fn test_bristol_subtracter() {
        let (circuit, inputs, outputs) = parser("src/core/bristol-examples/subtracter64.txt");
        let a: u64 = rng().random();
        let b: u64 = rng().random();
        for (i, wire) in inputs[0].iter().enumerate() {
            wire.borrow_mut().set((a >> i) & 1 == 1);
        }
        for (i, wire) in inputs[1].iter().enumerate() {
            wire.borrow_mut().set((b >> i) & 1 == 1);
        }
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let mut result_bits = Vec::new();
        for wire in outputs[0].clone() {
            result_bits.push(wire.borrow().get_value());
        }
        let mut c: u64 = 0;
        for bit in result_bits.iter().rev() {
            c = 2 * c + if *bit { 1 } else { 0 };
        }
        assert_eq!(c, a.wrapping_sub(b));
    }
}
