use std::{cell::RefCell, rc::Rc};
use bitvm::{bigint::U256, hash::blake3::blake3_compute_script_with_limb, treepp::*};
use crate::{convert_between_blake3_and_normal_form, s::S, wire::Wire, LIMB_LEN, N_LIMBS};

#[derive(Clone)]
pub struct Gate {
    pub wire_a: Rc<RefCell<Wire>>,
    pub wire_b: Rc<RefCell<Wire>>,
    pub wire_c: Rc<RefCell<Wire>>,
    pub name: String,
}

impl Gate {
    pub fn new(wire_a: Rc<RefCell<Wire>>, wire_b: Rc<RefCell<Wire>>, wire_c: Rc<RefCell<Wire>>, name: String) -> Self {
        Self {
            wire_a,
            wire_b,
            wire_c,
            name,
        }
    }

    pub fn f(&self) -> fn(bool, bool) -> bool {
        if self.name == "and" {
            fn and(a: bool, b: bool) -> bool {a & b}
            return and;
        }
        else if self.name == "or" {
            fn or(a: bool, b: bool) -> bool {a | b}
            return or;
        }
        else if self.name == "xor" {
            fn xor(a: bool, b: bool) -> bool {a ^ b}
            return xor;
        }
        else if self.name == "nand" {
            fn nand(a: bool, b: bool) -> bool {!(a ^ b)}
            return nand;
        }
        else if self.name == "inv" {
            fn not(a: bool, _b: bool) -> bool {!a}
            return not;
        }
        else {
            fn empty(_a: bool, _b: bool) -> bool {false}
            return empty;
        }
    }

    pub fn evaluation_script(&self) -> Script {
        if self.name == "and" {
            script! { OP_BOOLAND }
        }
        else if self.name == "or" {
            script! { OP_BOOLOR }
        }
        else if self.name == "xor" {
            script! { OP_NUMNOTEQUAL }
        }
        else if self.name == "nand" {
            script! { OP_BOOLAND OP_NOT }
        }
        else if self.name == "inv" {
            script! { OP_DROP OP_NOT }
        }
        else {
            script! {}
        }
    }
    
    pub fn evaluate(&mut self) {
        self.wire_c.borrow_mut().set((self.f())(self.wire_a.borrow().get_value(), self.wire_b.borrow().get_value()));
    }

    pub fn garbled(&self) -> Vec<S> {
        let mut result = Vec::new();
        for (i, j) in [(false, false), (true, false), (false, true), (true, true)] {
            let k = (self.f())(i, j);
            let a = self.wire_a.borrow().select(i);
            let b = self.wire_b.borrow().select(j);
            let c = self.wire_c.borrow().select(k);
            let garbled_row = S::hash_together(a, b) + c.neg();
            result.push(garbled_row);
        }
        result
    }

    pub fn check_garble(&self, garble: Vec<S>, bit: bool) -> (bool, S) {
        let a = self.wire_a.borrow().get_label();
        let b = self.wire_b.borrow().get_label();
        let bit_a = self.wire_a.borrow().get_value();
        let bit_b = self.wire_b.borrow().get_value();
        let row = garble[(if bit_a {1} else {0})+2*(if bit_b {1} else {0})].clone();
        let c = S::hash_together(a, b) + row.neg();
        let hc = c.hash();
        (hc == self.wire_c.borrow().select_hash(bit), c)
    }

    pub fn script(&self, garbled: Vec<S>, correct: bool) -> Script {
        script! {                                                     // a bit_a b bit_b
            { N_LIMBS + 1 } OP_PICK                                   // a bit_a b bit_b bit_a
            OP_OVER                                                   // a bit_a b bit_b bit_a bit_b
            OP_TOALTSTACK OP_TOALTSTACK                               // a bit_a b bit_b | bit_a bit_b
            for _ in 0..N_LIMBS { {2 * N_LIMBS + 1} OP_PICK }         // a bit_a b bit_b a | bit_a bit_b
            for _ in 0..N_LIMBS { {2 * N_LIMBS} OP_PICK }             // a bit_a b bit_b a b | bit_a bit_b
            { U256::toaltstack() } { U256::toaltstack() }             // a bit_a b bit_b | a b bit_a bit_b
            OP_TOALTSTACK { U256::toaltstack() }                      // a bit_a | b bit_b a b bit_a bit_b
            { self.wire_a.borrow().commitment_script() } OP_VERIFY    // | b bit_b a b bit_a bit_b
            { U256::fromaltstack() } OP_FROMALTSTACK                  // b bit_b | a b bit_a bit_b
            { self.wire_b.borrow().commitment_script() } OP_VERIFY    // | a b bit_a bit_b
            { U256::fromaltstack() }                                  // a | b bit_a bit_b
            { convert_between_blake3_and_normal_form() }              // a' | b bit_a bit_b
            { U256::fromaltstack() }                                  // a' b | bit_a bit_b
            { convert_between_blake3_and_normal_form() }              // a' b' | bit_a bit_b
            { blake3_compute_script_with_limb(64, LIMB_LEN) }
            { U256::transform_limbsize(4, LIMB_LEN.into()) }          // hab | bit_a bit_b
            { U256::push_hex(&hex::encode(garbled[0].0)) }
            { U256::push_hex(&hex::encode(garbled[1].0)) }
            { U256::push_hex(&hex::encode(garbled[2].0)) }
            { U256::push_hex(&hex::encode(garbled[3].0)) }            // hab tau0 tau1 tau2 tau3 | bit_a bit_b
            OP_FROMALTSTACK OP_FROMALTSTACK                           // hab tau0 tau1 tau2 tau3 bit_a bit_b
            OP_2DUP OP_TOALTSTACK OP_TOALTSTACK                       // hab tau0 tau1 tau2 tau3 bit_a bit_b | bit_a bit_b
            OP_IF
                OP_IF
                // tau3
                { U256::toaltstack() }
                { U256::drop() }
                { U256::drop() }
                { U256::drop() }
                { U256::fromaltstack() }
                OP_ELSE
                // tau2
                { U256::drop() }
                { U256::toaltstack() }
                { U256::drop() }
                { U256::drop() }
                { U256::fromaltstack() }
                OP_ENDIF
            OP_ELSE
                OP_IF
                // tau1
                { U256::drop() }
                { U256::drop() }
                { U256::toaltstack() }
                { U256::drop() }
                { U256::fromaltstack() }
                OP_ELSE
                // tau0
                { U256::drop() }
                { U256::drop() }
                { U256::drop() }
                OP_ENDIF
            OP_ENDIF                                               // hab tau | bit_a bit_b
            { U256::sub(1, 0) }                                    // c=hab-tau | bit_a bit_b
            OP_FROMALTSTACK OP_FROMALTSTACK                        // c bit_a bit_b
            { self.evaluation_script() }                           // c bit_c
            { self.wire_c.borrow().commitment_script() }
            if correct {
                OP_VERIFY
            }
            else {
                OP_NOT OP_VERIFY
            }
            OP_TRUE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gate() {
        let wire_1 = Rc::new(RefCell::new(Wire::new()));
        let wire_2 = Rc::new(RefCell::new(Wire::new()));
        let wire_3 = Rc::new(RefCell::new(Wire::new()));
        let gate = Gate::new(wire_1, wire_2, wire_3, "and".to_string());

        let correct_garbled = gate.garbled();
        let incorrect_garbled = vec![S::random(), S::random(), S::random(), S::random()];

        for (correct, garbled) in [(true, correct_garbled), (false, incorrect_garbled)] {
            println!("testing {:?} garble", if correct {"correct"} else {"incorrect"});
            for bit_a in [false, true] {
                for bit_b in [false, true] {
                    let a = gate.wire_a.borrow().select(bit_a);
                    let b = gate.wire_b.borrow().select(bit_b);
                    let gate_script = gate.script(garbled.clone(), correct);
                    let script = script! {
                        { U256::push_hex(&hex::encode(&a.0)) }
                        { if bit_a {1} else {0} }
                        { U256::push_hex(&hex::encode(&b.0)) }
                        { if bit_b {1} else {0} }
                        { gate_script }
                    };
                    println!("script len: {:?}", script.len());
                    let result = execute_script(script);
                    assert!(result.success);
                }
            }
        }
    }
}
