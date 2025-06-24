use crate::bag::*;
use crate::core::utils::{LIMB_LEN, N_LIMBS, bit_to_usize, convert_between_blake3_and_normal_form};
use bitvm::{bigint::U256, hash::blake3::blake3_compute_script_with_limb, treepp::*};
use std::ops::{Add, AddAssign};

#[derive(Clone)]
pub struct Gate {
    pub wire_a: Rc<RefCell<Wire>>,
    pub wire_b: Rc<RefCell<Wire>>,
    pub wire_c: Rc<RefCell<Wire>>,
    pub name: String,
}

impl Gate {
    pub fn new(
        wire_a: Rc<RefCell<Wire>>,
        wire_b: Rc<RefCell<Wire>>,
        wire_c: Rc<RefCell<Wire>>,
        name: String,
    ) -> Self {
        Self {
            wire_a,
            wire_b,
            wire_c,
            name,
        }
    }

    pub fn and(
        wire_a: Rc<RefCell<Wire>>,
        wire_b: Rc<RefCell<Wire>>,
        wire_c: Rc<RefCell<Wire>>,
    ) -> Self {
        Self::new(wire_a, wire_b, wire_c, "and".to_string())
    }

    pub fn nand(
        wire_a: Rc<RefCell<Wire>>,
        wire_b: Rc<RefCell<Wire>>,
        wire_c: Rc<RefCell<Wire>>,
    ) -> Self {
        Self::new(wire_a, wire_b, wire_c, "nand".to_string())
    }

    pub fn or(
        wire_a: Rc<RefCell<Wire>>,
        wire_b: Rc<RefCell<Wire>>,
        wire_c: Rc<RefCell<Wire>>,
    ) -> Self {
        Self::new(wire_a, wire_b, wire_c, "or".to_string())
    }

    pub fn xor(
        wire_a: Rc<RefCell<Wire>>,
        wire_b: Rc<RefCell<Wire>>,
        wire_c: Rc<RefCell<Wire>>,
    ) -> Self {
        Self::new(wire_a, wire_b, wire_c, "xor".to_string())
    }

    pub fn xnor(
        wire_a: Rc<RefCell<Wire>>,
        wire_b: Rc<RefCell<Wire>>,
        wire_c: Rc<RefCell<Wire>>,
    ) -> Self {
        Self::new(wire_a, wire_b, wire_c, "xnor".to_string())
    }

    pub fn not(wire_a: Rc<RefCell<Wire>>, wire_c: Rc<RefCell<Wire>>) -> Self {
        Self::new(wire_a.clone(), wire_a.clone(), wire_c, "not".to_string())
    }

    pub fn nimp(
        wire_a: Rc<RefCell<Wire>>,
        wire_b: Rc<RefCell<Wire>>,
        wire_c: Rc<RefCell<Wire>>,
    ) -> Self {
        Self::new(wire_a.clone(), wire_b.clone(), wire_c, "nimp".to_string())
    }

    pub fn nsor(
        wire_a: Rc<RefCell<Wire>>,
        wire_b: Rc<RefCell<Wire>>,
        wire_c: Rc<RefCell<Wire>>,
    ) -> Self {
        Self::new(wire_a.clone(), wire_b.clone(), wire_c, "nsor".to_string())
    }

    pub fn f(&self) -> fn(bool, bool) -> bool {
        match self.name.as_str() {
            "and" => {
                fn and(a: bool, b: bool) -> bool {
                    a & b
                }
                and
            }
            "or" => {
                fn or(a: bool, b: bool) -> bool {
                    a | b
                }
                or
            }
            "xor" => {
                fn xor(a: bool, b: bool) -> bool {
                    a ^ b
                }
                xor
            }
            "nand" => {
                fn nand(a: bool, b: bool) -> bool {
                    !(a & b)
                }
                nand
            }
            "inv" | "not" => {
                fn not(a: bool, _b: bool) -> bool {
                    !a
                }
                not
            }
            "xnor" => {
                fn xnor(a: bool, b: bool) -> bool {
                    !(a ^ b)
                }
                xnor
            }
            "nimp" => {
                fn nimp(a: bool, b: bool) -> bool {
                    (a) && (!b)
                }
                nimp
            }
            "nsor" => {
                fn nsor(a: bool, b: bool) -> bool {
                    a | (!b)
                }
                nsor
            }
            _ => {
                panic!("this gate type is not allowed");
            }
        }
    }

    pub fn evaluation_script(&self) -> Script {
        match self.name.as_str() {
            "and" => script! { OP_BOOLAND },
            "or" => script! { OP_BOOLOR },
            "xor" => script! { OP_NUMNOTEQUAL },
            "nand" => script! { OP_BOOLAND OP_NOT },
            "inv" | "not" => script! { OP_DROP OP_NOT },
            "xnor" => script! { OP_NUMNOTEQUAL OP_NOT },
            "nimp" => script! { OP_NOT OP_BOOLAND },
            "nsor" => script! { OP_NOT OP_BOOLOR},
            _ => panic!("this gate type is not allowed"),
        }
    }

    pub fn evaluate(&mut self) {
        self.wire_c.borrow_mut().set((self.f())(
            self.wire_a.borrow().get_value(),
            self.wire_b.borrow().get_value(),
        ));
    }

    pub fn garbled(&self) -> Vec<S> {
        [(false, false), (true, false), (false, true), (true, true)]
            .iter()
            .map(|(i, j)| {
                let k = (self.f())(*i, *j);
                let a = self.wire_a.borrow().select(*i);
                let b = self.wire_b.borrow().select(*j);
                let c = self.wire_c.borrow().select(k);
                S::hash_together(a, b) + c.neg()
            })
            .collect()
    }

    pub fn check_garble(&self, garble: Vec<S>, bit: bool) -> (bool, S) {
        let a = self.wire_a.borrow().get_label();
        let b = self.wire_b.borrow().get_label();
        let index = bit_to_usize(self.wire_a.borrow().get_value())
            + 2 * bit_to_usize(self.wire_b.borrow().get_value());
        let row = garble[index];
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

pub struct GateCount {
    pub and: usize,
    pub or: usize,
    pub xor: usize,
    pub nand: usize,
    pub not: usize,
    pub xnor: usize,
    pub nimp: usize,
    pub nsor: usize,
}

impl Add for GateCount {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        Self {
            and: self.and + other.and,
            or: self.or + other.or,
            xor: self.xor + other.xor,
            nand: self.nand + other.nand,
            not: self.not + other.not,
            xnor: self.xnor + other.xnor,
            nimp: self.nimp + other.nimp,
            nsor: self.nsor + other.nsor,
        }
    }
}

impl AddAssign for GateCount {
    fn add_assign(&mut self, other: Self) {
        self.and = self.and + other.and;
        self.or = self.or + other.or;
        self.xor = self.xor + other.xor;
        self.nand = self.nand + other.nand;
        self.not = self.not + other.not;
        self.xnor = self.xnor + other.xnor;
        self.nimp = self.nimp + other.nimp;
        self.nsor = self.nsor + other.nsor;
    }
}

impl GateCount {
    pub fn zero() -> Self {
        Self {
            and: 0,
            or: 0,
            xor: 0,
            nand: 0,
            not: 0,
            xnor: 0,
            nimp: 0,
            nsor: 0,
        }
    }

    pub fn total_gate_count(&self) -> usize {
        self.and + self.or + self.xor + self.nand + self.not + self.xnor + self.nimp + self.nsor
    }

    pub fn nonfree_gate_count(&self) -> usize {
        self.and + self.or + self.nand + self.nimp + self.nsor
    }

    pub fn print(&self) {
        println!("and:  {:?}", self.and);
        println!("or:   {:?}", self.or);
        println!("xor:  {:?}", self.xor);
        println!("nand: {:?}", self.nand);
        println!("not:  {:?}", self.not);
        println!("xnor: {:?}", self.xnor);
        println!("nimp: {:?}", self.nimp);
        println!("nsor: {:?}", self.nsor);
        println!();
        println!("total: {:?}", self.total_gate_count());
        println!("nonfree: {:?}", self.nonfree_gate_count());
    }
}

// these are here to speed up tests
impl GateCount {
    pub fn msm() -> Self {
        Self {
            and: 128808400,
            or: 76938400,
            xor: 102685425,
            nand: 213127590,
            not: 123282230,
            xnor: 51296850,
            nimp: 0,
            nsor: 0,
        }
    }

    pub fn msm_montgomery() -> Self {
        Self {
            and: 70952000,
            or: 31138000,
            xor: 62923825,
            nand: 58898790,
            not: 19856230,
            xnor: 89650,
            nimp: 1078400,
            nsor: 0,
        }
    }

    pub fn fq12_square() -> Self {
        Self {
            and: 12112256,
            or: 7260636,
            xor: 9693597,
            nand: 14567916,
            not: 9792178,
            xnor: 4837396,
            nimp: 0,
            nsor: 0,
        }
    }

    pub fn fq12_square_montgomery() -> Self {
        Self {
            and: 5536354,
            or: 2492002,
            xor: 4928636,
            nand: 344424,
            not: 247730,
            xnor: 108020,
            nimp: 80880,
            nsor: 0,
        }
    }

    pub fn fq12_cyclotomic_square() -> Self {
        Self {
            and: 5903509,
            or: 3540097,
            xor: 4728316,
            nand: 7090410,
            not: 4767360,
            xnor: 2357575,
            nimp: 0,
            nsor: 0,
        }
    }

    pub fn fq12_cyclotomic_square_montgomery() -> Self {
        Self {
            and: 3299971,
            or: 1479079,
            xor: 2939044,
            nand: 150114,
            not: 113190,
            xnor: 53251,
            nimp: 48528,
            nsor: 0,
        }
    }

    pub fn fq12_mul() -> Self {
        Self {
            and: 14793358,
            or: 8875324,
            xor: 11846173,
            nand: 17836896,
            not: 11985288,
            xnor: 5912170,
            nimp: 0,
            nsor: 0,
        }
    }

    pub fn fq12_mul_montgomery() -> Self {
        Self {
            and: 8284513,
            or: 3722779,
            xor: 7372993,
            nand: 486156,
            not: 349863,
            xnor: 151360,
            nimp: 121320,
            nsor: 0,
        }
    }

    pub fn fq12_inverse() -> Self {
        Self {
            and: 41464294,
            or: 22347965,
            xor: 32020868,
            nand: 43551348,
            not: 28864311,
            xnor: 13277144,
            nimp: 0,
            nsor: 0,
        }
    }

    pub fn fq12_inverse_montgomery() -> Self {
        Self {
            and: 25203015,
            or: 10118684,
            xor: 20503958,
            nand: 4991100,
            not: 3002469,
            xnor: 473862,
            nimp: 240452,
            nsor: 0,
        }
    }

    pub fn double_in_place() -> Self {
        Self {
            and: 7285002,
            or: 4452836,
            xor: 5912236,
            nand: 9029700,
            not: 6066530,
            xnor: 3000110,
            nimp: 0,
            nsor: 0,
        }
    }

    pub fn double_in_place_montgomery() -> Self {
        Self {
            and: 4227835,
            or: 1896606,
            xor: 3807690,
            nand: 72390,
            not: 59755,
            xnor: 26095,
            nimp: 58140,
            nsor: 0,
        }
    }

    pub fn add_in_place() -> Self {
        Self {
            and: 11969527,
            or: 7156743,
            xor: 9554233,
            nand: 14353794,
            not: 9644762,
            xnor: 4769941,
            nimp: 0,
            nsor: 0,
        }
    }

    pub fn add_in_place_montgomery() -> Self {
        Self {
            and: 6617810,
            or: 2920206,
            xor: 5876285,
            nand: 87630,
            not: 77857,
            xnor: 33275,
            nimp: 99752,
            nsor: 0,
        }
    }

    pub fn ell() -> Self {
        Self {
            and: 13963948,
            or: 8354104,
            xor: 11156899,
            nand: 16741140,
            not: 11250566,
            xnor: 5564020,
            nimp: 0,
            nsor: 0,
        }
    }

    pub fn ell_montgomery() -> Self {
        Self {
            and: 7744385,
            or: 3430561,
            xor: 6882527,
            nand: 161544,
            not: 132271,
            xnor: 59246,
            nimp: 115928,
            nsor: 0,
        }
    }

    pub fn ell_by_constant() -> Self {
        Self {
            and: 11438002,
            or: 7357571,
            xor: 9665248,
            nand: 15223236,
            not: 10232611,
            xnor: 5060584,
            nimp: 0,
            nsor: 0,
        }
    }

    pub fn ell_by_constant_montgomery() -> Self {
        Self {
            and: 7385523,
            or: 3424927,
            xor: 6848341,
            nand: 158496,
            not: 130231,
            xnor: 58734,
            nimp: 80920,
            nsor: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gate() {
        let wire_1 = new_wirex();
        let wire_2 = new_wirex();
        let wire_3 = new_wirex();
        let gate = Gate::and(wire_1, wire_2, wire_3);

        let correct_garbled = gate.garbled();
        let incorrect_garbled = vec![S::random(), S::random(), S::random(), S::random()];

        for (correct, garbled) in [(true, correct_garbled), (false, incorrect_garbled)] {
            println!(
                "testing {:?} garble",
                if correct { "correct" } else { "incorrect" }
            );
            for (bit_a, bit_b) in [(false, false), (true, false), (false, true), (true, true)] {
                let a = gate.wire_a.borrow().select(bit_a);
                let b = gate.wire_b.borrow().select(bit_b);
                let gate_script = gate.script(garbled.clone(), correct);
                let script = script! {
                    { U256::push_hex(&hex::encode(a.0)) }
                    { if bit_a {1} else {0} }
                    { U256::push_hex(&hex::encode(b.0)) }
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
