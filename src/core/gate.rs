use crate::bag::*;
use crate::core::utils::{LIMB_LEN, N_LIMBS, bit_to_usize, convert_between_blake3_and_normal_form};
use bitvm::{bigint::U256, hash::blake3::blake3_compute_script_with_limb, treepp::*};
use std::ops::{Add, AddAssign};

// Except Xor, Xnor and Not, each enum's bitmask represent the boolean operation ((a XOR bit_2) AND (b XOR bit_1)) XOR bit_0
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum GateType {
    And = 0,
    Nand = 1,
    Nimp = 2,
    Imp = 3, // a => b
    Ncimp = 4,
    Cimp = 5, // b => a
    Nor = 6,
    Or = 7,
    Xor,
    Xnor,
    Not,
}

// only for AND variants
impl TryFrom<u8> for GateType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(GateType::And),
            1 => Ok(GateType::Nand),
            2 => Ok(GateType::Nimp),
            3 => Ok(GateType::Imp),
            4 => Ok(GateType::Ncimp),
            5 => Ok(GateType::Cimp),
            6 => Ok(GateType::Nor),
            7 => Ok(GateType::Or),
            _ => Err(()),
        }
    }
}

const GATE_TYPE_COUNT: usize = 11;

#[derive(Clone)]
pub struct Gate {
    pub wire_a: Wirex,
    pub wire_b: Wirex,
    pub wire_c: Wirex,
    pub gate_type: GateType,
}

impl Gate {
    pub fn new(wire_a: Wirex, wire_b: Wirex, wire_c: Wirex, gate_type: GateType) -> Self {
        Self {
            wire_a,
            wire_b,
            wire_c,
            gate_type,
        }
    }

    pub fn and(wire_a: Wirex, wire_b: Wirex, wire_c: Wirex) -> Self {
        Self::new(wire_a, wire_b, wire_c, GateType::And)
    }

    pub fn nand(wire_a: Wirex, wire_b: Wirex, wire_c: Wirex) -> Self {
        Self::new(wire_a, wire_b, wire_c, GateType::Nand)
    }

    pub fn nimp(wire_a: Wirex, wire_b: Wirex, wire_c: Wirex) -> Self {
        Self::new(wire_a, wire_b, wire_c, GateType::Nimp)
    }

    pub fn imp(wire_a: Wirex, wire_b: Wirex, wire_c: Wirex) -> Self {
        Self::new(wire_a, wire_b, wire_c, GateType::Imp)
    }

    pub fn ncimp(wire_a: Wirex, wire_b: Wirex, wire_c: Wirex) -> Self {
        Self::new(wire_a, wire_b, wire_c, GateType::Ncimp)
    }

    pub fn cimp(wire_a: Wirex, wire_b: Wirex, wire_c: Wirex) -> Self {
        Self::new(wire_a, wire_b, wire_c, GateType::Cimp)
    }

    pub fn nor(wire_a: Wirex, wire_b: Wirex, wire_c: Wirex) -> Self {
        Self::new(wire_a, wire_b, wire_c, GateType::Nor)
    }

    pub fn or(wire_a: Wirex, wire_b: Wirex, wire_c: Wirex) -> Self {
        Self::new(wire_a, wire_b, wire_c, GateType::Or)
    }

    pub fn xor(wire_a: Wirex, wire_b: Wirex, wire_c: Wirex) -> Self {
        Self::new(wire_a, wire_b, wire_c, GateType::Xor)
    }

    pub fn xnor(wire_a: Wirex, wire_b: Wirex, wire_c: Wirex) -> Self {
        Self::new(wire_a, wire_b, wire_c, GateType::Xnor)
    }

    pub fn not(wire_a: Wirex, wire_c: Wirex) -> Self {
        Self::new(wire_a.clone(), wire_a, wire_c, GateType::Not)
    }

    //((a XOR f_0) AND (b XOR f_1)) XOR f_2
    pub fn and_variant(wire_a: Wirex, wire_b: Wirex, wire_c: Wirex, f: [u8; 3]) -> Self {
        let gate_index = (f[0] << 2) | (f[1] << 1) | f[2];
        let gate_type = match GateType::try_from(gate_index) {
            Ok(gt) => gt,
            Err(_) => panic!("Invalid gate type index: {}", gate_index),
        };
        Self::new(wire_a, wire_b, wire_c, gate_type)
    }

    pub fn f(&self) -> fn(bool, bool) -> bool {
        match self.gate_type {
            GateType::And => |a, b| a & b,
            GateType::Nand => |a, b| !(a & b),

            GateType::Nimp => |a, b| a & !b,
            GateType::Imp => |a, b| !a | b,

            GateType::Ncimp => |a, b| !a & b,
            GateType::Cimp => |a, b| !b | a,

            GateType::Nor => |a, b| !(a | b),
            GateType::Or => |a, b| a | b,

            GateType::Xor => |a, b| a ^ b,
            GateType::Xnor => |a, b| !(a ^ b),

            GateType::Not => |a, _| !a,
        }
    }

    pub fn evaluation_script(&self) -> Script {
        match self.gate_type {
            GateType::And => script! { OP_BOOLAND },
            GateType::Nand => script! { OP_BOOLAND OP_NOT },

            GateType::Nimp => script! { OP_SWAP OP_NOT OP_BOOLAND },
            GateType::Imp => script! { OP_NOT OP_SWAP OP_BOOLOR },

            GateType::Ncimp => script! { OP_NOT OP_BOOLAND },
            GateType::Cimp => script! { OP_SWAP OP_NOT OP_BOOLOR },

            GateType::Nor => script! { OP_BOOLOR OP_NOT },
            GateType::Or => script! { OP_BOOLOR },

            GateType::Xor => script! { OP_NUMNOTEQUAL },
            GateType::Xnor => script! { OP_NUMNOTEQUAL OP_NOT },

            GateType::Not => script! { OP_DROP OP_NOT },
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

#[derive(Default)]
pub struct GateCount(pub [u64; GATE_TYPE_COUNT]);

impl Add for GateCount {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        let mut result = [0u64; GATE_TYPE_COUNT];
        for (i, r) in result.iter_mut().enumerate() {
            *r = self.0[i] + other.0[i];
        }
        GateCount(result)
    }
}

impl AddAssign for GateCount {
    fn add_assign(&mut self, other: Self) {
        for i in 0..GATE_TYPE_COUNT {
            self.0[i] += other.0[i];
        }
    }
}

impl GateCount {
    pub fn zero() -> Self {
        Self([0; GATE_TYPE_COUNT])
    }

    pub fn total_gate_count(&self) -> u64 {
        let mut sum = 0u64;
        for x in self.0 {
            sum += x;
        }
        sum
    }

    fn and_variants_count(&self) -> u64 {
        let mut sum = 0u64;
        for x in &self.0[0..8] {
            sum += x;
        }
        sum
    }

    pub fn nonfree_gate_count(&self) -> u64 {
        self.and_variants_count()
    }

    fn xor_variants_count(&self) -> u64 {
        self.0[GateType::Xor as usize] + self.0[GateType::Xnor as usize]
    }

    pub fn print(&self) {
        println!("{:?}", self.0);
        println!("{:<15}{:>11}", "and variants:", self.and_variants_count());
        println!("{:<15}{:>11}", "xor variants:", self.xor_variants_count());
        println!("{:<15}{:>11}", "not:", self.0[GateType::Not as usize]);
        println!("{:<15}{:>11}", "total:", self.total_gate_count());
        println!()
        //println!("nonfree:       {:?}\n", self.nonfree_gate_count()); //equals to and variants
    }

    pub fn and_count(&self) -> u64 {
        self.0[GateType::And as usize]
    }

    pub fn nand_count(&self) -> u64 {
        self.0[GateType::Nand as usize]
    }

    pub fn nimp_count(&self) -> u64 {
        self.0[GateType::Nimp as usize]
    }

    pub fn imp_count(&self) -> u64 {
        self.0[GateType::Imp as usize]
    }

    pub fn ncimp_count(&self) -> u64 {
        self.0[GateType::Ncimp as usize]
    }

    pub fn cimp_count(&self) -> u64 {
        self.0[GateType::Cimp as usize]
    }

    pub fn nor_count(&self) -> u64 {
        self.0[GateType::Nor as usize]
    }

    pub fn or_count(&self) -> u64 {
        self.0[GateType::Or as usize]
    }

    pub fn xor_count(&self) -> u64 {
        self.0[GateType::Xor as usize]
    }

    pub fn xnor_count(&self) -> u64 {
        self.0[GateType::Xnor as usize]
    }

    pub fn not_count(&self) -> u64 {
        self.0[GateType::Not as usize]
    }
}

// these are here to speed up tests
impl GateCount {
    pub fn msm() -> Self {
        /*
        Self {
            and: 128808400,
            or: 51296850,
            xor: 128326975,
            nand: 213127590,
            not: 123282230,
            xnor: 51296850,
            nimp: 0,
            nsor: 0,
        } */
        Self::zero()
    }

    pub fn msm_montgomery() -> Self {
        Self([
            40952275, 39265860, 0, 0, 29750, 19632930, 0, 89650, 125020525, 89700, 210275,
        ])
    }

    pub fn fq12_square() -> Self {
        /*
        Self {
            and: 9875584,
            or: 3951608,
            xor: 9886180,
            nand: 11911584,
            not: 8004680,
            xnor: 3948560,
            nimp: 0,
            nsor: 0,
        }
        */
        Self::zero()
    }

    pub fn fq12_square_montgomery() -> Self {
        Self([
            3234570, 229616, 0, 0, 1640, 114808, 0, 111068, 9690504, 108020, 132452,
        ])
    }

    pub fn fq12_cyclotomic_square() -> Self {
        /*
        Self {
            and: 5903509,
            or: 2357575,
            xor: 5910838,
            nand: 7090410,
            not: 4767360,
            xnor: 2357575,
            nimp: 0,
            nsor: 0,
        }
        */
        Self::zero()
    }

    pub fn fq12_cyclotomic_square_montgomery() -> Self {
        Self([
            1921672, 100076, 0, 0, 953, 50038, 0, 53251, 5790700, 53251, 62909,
        ])
    }

    pub fn fq12_mul() -> Self {
        /*
        Self {
            and: 14793358,
            or: 5916742,
            xor: 14804755,
            nand: 17836896,
            not: 11985288,
            xnor: 5912170,
            nimp: 0,
            nsor: 0,
        }
        */
        Self::zero()
    }

    pub fn fq12_mul_montgomery() -> Self {
        Self([
            4836448, 324104, 0, 0, 2420, 162052, 0, 155932, 14506687, 151360, 187163,
        ])
    }

    pub fn fq12_inverse() -> Self {
        /*
        Self {
            and: 37917672,
            or: 12127813,
            xor: 37294593,
            nand: 39307008,
            not: 26014500,
            xnor: 11867464,
            nimp: 0,
            nsor: 0,
        }
        */
        Self::zero()
    }

    pub fn fq12_inverse_montgomery() -> Self {
        Self([
            14828696, 3327400, 645668, 0, 327459, 1663700, 0, 477163, 39787000, 474370, 498290,
        ])
    }

    pub fn double_in_place() -> Self {
        /*
        Self {
            and: 7285002,
            or: 3000110,
            xor: 7364962,
            nand: 9029700,
            not: 6066530,
            xnor: 3000110,
            nimp: 0,
            nsor: 0,
        }
        */
        Self::zero()
    }

    pub fn double_in_place_montgomery() -> Self {
        Self([
            2414471, 48260, 0, 0, 979, 24130, 0, 26095, 7548712, 26095, 35520,
        ])
    }

    pub fn add_in_place() -> Self {
        /*
        Self {
            and: 11969527,
            or: 4769941,
            xor: 11941035,
            nand: 14353794,
            not: 9644762,
            xnor: 4769941,
            nimp: 0,
            nsor: 0,
        }
        */
        Self::zero()
    }

    pub fn add_in_place_montgomery() -> Self {
        Self([
            3828958, 58420, 0, 0, 1669, 29210, 0, 33275, 11650147, 33275, 48528,
        ])
    }

    pub fn ell() -> Self {
        /*
        Self {
            and: 13963948,
            or: 5564020,
            xor: 13946983,
            nand: 16741140,
            not: 11250566,
            xnor: 5564020,
            nimp: 0,
            nsor: 0,
        }
        */
        Self::zero()
    }

    pub fn ell_montgomery() -> Self {
        Self([
            4486968, 107696, 0, 0, 2018, 53848, 0, 59246, 13625157, 59246, 78199,
        ])
    }

    pub fn ell_by_constant() -> Self {
        /*
        Self {
            and: 11438002,
            or: 5060584,
            xor: 11962235,
            nand: 15223236,
            not: 10232611,
            xnor: 5060584,
            nimp: 0,
            nsor: 0,
        }
        */
        Self::zero()
    }

    pub fn ell_by_constant_montgomery() -> Self {
        Self([
            4098864, 105664, 0, 0, 1374, 52832, 0, 58734, 13580727, 58734, 77179,
        ])
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
