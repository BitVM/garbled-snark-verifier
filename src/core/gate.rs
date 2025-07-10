use crate::{bag::*, core::utils::bit_to_usize};
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
    pub fn msm_montgomery() -> Self {
        Self([
            40952275, 39265860, 0, 0, 29750, 19632930, 0, 89650, 125020525, 89700, 210275,
        ])
    }

    pub fn fq12_square_montgomery() -> Self {
        Self([
            3234570, 229616, 0, 0, 1640, 114808, 0, 111068, 9690504, 108020, 132452,
        ])
    }

    pub fn fq12_cyclotomic_square_montgomery() -> Self {
        Self([
            1921672, 100076, 0, 0, 953, 50038, 0, 53251, 5790700, 53251, 62909,
        ])
    }

    pub fn fq12_mul_montgomery() -> Self {
        Self([
            4836448, 324104, 0, 0, 2420, 162052, 0, 155932, 14506687, 151360, 187163,
        ])
    }

    pub fn fq12_inverse_montgomery() -> Self {
        Self([
            14828696, 3327400, 645668, 0, 327459, 1663700, 0, 477163, 39787000, 474370, 498290,
        ])
    }

    pub fn double_in_place_montgomery() -> Self {
        Self([
            2414471, 48260, 0, 0, 979, 24130, 0, 26095, 7548712, 26095, 35520,
        ])
    }

    pub fn add_in_place_montgomery() -> Self {
        Self([
            3828958, 58420, 0, 0, 1669, 29210, 0, 33275, 11650147, 33275, 48528,
        ])
    }

    pub fn ell_montgomery() -> Self {
        Self([
            4486968, 107696, 0, 0, 2018, 53848, 0, 59246, 13625157, 59246, 78199,
        ])
    }

    pub fn ell_by_constant_montgomery() -> Self {
        Self([
            4098864, 105664, 0, 0, 1374, 52832, 0, 58734, 13580727, 58734, 77179,
        ])
    }
}
