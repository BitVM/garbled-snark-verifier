//! Boolean Pasta field kernels for a future Nova/Spartan/IPA verifier.
//!
//! These predicates check arithmetic claims. They do not verify Nova proofs.
//! Encodings are 256 little-endian bits and MUST be strictly below the modulus.
use crate::{
    CircuitContext, Gate, WireId,
    circuit::{FALSE_WIRE, TRUE_WIRE, generate_component_key},
};

pub type Word = [WireId; 256];

/// Pallas scalar field = Vesta base field, and conversely.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PastaField {
    PallasBase,
    VestaBase,
}

impl PastaField {
    pub fn modulus_le(self) -> [u64; 4] {
        match self {
            Self::PallasBase => [
                0x992d30ed00000001,
                0x224698fc094cf91b,
                0,
                0x4000000000000000,
            ],
            Self::VestaBase => [
                0x8c46eb2100000001,
                0x224698fc0994a8dd,
                0,
                0x4000000000000000,
            ],
        }
    }
    fn constant(self) -> Word {
        let p = self.modulus_le();
        std::array::from_fn(|i| {
            if (p[i / 64] >> (i % 64)) & 1 == 1 {
                TRUE_WIRE
            } else {
                FALSE_WIRE
            }
        })
    }
}
fn xor<C: CircuitContext>(c: &mut C, a: WireId, b: WireId) -> WireId {
    let w = c.issue_wire();
    c.add_gate(Gate::xor(a, b, w));
    w
}
fn and<C: CircuitContext>(c: &mut C, a: WireId, b: WireId) -> WireId {
    let w = c.issue_wire();
    c.add_gate(Gate::and(a, b, w));
    w
}
fn not<C: CircuitContext>(c: &mut C, a: WireId) -> WireId {
    xor(c, a, TRUE_WIRE)
}
fn mux<C: CircuitContext>(c: &mut C, select_b: WireId, a: WireId, b: WireId) -> WireId {
    let d = xor(c, a, b);
    let t = and(c, select_b, d);
    xor(c, a, t)
}
fn sub<C: CircuitContext>(c: &mut C, a: &Word, b: &Word) -> (Word, WireId) {
    let mut borrow = FALSE_WIRE;
    let mut out = [FALSE_WIRE; 256];
    for i in 0..256 {
        let t = xor(c, a[i], b[i]);
        out[i] = xor(c, t, borrow);
        let na = not(c, a[i]);
        let nt = not(c, t);
        let u = and(c, na, b[i]);
        let v = and(c, nt, borrow);
        borrow = xor(c, u, v);
    }
    (out, borrow)
}
fn add_inner<C: CircuitContext>(c: &mut C, field: PastaField, a: &Word, b: &Word) -> Word {
    let mut carry = FALSE_WIRE;
    let mut sum = [FALSE_WIRE; 256];
    for i in 0..256 {
        let t = xor(c, a[i], b[i]);
        sum[i] = xor(c, t, carry);
        let u = and(c, a[i], b[i]);
        let v = and(c, t, carry);
        carry = xor(c, u, v);
    }
    // For admitted a,b < p, a+b < 2p < 2^256; one subtraction suffices.
    let (reduced, borrow) = sub(c, &sum, &field.constant());
    std::array::from_fn(|i| mux(c, borrow, reduced[i], sum[i]))
}
/// Internal arithmetic on admitted canonical operands. Callers enforce admission.
/// A cached child keeps repeated additions out of the root metadata graph.
fn add_mod<C: CircuitContext>(c: &mut C, field: PastaField, a: &Word, b: &Word) -> Word {
    let tag = [match field {
        PastaField::PallasBase => 0u8,
        PastaField::VestaBase => 1,
    }];
    let key = generate_component_key("nova.pasta.add.v1", [("field", tag.as_slice())], 256, 512);
    let inputs: Vec<WireId> = a.iter().chain(b).copied().collect();
    let out: Vec<WireId> = c.with_named_child(
        key,
        inputs,
        |ctx, wires| {
            let a: Word = wires[..256].try_into().expect("fixed input arity");
            let b: Word = wires[256..].try_into().expect("fixed input arity");
            add_inner(ctx, field, &a, &b).to_vec()
        },
        256,
    );
    out.try_into().expect("fixed output arity")
}
fn equal<C: CircuitContext>(c: &mut C, a: &Word, b: &Word) -> WireId {
    let mut ok = TRUE_WIRE;
    for i in 0..256 {
        let d = xor(c, a[i], b[i]);
        let same = not(c, d);
        ok = and(c, ok, same);
    }
    ok
}
pub fn canonical<C: CircuitContext>(c: &mut C, field: PastaField, x: &Word) -> WireId {
    sub(c, x, &field.constant()).1
}
fn admitted<C: CircuitContext>(
    c: &mut C,
    field: PastaField,
    a: &Word,
    b: &Word,
    z: &Word,
) -> WireId {
    let x = canonical(c, field, a);
    let y = canonical(c, field, b);
    let z = canonical(c, field, z);
    let xy = and(c, x, y);
    and(c, xy, z)
}
/// True iff a,b,z have canonical encodings and z = a+b mod p.
pub fn check_add<C: CircuitContext>(
    c: &mut C,
    field: PastaField,
    a: &Word,
    b: &Word,
    z: &Word,
) -> WireId {
    let valid = admitted(c, field, a, b, z);
    let sum = add_mod(c, field, a, b);
    let eq = equal(c, &sum, z);
    and(c, valid, eq)
}
/// True iff a,b,z have canonical encodings and z = a*b mod p.
/// Fixed 255-round Horner circuit; branch structure never depends on witness bits.
pub fn check_mul<C: CircuitContext>(
    c: &mut C,
    field: PastaField,
    a: &Word,
    b: &Word,
    z: &Word,
) -> WireId {
    let valid = admitted(c, field, a, b, z);
    let mut acc = [FALSE_WIRE; 256];
    for i in (0..255).rev() {
        let doubled = add_mod(c, field, &acc, &acc);
        let masked = std::array::from_fn(|j| and(c, b[i], a[j]));
        acc = add_mod(c, field, &doubled, &masked);
    }
    let eq = equal(c, &acc, z);
    and(c, valid, eq)
}
