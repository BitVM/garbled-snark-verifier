//! High-level Groth16 verification API (BN254) for streaming circuits.

use std::ops::Deref;

use ark_bn254::Bn254;
use ark_ec::AffineRepr;
use ark_ff::{AdditiveGroup, Field, PrimeField};
use ark_groth16::VerifyingKey;
use itertools::Itertools;
use num_bigint::BigUint;

// Bring trait with N_BITS into scope for Fr/Fq wires
use crate::gadgets::bn254::Fp254Impl;
use crate::{
    CircuitContext, EvaluatedWire, Fq2Wire, FqWire, FrWire, G1Wire, G2Wire, GarbleMode,
    GarbledWire, GateHasher, WireId, bits_from_biguint_with_len,
    circuit::{CiphertextHandler, CircuitInput, CircuitMode, EncodeInput, WiresObject},
    gadgets::groth16::{self as gadgets, CompressedG1Wires, CompressedG2Wires},
};

// ============================================================================
// High-level proof type reused across modes
// ============================================================================

#[derive(Debug, Clone)]
pub struct Proof {
    pub proof: ark_groth16::Proof<Bn254>,
    pub public_inputs: Vec<ark_bn254::Fr>,
}

impl Proof {
    pub fn new(proof: ark_groth16::Proof<Bn254>, public_inputs: Vec<ark_bn254::Fr>) -> Self {
        Self {
            proof,
            public_inputs,
        }
    }
}

/// Verification input = proof + verifying key (off-circuit parameter stored alongside wires)
#[derive(Debug, Clone)]
pub struct VerifierInput {
    pub proof: Proof,
    pub vk: VerifyingKey<Bn254>,
}

#[derive(Debug)]
pub struct ProofWires {
    pub public: Vec<FrWire>,
    pub a_x: FqWire,
    pub a_y: FqWire,
    pub b_x: Fq2Wire,
    pub b_y: Fq2Wire,
    pub c_x: FqWire,
    pub c_y: FqWire,
    pub vk: VerifyingKey<Bn254>,
}

/// Uncompressed encoding wrapper around a `Proof`.
#[derive(Debug, Clone)]
pub struct Uncompressed(pub VerifierInput);

impl CircuitInput for Uncompressed {
    type WireRepr = ProofWires;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        ProofWires {
            public: self
                .0
                .proof
                .public_inputs
                .iter()
                .map(|_| FrWire::new(&mut issue))
                .collect(),
            a_x: FqWire::new(&mut issue),
            a_y: FqWire::new(&mut issue),
            b_x: Fq2Wire::new(&mut issue),
            b_y: Fq2Wire::new(&mut issue),
            c_x: FqWire::new(&mut issue),
            c_y: FqWire::new(&mut issue),
            vk: self.0.vk.clone(),
        }
    }
    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        let mut ids = Vec::new();
        for s in &repr.public {
            ids.extend(s.to_wires_vec());
        }
        ids.extend(repr.a_x.to_wires_vec());
        ids.extend(repr.a_y.to_wires_vec());
        ids.extend(repr.b_x.to_wires_vec());
        ids.extend(repr.b_y.to_wires_vec());
        ids.extend(repr.c_x.to_wires_vec());
        ids.extend(repr.c_y.to_wires_vec());
        ids
    }
}

impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for Uncompressed {
    fn encode(&self, repr: &ProofWires, cache: &mut M) {
        // Public Fr scalars
        for (w, v) in repr.public.iter().zip(self.0.proof.public_inputs.iter()) {
            let fr_fn = FrWire::get_wire_bits_fn(w, v).expect("fr encoding fn");
            for &wire in w.iter() {
                if let Some(bit) = fr_fn(wire) {
                    cache.feed_wire(wire, bit);
                }
            }
        }

        // Convert to Montgomery for encoding
        let a_m = G1Wire::as_montgomery(self.0.proof.proof.a.into_group());
        let b_m = G2Wire::as_montgomery(self.0.proof.proof.b.into_group());
        let c_m = G1Wire::as_montgomery(self.0.proof.proof.c.into_group());

        // A.x, A.y
        let a_x_fn = FqWire::get_wire_bits_fn(&repr.a_x, &a_m.x).unwrap();
        for &w in repr.a_x.iter() {
            if let Some(b) = a_x_fn(w) {
                cache.feed_wire(w, b);
            }
        }
        let a_y_fn = FqWire::get_wire_bits_fn(&repr.a_y, &a_m.y).unwrap();
        for &w in repr.a_y.iter() {
            if let Some(b) = a_y_fn(w) {
                cache.feed_wire(w, b);
            }
        }

        // B.x, B.y (Fq2)
        let b_x_fn = Fq2Wire::get_wire_bits_fn(&repr.b_x, &b_m.x).unwrap();
        for &w in repr.b_x.iter() {
            if let Some(b) = b_x_fn(w) {
                cache.feed_wire(w, b);
            }
        }
        let b_y_fn = Fq2Wire::get_wire_bits_fn(&repr.b_y, &b_m.y).unwrap();
        for &w in repr.b_y.iter() {
            if let Some(b) = b_y_fn(w) {
                cache.feed_wire(w, b);
            }
        }

        // C.x, C.y
        let c_x_fn = FqWire::get_wire_bits_fn(&repr.c_x, &c_m.x).unwrap();
        for &w in repr.c_x.iter() {
            if let Some(b) = c_x_fn(w) {
                cache.feed_wire(w, b);
            }
        }
        let c_y_fn = FqWire::get_wire_bits_fn(&repr.c_y, &c_m.y).unwrap();
        for &w in repr.c_y.iter() {
            if let Some(b) = c_y_fn(w) {
                cache.feed_wire(w, b);
            }
        }
    }
}

/// Verify an uncompressed Groth16 proof. Returns a single boolean wire id.
pub fn verify<C: CircuitContext>(ctx: &mut C, wires: &ProofWires) -> WireId {
    // z should be constant 1 in Montgomery domain for projective points
    let one_m = FqWire::as_montgomery(ark_bn254::Fq::ONE);
    let zero_m = FqWire::as_montgomery(ark_bn254::Fq::ZERO);

    let a = G1Wire {
        x: wires.a_x.clone(),
        y: wires.a_y.clone(),
        z: FqWire::new_constant(&one_m).unwrap(),
    };
    let b = G2Wire {
        x: wires.b_x.clone(),
        y: wires.b_y.clone(),
        z: Fq2Wire([
            FqWire::new_constant(&one_m).unwrap(),
            FqWire::new_constant(&zero_m).unwrap(),
        ]),
    };
    let c = G1Wire {
        x: wires.c_x.clone(),
        y: wires.c_y.clone(),
        z: FqWire::new_constant(&one_m).unwrap(),
    };

    gadgets::groth16_verify(ctx, &wires.public, &a, &b, &c, &wires.vk)
}

// ============================================================================
// Compressed wires and wrapper around a Proof
// ============================================================================

#[derive(Debug)]
pub struct ProofCompressedWires {
    pub public: Vec<FrWire>,
    pub a: CompressedG1Wires,
    pub b: CompressedG2Wires,
    pub c: CompressedG1Wires,
    pub vk: VerifyingKey<Bn254>,
}

/// Compressed encoding wrapper around a `Proof`.
#[derive(Debug, Clone)]
pub struct Compressed(pub VerifierInput);

impl CircuitInput for Compressed {
    type WireRepr = ProofCompressedWires;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        ProofCompressedWires {
            public: self
                .0
                .proof
                .public_inputs
                .iter()
                .map(|_| FrWire::new(&mut issue))
                .collect(),
            a: CompressedG1Wires::new(&mut issue),
            b: CompressedG2Wires::new(&mut issue),
            c: CompressedG1Wires::new(issue),
            vk: self.0.vk.clone(),
        }
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        let mut ids = Vec::new();
        for s in &repr.public {
            ids.extend(s.to_wires_vec());
        }
        ids.extend(repr.a.to_wires_vec());
        ids.extend(repr.b.to_wires_vec());
        ids.extend(repr.c.to_wires_vec());
        ids
    }
}

impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for Compressed {
    fn encode(&self, repr: &ProofCompressedWires, cache: &mut M) {
        // Public Fr scalars
        for (w, v) in repr.public.iter().zip(self.0.proof.public_inputs.iter()) {
            let fr_fn = FrWire::get_wire_bits_fn(w, v).unwrap();
            for &wire in w.iter() {
                if let Some(bit) = fr_fn(wire) {
                    cache.feed_wire(wire, bit);
                }
            }
        }

        // Compute sign flags off-circuit using standard affine, feed Montgomery x
        let a_aff_std = self.0.proof.proof.a;
        let b_aff_std = self.0.proof.proof.b;
        let c_aff_std = self.0.proof.proof.c;

        let a_flag = (a_aff_std.y.square())
            .sqrt()
            .expect("y^2 must be QR")
            .eq(&a_aff_std.y);
        let b_flag = (b_aff_std.y.square())
            .sqrt()
            .expect("y^2 must be QR in Fq2")
            .eq(&b_aff_std.y);
        let c_flag = (c_aff_std.y.square())
            .sqrt()
            .expect("y^2 must be QR")
            .eq(&c_aff_std.y);

        let a_x_m = FqWire::as_montgomery(a_aff_std.x);
        let b_x_m = Fq2Wire::as_montgomery(b_aff_std.x);
        let c_x_m = FqWire::as_montgomery(c_aff_std.x);

        let a_x_fn = FqWire::get_wire_bits_fn(&repr.a.x_m, &a_x_m).unwrap();
        for &wire_id in repr.a.x_m.iter() {
            if let Some(bit) = a_x_fn(wire_id) {
                cache.feed_wire(wire_id, bit);
            }
        }
        cache.feed_wire(repr.a.y_flag, a_flag);

        let b_x_fn = Fq2Wire::get_wire_bits_fn(&repr.b.p, &b_x_m).unwrap();
        for &wire_id in repr.b.p.iter() {
            if let Some(bit) = b_x_fn(wire_id) {
                cache.feed_wire(wire_id, bit);
            }
        }
        cache.feed_wire(repr.b.y_flag, b_flag);

        let c_x_fn = FqWire::get_wire_bits_fn(&repr.c.x_m, &c_x_m).unwrap();
        for &wire_id in repr.c.x_m.iter() {
            if let Some(bit) = c_x_fn(wire_id) {
                cache.feed_wire(wire_id, bit);
            }
        }
        cache.feed_wire(repr.c.y_flag, c_flag);
    }
}

/// Verify a compressed Groth16 proof. Returns a single boolean wire id.
pub fn verify_compressed<C: CircuitContext>(ctx: &mut C, wires: &ProofCompressedWires) -> WireId {
    gadgets::groth16_verify_compressed(ctx, &wires.public, &wires.a, &wires.b, &wires.c, &wires.vk)
}

// ============================================================================
// Garbling helpers (deterministic allocation/encoding of input labels)
// ============================================================================

#[derive(Debug, Clone)]
pub struct GarblerInput {
    pub public_params_len: usize,
    pub vk: VerifyingKey<Bn254>,
}

impl GarblerInput {
    pub fn compress(self) -> GarblerCompressedInput {
        GarblerCompressedInput { inner: self }
    }
}

impl CircuitInput for GarblerInput {
    type WireRepr = ProofWires;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        ProofWires {
            public: (0..self.public_params_len)
                .map(|_| FrWire::new(&mut issue))
                .collect(),
            a_x: FqWire::new(&mut issue),
            a_y: FqWire::new(&mut issue),
            b_x: Fq2Wire::new(&mut issue),
            b_y: Fq2Wire::new(&mut issue),
            c_x: FqWire::new(&mut issue),
            c_y: FqWire::new(&mut issue),
            vk: self.vk.clone(),
        }
    }
    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        let mut ids = Vec::new();
        for s in &repr.public {
            ids.extend(s.to_wires_vec());
        }
        ids.extend(repr.a_x.to_wires_vec());
        ids.extend(repr.a_y.to_wires_vec());
        ids.extend(repr.b_x.to_wires_vec());
        ids.extend(repr.b_y.to_wires_vec());
        ids.extend(repr.c_x.to_wires_vec());
        ids.extend(repr.c_y.to_wires_vec());
        ids
    }
}

impl<H: GateHasher, CTH: CiphertextHandler> EncodeInput<GarbleMode<H, CTH>> for GarblerInput {
    fn encode(&self, repr: &ProofWires, cache: &mut GarbleMode<H, CTH>) {
        for w in &repr.public {
            for &wire in w.iter() {
                let gw = cache.issue_garbled_wire();
                cache.feed_wire(wire, gw);
            }
        }
        for &wire_id in repr.a_x.iter().chain(repr.a_y.iter()) {
            let gw = cache.issue_garbled_wire();
            cache.feed_wire(wire_id, gw);
        }
        for &wire_id in repr.b_x.iter().chain(repr.b_y.iter()) {
            let gw = cache.issue_garbled_wire();
            cache.feed_wire(wire_id, gw);
        }
        for &wire_id in repr.c_x.iter().chain(repr.c_y.iter()) {
            let gw = cache.issue_garbled_wire();
            cache.feed_wire(wire_id, gw);
        }
    }
}

// ============================================================================
// Evaluation helpers (map provided labels + semantic proof into EvaluatedWire inputs)
// ============================================================================

/// Bit-vector wrapper for field element wires evaluated against garbled labels.
#[derive(Debug, Clone)]
pub struct EvaluatedFrWires(pub Vec<EvaluatedWire>);

impl Deref for EvaluatedFrWires {
    type Target = [EvaluatedWire];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
pub struct EvaluatedG1Wires {
    pub x: EvaluatedFrWires,
    pub y: EvaluatedFrWires,
}

#[derive(Debug)]
pub struct EvaluatedG2Wires {
    pub x: [EvaluatedFrWires; 2],
    pub y: [EvaluatedFrWires; 2],
}

impl EvaluatedG1Wires {
    pub fn iter(&self) -> impl Iterator<Item = &EvaluatedWire> {
        self.x.iter().chain(self.y.iter())
    }
}

#[derive(Debug)]
pub struct EvaluatorInput {
    pub public: Vec<EvaluatedFrWires>,
    pub a: EvaluatedG1Wires,
    pub b: EvaluatedG2Wires,
    pub c: EvaluatedG1Wires,
    pub vk: VerifyingKey<Bn254>,
}

impl EvaluatorInput {
    pub fn new(proof: Proof, vk: VerifyingKey<Bn254>, wires: Vec<GarbledWire>) -> Self {
        // public scalars + (a.x,a.y) + (b.x,b.y as Fq2 -> 2 Fq each) + (c.x,c.y)
        // = public.len * Fr::N_BITS + 8 * Fq::N_BITS
        assert_eq!(
            wires.len(),
            (proof.public_inputs.len() * FrWire::N_BITS) + (FqWire::N_BITS * 8)
        );

        let mut wires = wires.iter();

        let public: Vec<EvaluatedFrWires> = proof
            .public_inputs
            .iter()
            .map(|f| {
                let wires_chunk = wires.by_ref().take(FrWire::N_BITS).collect::<Box<[_]>>();
                assert_eq!(wires_chunk.len(), FrWire::N_BITS);
                let bits =
                    bits_from_biguint_with_len(&BigUint::from(f.into_bigint()), FrWire::N_BITS)
                        .unwrap();
                EvaluatedFrWires(
                    bits.into_iter()
                        .zip_eq(wires_chunk)
                        .map(|(bit, gw)| EvaluatedWire::new_from_garbled(gw, bit))
                        .collect(),
                )
            })
            .collect();

        let a_m = G1Wire::as_montgomery(proof.proof.a.into_group());
        let b_m = G2Wire::as_montgomery(proof.proof.b.into_group());
        let c_m = G1Wire::as_montgomery(proof.proof.c.into_group());

        fn to_eval_fq_bits<'s>(
            f: &ark_bn254::Fq,
            wires: &mut impl Iterator<Item = &'s crate::GarbledWire>,
        ) -> EvaluatedFrWires {
            let bits = FqWire::to_bits(*f);
            EvaluatedFrWires(
                bits.into_iter()
                    .zip_eq(wires.by_ref().take(FqWire::N_BITS))
                    .map(|(bit, gw)| EvaluatedWire::new_from_garbled(gw, bit))
                    .collect(),
            )
        }

        fn to_eval_fq2_bits<'s>(
            fr2: &ark_bn254::Fq2,
            wires: &mut impl Iterator<Item = &'s crate::GarbledWire>,
        ) -> [EvaluatedFrWires; 2] {
            [
                to_eval_fq_bits(&fr2.c0, wires),
                to_eval_fq_bits(&fr2.c1, wires),
            ]
        }

        let a = EvaluatedG1Wires {
            x: to_eval_fq_bits(&a_m.x, &mut wires),
            y: to_eval_fq_bits(&a_m.y, &mut wires),
        };
        let b = EvaluatedG2Wires {
            x: to_eval_fq2_bits(&b_m.x, &mut wires),
            y: to_eval_fq2_bits(&b_m.y, &mut wires),
        };
        let c = EvaluatedG1Wires {
            x: to_eval_fq_bits(&c_m.x, &mut wires),
            y: to_eval_fq_bits(&c_m.y, &mut wires),
        };

        EvaluatorInput {
            public,
            a,
            b,
            c,
            vk,
        }
    }
}

impl CircuitInput for EvaluatorInput {
    type WireRepr = ProofWires;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        ProofWires {
            public: (0..self.public.len())
                .map(|_| FrWire::new(&mut issue))
                .collect(),
            a_x: FqWire::new(&mut issue),
            a_y: FqWire::new(&mut issue),
            b_x: Fq2Wire::new(&mut issue),
            b_y: Fq2Wire::new(&mut issue),
            c_x: FqWire::new(&mut issue),
            c_y: FqWire::new(&mut issue),
            vk: self.vk.clone(),
        }
    }
    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        let mut ids = Vec::new();
        for s in &repr.public {
            ids.extend(s.to_wires_vec());
        }
        ids.extend(repr.a_x.to_wires_vec());
        ids.extend(repr.a_y.to_wires_vec());
        ids.extend(repr.b_x.to_wires_vec());
        ids.extend(repr.b_y.to_wires_vec());
        ids.extend(repr.c_x.to_wires_vec());
        ids.extend(repr.c_y.to_wires_vec());
        ids
    }
}

impl<M: CircuitMode<WireValue = EvaluatedWire>> EncodeInput<M> for EvaluatorInput {
    fn encode(&self, repr: &ProofWires, cache: &mut M) {
        repr.public
            .iter()
            .zip_eq(self.public.iter())
            .for_each(|(wires, vars)| {
                wires
                    .iter()
                    .zip_eq(vars.iter())
                    .for_each(|(wire_id, evaluated_wire)| {
                        cache.feed_wire(*wire_id, evaluated_wire.clone());
                    });
            });

        repr.a_x
            .iter()
            .zip_eq(self.a.x.iter())
            .for_each(|(wire_id, ew)| {
                cache.feed_wire(*wire_id, ew.clone());
            });
        repr.a_y
            .iter()
            .zip_eq(self.a.y.iter())
            .for_each(|(wire_id, ew)| {
                cache.feed_wire(*wire_id, ew.clone());
            });

        repr.b_x
            .iter()
            .zip_eq(self.b.x[0].iter().chain(self.b.x[1].iter()))
            .for_each(|(wire_id, ew)| {
                cache.feed_wire(*wire_id, ew.clone());
            });
        repr.b_y
            .iter()
            .zip_eq(self.b.y[0].iter().chain(self.b.y[1].iter()))
            .for_each(|(wire_id, ew)| {
                cache.feed_wire(*wire_id, ew.clone());
            });

        repr.c_x
            .iter()
            .zip_eq(self.c.x.iter())
            .for_each(|(wire_id, ew)| {
                cache.feed_wire(*wire_id, ew.clone());
            });
        repr.c_y
            .iter()
            .zip_eq(self.c.y.iter())
            .for_each(|(wire_id, ew)| {
                cache.feed_wire(*wire_id, ew.clone());
            });
    }
}

#[derive(Debug, Clone)]
pub struct GarblerCompressedInput {
    inner: GarblerInput,
}

impl Deref for GarblerCompressedInput {
    type Target = GarblerInput;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl CircuitInput for GarblerCompressedInput {
    type WireRepr = ProofCompressedWires;

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        ProofCompressedWires {
            public: (0..self.inner.public_params_len)
                .map(|_| FrWire::new(&mut issue))
                .collect(),
            a: CompressedG1Wires::new(&mut issue),
            b: CompressedG2Wires::new(&mut issue),
            c: CompressedG1Wires::new(issue),
            vk: self.inner.vk.clone(),
        }
    }
    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        let mut ids = Vec::new();
        for s in &repr.public {
            ids.extend(s.to_wires_vec());
        }
        ids.extend(repr.a.to_wires_vec());
        ids.extend(repr.b.to_wires_vec());
        ids.extend(repr.c.to_wires_vec());
        ids
    }
}

impl<H: GateHasher, CTH: CiphertextHandler> EncodeInput<GarbleMode<H, CTH>>
    for GarblerCompressedInput
{
    fn encode(&self, repr: &ProofCompressedWires, cache: &mut GarbleMode<H, CTH>) {
        // Assign fresh labels to all input wires deterministically
        for w in &repr.public {
            for &wire in w.iter() {
                let gw = cache.issue_garbled_wire();
                cache.feed_wire(wire, gw);
            }
        }

        for &wire_id in repr.a.x_m.iter() {
            let gw = cache.issue_garbled_wire();
            cache.feed_wire(wire_id, gw);
        }
        {
            let gw = cache.issue_garbled_wire();
            cache.feed_wire(repr.a.y_flag, gw);
        }

        for &wire_id in repr.b.p.iter() {
            let gw = cache.issue_garbled_wire();
            cache.feed_wire(wire_id, gw);
        }
        {
            let gw = cache.issue_garbled_wire();
            cache.feed_wire(repr.b.y_flag, gw);
        }

        for &wire_id in repr.c.x_m.iter() {
            let gw = cache.issue_garbled_wire();
            cache.feed_wire(wire_id, gw);
        }
        {
            let gw = cache.issue_garbled_wire();
            cache.feed_wire(repr.c.y_flag, gw);
        }
    }
}

#[derive(Debug)]
pub struct EvaluatedCompressedG1Wires {
    pub x: EvaluatedFrWires,
    pub y_flag: EvaluatedWire,
}

#[derive(Debug)]
pub struct EvaluatedCompressedG2Wires {
    pub x: [EvaluatedFrWires; 2],
    pub y_flag: EvaluatedWire,
}

pub struct EvaluatorCompressedInput {
    pub public: Vec<EvaluatedFrWires>,
    pub a: EvaluatedCompressedG1Wires,
    pub b: EvaluatedCompressedG2Wires,
    pub c: EvaluatedCompressedG1Wires,
    pub vk: VerifyingKey<Bn254>,
}

impl EvaluatorCompressedInput {
    pub fn new(proof: Proof, vk: VerifyingKey<Bn254>, wires: Vec<GarbledWire>) -> Self {
        // public.len * Fr::N_BITS + (A: Fq::N_BITS + 1) + (B: 2*Fq::N_BITS + 1) + (C: Fq::N_BITS + 1)
        let expected = (proof.public_inputs.len() * FrWire::N_BITS)
            + (FqWire::N_BITS + 1)
            + (2 * FqWire::N_BITS + 1)
            + (FqWire::N_BITS + 1);
        assert_eq!(wires.len(), expected);

        let mut it = wires.iter();

        // Public inputs
        let public: Vec<EvaluatedFrWires> = proof
            .public_inputs
            .iter()
            .map(|f| {
                let wires_chunk = it.by_ref().take(FrWire::N_BITS).collect::<Box<[_]>>();
                assert_eq!(wires_chunk.len(), FrWire::N_BITS);
                let bits =
                    bits_from_biguint_with_len(&BigUint::from(f.into_bigint()), FrWire::N_BITS)
                        .unwrap();
                EvaluatedFrWires(
                    bits.into_iter()
                        .zip_eq(wires_chunk)
                        .map(|(bit, gw)| EvaluatedWire::new_from_garbled(gw, bit))
                        .collect(),
                )
            })
            .collect();

        // Compression flags computed from standard affine y
        let a_aff_std = proof.proof.a;
        let b_aff_std = proof.proof.b;
        let c_aff_std = proof.proof.c;

        let a_flag = (a_aff_std.y.square())
            .sqrt()
            .expect("y^2 must be QR")
            .eq(&a_aff_std.y);
        let b_flag = (b_aff_std.y.square())
            .sqrt()
            .expect("y^2 must be QR in Fq2")
            .eq(&b_aff_std.y);
        let c_flag = (c_aff_std.y.square())
            .sqrt()
            .expect("y^2 must be QR")
            .eq(&c_aff_std.y);

        // A.x (Montgomery) bits + flag
        let a_x_m = FqWire::as_montgomery(a_aff_std.x);
        let a_bits = FqWire::to_bits(a_x_m);
        let a_x = EvaluatedFrWires(
            a_bits
                .into_iter()
                .zip_eq(it.by_ref().take(FqWire::N_BITS))
                .map(|(bit, gw)| EvaluatedWire::new_from_garbled(gw, bit))
                .collect(),
        );
        let a_y_flag = {
            let gw = it.next().expect("a.y_flag wire");
            EvaluatedWire::new_from_garbled(gw, a_flag)
        };

        // B.x (Montgomery) bits + flag
        let b_x_m = Fq2Wire::as_montgomery(b_aff_std.x);
        let (b_c0_bits, b_c1_bits) = Fq2Wire::to_bits(b_x_m);
        let b_x0 = EvaluatedFrWires(
            b_c0_bits
                .into_iter()
                .zip_eq(it.by_ref().take(FqWire::N_BITS))
                .map(|(bit, gw)| EvaluatedWire::new_from_garbled(gw, bit))
                .collect(),
        );
        let b_x1 = EvaluatedFrWires(
            b_c1_bits
                .into_iter()
                .zip_eq(it.by_ref().take(FqWire::N_BITS))
                .map(|(bit, gw)| EvaluatedWire::new_from_garbled(gw, bit))
                .collect(),
        );
        let b_y_flag = {
            let gw = it.next().expect("b.y_flag wire");
            EvaluatedWire::new_from_garbled(gw, b_flag)
        };

        // C.x (Montgomery) bits + flag
        let c_x_m = FqWire::as_montgomery(c_aff_std.x);
        let c_bits = FqWire::to_bits(c_x_m);
        let c_x = EvaluatedFrWires(
            c_bits
                .into_iter()
                .zip_eq(it.by_ref().take(FqWire::N_BITS))
                .map(|(bit, gw)| EvaluatedWire::new_from_garbled(gw, bit))
                .collect(),
        );
        let c_y_flag = {
            let gw = it.next().expect("c.y_flag wire");
            EvaluatedWire::new_from_garbled(gw, c_flag)
        };

        EvaluatorCompressedInput {
            public,
            a: EvaluatedCompressedG1Wires {
                x: a_x,
                y_flag: a_y_flag,
            },
            b: EvaluatedCompressedG2Wires {
                x: [b_x0, b_x1],
                y_flag: b_y_flag,
            },
            c: EvaluatedCompressedG1Wires {
                x: c_x,
                y_flag: c_y_flag,
            },
            vk,
        }
    }
}

impl CircuitInput for EvaluatorCompressedInput {
    type WireRepr = ProofCompressedWires;

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        ProofCompressedWires {
            public: (0..self.public.len())
                .map(|_| FrWire::new(&mut issue))
                .collect(),
            a: CompressedG1Wires::new(&mut issue),
            b: CompressedG2Wires::new(&mut issue),
            c: CompressedG1Wires::new(issue),
            vk: self.vk.clone(),
        }
    }
    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        let mut ids = Vec::new();
        for s in &repr.public {
            ids.extend(s.to_wires_vec());
        }
        ids.extend(repr.a.to_wires_vec());
        ids.extend(repr.b.to_wires_vec());
        ids.extend(repr.c.to_wires_vec());
        ids
    }
}

impl<M: CircuitMode<WireValue = EvaluatedWire>> EncodeInput<M> for EvaluatorCompressedInput {
    fn encode(&self, repr: &ProofCompressedWires, cache: &mut M) {
        // Public inputs
        repr.public
            .iter()
            .zip_eq(self.public.iter())
            .for_each(|(wires, vals)| {
                wires
                    .iter()
                    .zip_eq(vals.iter())
                    .for_each(|(wire_id, ew)| cache.feed_wire(*wire_id, ew.clone()));
            });

        // A.x bits and y_flag
        repr.a
            .x_m
            .iter()
            .zip_eq(self.a.x.iter())
            .for_each(|(wire_id, ew)| cache.feed_wire(*wire_id, ew.clone()));
        cache.feed_wire(repr.a.y_flag, self.a.y_flag.clone());

        // B.x bits (c0 || c1) and y_flag
        repr.b
            .p
            .iter()
            .zip_eq(self.b.x[0].iter().chain(self.b.x[1].iter()))
            .for_each(|(wire_id, ew)| cache.feed_wire(*wire_id, ew.clone()));
        cache.feed_wire(repr.b.y_flag, self.b.y_flag.clone());

        // C.x bits and y_flag
        repr.c
            .x_m
            .iter()
            .zip_eq(self.c.x.iter())
            .for_each(|(wire_id, ew)| cache.feed_wire(*wire_id, ew.clone()));
        cache.feed_wire(repr.c.y_flag, self.c.y_flag.clone());
    }
}
