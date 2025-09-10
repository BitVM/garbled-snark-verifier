//! Groth16 proof input wiring helpers for the streaming verifier.
//!
//! Ordering and domains
//! - All field encodings use Montgomery domain to match gadget operations.
//! - When flattening inputs into wires, the bit order is:
//!   1) public scalars `Fr` (each as `Fr::N_BITS` bits), in given slice order
//!   2) `A.x` then `A.y` (each `Fq::N_BITS`)
//!   3) `B.x` then `B.y` as `Fq2` with limb order `c0` then `c1` (each limb `Fq::N_BITS`)
//!   4) `C.x` then `C.y`
//! - Projective z-coordinates are fixed to Montgomery ONE (for G1) and (1,0) in Fq2 for G2.
//!
//! Wire count formula: `public.len * Fr::N_BITS + 8 * Fq::N_BITS`.
//! The constructors/encoders assume this exact layout.

use ark_ff::{AdditiveGroup, Field, PrimeField};
use itertools::Itertools;
use num_bigint::BigUint;

// Re-import gadgets Groth16 exec input types here for consistent namespace access
pub use crate::gadgets::groth16::{Groth16ExecInput, Groth16ExecInputWires};
use crate::{
    circuit::{
        CircuitInput,
        streaming::{CircuitMode, EncodeInput, WiresObject},
    },
    *,
};

pub struct Groth16ProofInputs {
    pub public: Vec<ark_bn254::Fr>,
    pub a: ark_bn254::G1Projective,
    pub b: ark_bn254::G2Projective,
    pub c: ark_bn254::G1Projective,
}

pub struct Groth16ProofWires {
    pub public: Vec<FrWire>,
    pub a_x: FqWire,
    pub a_y: FqWire,
    pub b_x: Fq2Wire,
    pub b_y: Fq2Wire,
    pub c_x: FqWire,
    pub c_y: FqWire,
}

impl CircuitInput for Groth16ProofInputs {
    type WireRepr = Groth16ProofWires;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        Groth16ProofWires {
            public: self
                .public
                .iter()
                .map(|_| FrWire::new(&mut issue))
                .collect(),
            a_x: FqWire::new(&mut issue),
            a_y: FqWire::new(&mut issue),
            b_x: Fq2Wire::new(&mut issue),
            b_y: Fq2Wire::new(&mut issue),
            c_x: FqWire::new(&mut issue),
            c_y: FqWire::new(&mut issue),
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

// For garbling, we need to generate garbled wire labels instead of boolean values
#[derive(Debug, Clone)]
pub struct GarbledInputs {
    pub public_params_len: usize,
}

impl CircuitInput for GarbledInputs {
    type WireRepr = Groth16ProofWires;

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        Groth16ProofWires {
            public: (0..self.public_params_len)
                .map(|_| FrWire::new(&mut issue))
                .collect(),
            a_x: FqWire::new(&mut issue),
            a_y: FqWire::new(&mut issue),
            b_x: Fq2Wire::new(&mut issue),
            b_y: Fq2Wire::new(&mut issue),
            c_x: FqWire::new(&mut issue),
            c_y: FqWire::new(&mut issue),
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

impl<H: crate::core::gate::garbling::GateHasher>
    EncodeInput<crate::circuit::streaming::modes::GarbleMode<H>> for GarbledInputs
{
    fn encode(
        &self,
        repr: &Groth16ProofWires,
        cache: &mut crate::circuit::streaming::modes::GarbleMode<H>,
    ) {
        // Encode public scalars
        for w in &repr.public {
            for &wire in w.iter() {
                let gw = cache.issue_garbled_wire();
                cache.feed_wire(wire, gw);
            }
        }

        // Encode G1 points
        for &wire_id in repr.a_x.iter().chain(repr.a_y.iter()) {
            let gw = cache.issue_garbled_wire();
            cache.feed_wire(wire_id, gw);
        }

        // Encode G2 points
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

/// Bit-vector wrapper for field element wires evaluated against garbled labels.
///
/// Provides a slice view via Deref so it can be used like `&[EvaluatedWire]`.
#[derive(Debug, Clone)]
pub struct EvaluatedFrWires(pub Vec<EvaluatedWire>);

impl ::core::ops::Deref for EvaluatedFrWires {
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
        let Self { x, y } = self;
        x.iter().chain(y.iter())
    }
}

#[derive(Debug)]
pub struct Groth16EvaluatorInputs {
    pub public: Vec<EvaluatedFrWires>,
    pub a: EvaluatedG1Wires,
    pub b: EvaluatedG2Wires,
    pub c: EvaluatedG1Wires,
}
impl Groth16EvaluatorInputs {
    // Return true wire, false wire values and inputs, correctly interpret wires`
    pub fn new(
        a: ark_bn254::G1Projective,
        b: ark_bn254::G2Projective,
        c: ark_bn254::G1Projective,
        public_params: Vec<ark_bn254::Fr>,
        wires: Vec<GarbledWire>,
    ) -> Self {
        // public scalars + (a.x,a.y) + (b.x,b.y as Fq2 -> 2 Fq each) + (c.x,c.y)
        // = public.len * Fr::N_BITS + 8 * Fq::N_BITS
        assert_eq!(
            wires.len(),
            (public_params.len() * FrWire::N_BITS) + (FqWire::N_BITS * 8)
        );

        let mut wires = wires.iter();

        let public: Vec<EvaluatedFrWires> = public_params
            .iter()
            .map(|f| {
                let wires = wires.by_ref().take(FrWire::N_BITS).collect::<Box<[_]>>();
                assert_eq!(wires.len(), FrWire::N_BITS);

                let bits =
                    bits_from_biguint_with_len(&BigUint::from(f.into_bigint()), FrWire::N_BITS)
                        .unwrap();

                assert_eq!(bits.len(), FrWire::N_BITS);

                EvaluatedFrWires(
                    bits.into_iter()
                        .zip_eq(wires)
                        .map(|(bit, gw)| EvaluatedWire::new_from_garbled(gw, bit))
                        .collect(),
                )
            })
            .collect();

        // Use Montgomery form for G1 inputs to match Execute encoding
        let a_m = G1Wire::as_montgomery(a);
        let b_m = G2Wire::as_montgomery(b);
        let c_m = G1Wire::as_montgomery(c);

        // Convert an Fq element to evaluated bit wires using provided garbled wires iterator
        fn to_eval_fq_bits<'s>(
            f: &ark_bn254::Fq,
            wires: &mut impl Iterator<Item = &'s GarbledWire>,
        ) -> EvaluatedFrWires {
            let bits = FqWire::to_bits(*f);
            EvaluatedFrWires(
                bits.into_iter()
                    .zip_eq(wires.by_ref().take(FqWire::N_BITS))
                    .map(|(bit, gw)| EvaluatedWire::new_from_garbled(gw, bit))
                    .collect(),
            )
        }

        // Convert an Fq2 element to evaluated bit wires (c0 then c1 ordering)
        fn to_eval_fq2_bits<'s>(
            fr2: &ark_bn254::Fq2,
            wires: &mut impl Iterator<Item = &'s GarbledWire>,
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

        Groth16EvaluatorInputs { public, a, b, c }
    }
}

impl CircuitInput for Groth16EvaluatorInputs {
    type WireRepr = Groth16ProofWires;

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        Groth16ProofWires {
            public: (0..self.public.len())
                .map(|_| FrWire::new(&mut issue))
                .collect(),
            a_x: FqWire::new(&mut issue),
            a_y: FqWire::new(&mut issue),
            b_x: Fq2Wire::new(&mut issue),
            b_y: Fq2Wire::new(&mut issue),
            c_x: FqWire::new(&mut issue),
            c_y: FqWire::new(&mut issue),
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

impl<M: CircuitMode<WireValue = EvaluatedWire>> EncodeInput<M> for Groth16EvaluatorInputs {
    fn encode(&self, repr: &Groth16ProofWires, cache: &mut M) {
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

        // A.x
        repr.a_x
            .iter()
            .zip_eq(self.a.x.iter())
            .for_each(|(wire_id, evaluated_wire)| {
                cache.feed_wire(*wire_id, evaluated_wire.clone());
            });

        // A.y
        repr.a_y
            .iter()
            .zip_eq(self.a.y.iter())
            .for_each(|(wire_id, evaluated_wire)| {
                cache.feed_wire(*wire_id, evaluated_wire.clone());
            });

        // B.x (Fq2 -> c0 then c1)
        repr.b_x
            .iter()
            .zip_eq(self.b.x[0].iter().chain(self.b.x[1].iter()))
            .for_each(|(wire_id, evaluated_wire)| {
                cache.feed_wire(*wire_id, evaluated_wire.clone());
            });

        // B.y (Fq2 -> c0 then c1)
        repr.b_y
            .iter()
            .zip_eq(self.b.y[0].iter().chain(self.b.y[1].iter()))
            .for_each(|(wire_id, evaluated_wire)| {
                cache.feed_wire(*wire_id, evaluated_wire.clone());
            });

        // C.x
        repr.c_x
            .iter()
            .zip_eq(self.c.x.iter())
            .for_each(|(wire_id, evaluated_wire)| {
                cache.feed_wire(*wire_id, evaluated_wire.clone());
            });

        // C.y
        repr.c_y
            .iter()
            .zip_eq(self.c.y.iter())
            .for_each(|(wire_id, evaluated_wire)| {
                cache.feed_wire(*wire_id, evaluated_wire.clone());
            });
    }
}

pub fn groth16_proof_verify<C: CircuitContext>(
    ctx: &mut C,
    wires: &Groth16ProofWires,
    vk: &ark_groth16::VerifyingKey<ark_bn254::Bn254>,
) -> Vec<WireId> {
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
        // In Fq2, ONE is (c0=1, c1=0). Use Montgomery representation.
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

    let is_ok = groth16_verify(ctx, &wires.public, &a, &b, &c, vk);

    vec![is_ok]
}
