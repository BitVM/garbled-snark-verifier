use std::{cmp::min, collections::HashMap, iter::zip};

use ark_ff::{AdditiveGroup, Field, UniformRand, Zero};
use circuit_component_macro::component;
use digest::typenum::bit;
use num_bigint::BigUint;
use rand::Rng;

use crate::{
    CircuitContext, WireId,
    gadgets::{
        bigint::{self, BigIntWires, Error},
        bn254::{fp254impl::Fp254Impl, fq::Fq, fr::Fr},
    },
};

#[derive(Clone)]
pub struct G1Projective {
    pub x: Fq,
    pub y: Fq,
    pub z: Fq,
}

impl G1Projective {
    pub const N_BITS: usize = 3 * Fq::N_BITS;

    pub fn new<C: CircuitContext>(circuit: &mut C) -> Self {
        Self {
            x: Fq::new(circuit),
            y: Fq::new(circuit),
            z: Fq::new(circuit),
        }
    }

    pub fn new_constant(u: &ark_bn254::G1Projective) -> Result<Self, Error> {
        Ok(Self {
            x: Fq::new_constant(&u.x).unwrap(),
            y: Fq::new_constant(&u.y).unwrap(),
            z: Fq::new_constant(&u.z).unwrap(),
        })
    }

    pub fn from_bits_unchecked(bits: Vec<bool>) -> ark_bn254::G1Projective {
        let bits1 = &bits[0..Fq::N_BITS].to_vec();
        let bits2 = &bits[Fq::N_BITS..Fq::N_BITS * 2].to_vec();
        let bits3 = &bits[Fq::N_BITS * 2..Fq::N_BITS * 3].to_vec();
        ark_bn254::G1Projective {
            x: Fq::from_bits(bits1.clone()),
            y: Fq::from_bits(bits2.clone()),
            z: Fq::from_bits(bits3.clone()),
        }
    }


    pub fn to_bitmask(&self, get_val: impl Fn(WireId) -> bool) -> String {
        let to_char = |wire_id: &WireId| if (get_val)(*wire_id) { '1' } else { '0' };
        let x = self.x.iter().map(to_char).collect::<String>();
        let y = self.y.iter().map(to_char).collect::<String>();
        let z = self.z.iter().map(to_char).collect::<String>();

        format!("x: {x}, y: {y}, z: {z}")
    }

    pub fn to_bitvec(&self, get_val: impl Fn(WireId) -> bool) -> Vec<bool> {
        let to_char = |wire_id: &WireId| (get_val)(*wire_id);
        let x = self.x.iter().map(to_char).collect::<Vec<bool>>();
        let y = self.y.iter().map(to_char).collect::<Vec<bool>>();
        let z = self.z.iter().map(to_char).collect::<Vec<bool>>();

        let mut v = Vec::new();
        v.extend(x);
        v.extend(y);
        v.extend(z);

        v
    }

    pub fn as_montgomery(p: ark_bn254::G1Projective) -> ark_bn254::G1Projective {
        ark_bn254::G1Projective {
            x: Fq::as_montgomery(p.x),
            y: Fq::as_montgomery(p.y),
            z: Fq::as_montgomery(p.z),
        }
    }

    pub fn from_montgomery(p: ark_bn254::G1Projective) -> ark_bn254::G1Projective {
        ark_bn254::G1Projective {
            x: Fq::from_montgomery(p.x),
            y: Fq::from_montgomery(p.y),
            z: Fq::from_montgomery(p.z),
        }
    }

    pub fn get_wire_bits_fn(
        wires: &G1Projective,
        value: &ark_bn254::G1Projective,
    ) -> Result<impl Fn(WireId) -> Option<bool> + use<>, crate::gadgets::bigint::Error> {
        let G1Projective {
            x: wires_x,
            y: wirex_y,
            z: wires_z,
        } = wires;
        let x = Fq::to_bits(value.x);
        let y = Fq::to_bits(value.y);
        let z = Fq::to_bits(value.z);

        let bits = wires_x
            .iter()
            .zip(x.iter())
            .chain(wirex_y.iter().zip(y.iter()))
            .chain(wires_z.iter().zip(z.iter()))
            .map(|(wire_id, value)| (*wire_id, *value))
            .collect::<HashMap<WireId, bool>>();

        Ok(move |wire_id: WireId| bits.get(&wire_id).copied())
    }

    pub fn random(rng: &mut impl Rng) -> ark_bn254::G1Projective {
        ark_bn254::G1Projective::default() * Fr::random(rng)
    }
}

impl G1Projective {
    // http://koclab.cs.ucsb.edu/teaching/ccs130h/2018/09projective.pdf
    #[component]
    pub fn add_montgomery<C: CircuitContext>(
        circuit: &mut C,
        p: &G1Projective,
        q: &G1Projective,
    ) -> G1Projective {
        assert_eq!(p.x.len(), Fq::N_BITS);
        assert_eq!(p.y.len(), Fq::N_BITS);
        assert_eq!(p.z.len(), Fq::N_BITS);

        assert_eq!(q.x.len(), Fq::N_BITS);
        assert_eq!(q.y.len(), Fq::N_BITS);
        assert_eq!(q.z.len(), Fq::N_BITS);

        let G1Projective {
            x: x1,
            y: y1,
            z: z1,
        } = p;
        let G1Projective {
            x: x2,
            y: y2,
            z: z2,
        } = q;

        let z1s = Fq::square_montgomery(circuit, z1);
        let z2s = Fq::square_montgomery(circuit, z2);
        let z1c = Fq::mul_montgomery(circuit, &z1s, z1);
        let z2c = Fq::mul_montgomery(circuit, &z2s, z2);
        let u1 = Fq::mul_montgomery(circuit, x1, &z2s);
        let u2 = Fq::mul_montgomery(circuit, x2, &z1s);
        let s1 = Fq::mul_montgomery(circuit, y1, &z2c);
        let s2 = Fq::mul_montgomery(circuit, y2, &z1c);
        let r = Fq::sub(circuit, &s1, &s2);
        let h = Fq::sub(circuit, &u1, &u2);
        let h2 = Fq::square_montgomery(circuit, &h);
        let g = Fq::mul_montgomery(circuit, &h, &h2);
        let v = Fq::mul_montgomery(circuit, &u1, &h2);
        let r2 = Fq::square_montgomery(circuit, &r);
        let r2g = Fq::add(circuit, &r2, &g);
        let vd = Fq::double(circuit, &v);
        let x3 = Fq::sub(circuit, &r2g, &vd);
        let vx3 = Fq::sub(circuit, &v, &x3);
        let w = Fq::mul_montgomery(circuit, &r, &vx3);
        let s1g = Fq::mul_montgomery(circuit, &s1, &g);
        let y3 = Fq::sub(circuit, &w, &s1g);
        let z1z2 = Fq::mul_montgomery(circuit, z1, z2);
        let z3 = Fq::mul_montgomery(circuit, &z1z2, &h);

        let z1_0 = Fq::equal_constant(circuit, z1, &ark_bn254::Fq::zero());
        let z2_0 = Fq::equal_constant(circuit, z2, &ark_bn254::Fq::zero());

        let zero = Fq::new_constant(&ark_bn254::Fq::zero()).unwrap();

        let s = [z1_0, z2_0];

        let x = Fq::multiplexer(
            circuit,
            &[x3.clone(), x2.clone(), x1.clone(), zero.clone()],
            &s,
            2,
        );
        let y = Fq::multiplexer(
            circuit,
            &[y3.clone(), y2.clone(), y1.clone(), zero.clone()],
            &s,
            2,
        );
        let z = Fq::multiplexer(
            circuit,
            &[z3.clone(), z2.clone(), z1.clone(), zero.clone()],
            &s,
            2,
        );

        G1Projective { x, y, z }
    }

    /*
    pub fn add_evaluate_montgomery(p: Wires, q: Wires) -> (Wires, GateCount) {
        let circuit = Self::add_montgomery(p, q);
        let n = circuit.gate_counts();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        (circuit.0, n)
    }
    */

    pub fn double_montgomery<C: CircuitContext>(circuit: &mut C, p: &G1Projective) -> G1Projective {
        assert_eq!(p.x.len(), Fq::N_BITS);
        assert_eq!(p.y.len(), Fq::N_BITS);
        assert_eq!(p.z.len(), Fq::N_BITS);

        let G1Projective {
            x: x1,
            y: y1,
            z: z1,
        } = p;

        let x2 = Fq::square_montgomery(circuit, x1);
        let y2 = Fq::square_montgomery(circuit, y1);
        let m = Fq::triple(circuit, &x2);
        let t = Fq::square_montgomery(circuit, &y2);
        let xy2 = Fq::mul_montgomery(circuit, x1, &y2);
        let xy2d = Fq::double(circuit, &xy2);
        let s = Fq::double(circuit, &xy2d);
        let m2 = Fq::square_montgomery(circuit, &m);
        let sd = Fq::double(circuit, &s);
        let xr = Fq::sub(circuit, &m2, &sd);
        let sxr = Fq::sub(circuit, &s, &xr);
        let msxr = Fq::mul_montgomery(circuit, &m, &sxr);
        let td = Fq::double(circuit, &t);
        let tdd = Fq::double(circuit, &td);
        let tddd = Fq::double(circuit, &tdd);
        let yr = Fq::sub(circuit, &msxr, &tddd);
        let yz = Fq::mul_montgomery(circuit, y1, z1);
        let zr = Fq::double(circuit, &yz);

        let z_0 = Fq::equal_constant(circuit, z1, &ark_bn254::Fq::zero()); //equal _zero _function ?
        let zero = Fq::new_constant(&ark_bn254::Fq::zero()).unwrap();
        // let z = Fq::multiplexer(circuit, &[&x3, x2, x1, &zero], &s, 1);
        let z = Fq::multiplexer(circuit, &[zr.clone(), zero.clone()], &[z_0], 1);

        G1Projective { x: xr, y: yr, z }
    }

    pub fn multiplexer<C: CircuitContext>(
        circuit: &mut C,
        a: &[G1Projective],
        s: Vec<WireId>,
        w: usize,
    ) -> G1Projective {
        let n = 2_usize.pow(w.try_into().unwrap());
        assert_eq!(a.len(), n);
        assert_eq!(s.len(), w);

        G1Projective {
            x: Fq::multiplexer(
                circuit,
                &a.iter().map(|p| p.x.clone()).collect::<Vec<_>>(),
                &s,
                w,
            ),
            y: Fq::multiplexer(
                circuit,
                &a.iter().map(|p| p.y.clone()).collect::<Vec<_>>(),
                &s,
                w,
            ),
            z: Fq::multiplexer(
                circuit,
                &a.iter().map(|p| p.z.clone()).collect::<Vec<_>>(),
                &s,
                w,
            ),
        }
    }

    // pub fn multiplexer_evaluate(a: Vec<Wires>, s: Wires, w: usize) -> (Wires, GateCount) {
    //     let circuit = Self::multiplexer(a, s, w);
    //     let n = circuit.gate_counts();
    //     for mut gate in circuit.1 {
    //         gate.evaluate();
    //     }
    //     (circuit.0, n)
    // }
    // pub fn scalar_mul_by_constant_base_evaluate_montgomery<const W: usize>(
    //     s: Wires,
    //     base: ark_bn254::G1Projective,
    // ) -> (Wires, GateCount) {
    //     assert_eq!(s.len(), Fr::N_BITS);
    //     let mut gate_count = GateCount::zero();
    //     let n = 2_usize.pow(W as u32);

    //     let mut bases = Vec::new();
    //     let mut p = ark_bn254::G1Projective::default();

    //     for _ in 0..n {
    //         bases.push(p);
    //         p += base;
    //     }

    //     let mut bases_wires = bases
    //         .iter()
    //         .map(|p| G1Projective::wires_set_montgomery(*p))
    //         .collect::<Vec<Wires>>();

    //     let mut to_be_added = Vec::new();

    //     let mut index = 0;
    //     while index < Fr::N_BITS {
    //         let w = min(W, Fr::N_BITS - index);
    //         let m = 2_usize.pow(w as u32);
    //         let selector = s[index..(index + w)].to_vec();
    //         let (result, gc) =
    //             Self::multiplexer_evaluate(bases_wires.clone()[0..m].to_vec(), selector, w);
    //         gate_count += gc;
    //         to_be_added.push(result);
    //         index += W;
    //         let mut new_bases = Vec::new();
    //         for b in bases {
    //             let mut new_b = b;
    //             for _ in 0..w {
    //                 new_b = new_b + new_b;
    //             }
    //             new_bases.push(new_b);
    //         }
    //         bases = new_bases;
    //         bases_wires = bases
    //             .iter()
    //             .map(|p| G1Projective::wires_set_montgomery(*p))
    //             .collect::<Vec<Wires>>();
    //     }

    //     let mut acc = to_be_added[0].clone();
    //     for add in to_be_added.iter().skip(1) {
    //         let (new_acc, gc) = Self::add_evaluate_montgomery(acc, add.clone());
    //         gate_count += gc;
    //         acc = new_acc;
    //     }

    //     (acc, gate_count)
    // }

    pub fn scalar_mul_by_constant_base_montgomery<const W: usize, C: CircuitContext>(
        circuit: &mut C,
        s: &Fr,
        base: &ark_bn254::G1Projective,
    ) -> G1Projective {
        assert_eq!(s.len(), Fr::N_BITS);
        let n = 2_usize.pow(W as u32);

        let mut bases = Vec::new();
        let mut p = ark_bn254::G1Projective::default();

        for _ in 0..n {
            bases.push(p);
            p += base;
        }

        let mut bases_wires = bases
            .iter()
            .map(|p| G1Projective::new_constant(p).unwrap())
            .collect::<Vec<_>>();

        let mut to_be_added = Vec::new();

        let mut index = 0;
        while index < Fr::N_BITS {
            let w = min(W, Fr::N_BITS - index);
            let m = 2_usize.pow(w as u32);
            let selector = s.iter().skip(index).take(w).copied().collect();
            let result = Self::multiplexer(circuit, &bases_wires[0..m], selector, w);
            to_be_added.push(result);
            index += W;
            let mut new_bases = Vec::new();
            for b in bases {
                let mut new_b = b;
                for _ in 0..w {
                    new_b = new_b + new_b;
                }
                new_bases.push(new_b);
            }
            bases = new_bases;
            bases_wires = bases
                .iter()
                .map(|p| G1Projective::new_constant(p).unwrap())
                .collect::<Vec<_>>();
        }

        let mut acc = to_be_added[0].clone();
        for add in to_be_added.iter().skip(1) {
            let new_acc = Self::add_montgomery(circuit, &acc, add);
            acc = new_acc;
        }

        acc
    }

    // pub fn msm_with_constant_bases_evaluate_montgomery<const W: usize>(
    //     scalars: Vec<Wires>,
    //     bases: Vec<ark_bn254::G1Projective>,
    // ) -> (Wires, GateCount) {
    //     assert_eq!(scalars.len(), bases.len());
    //     let mut gate_count = GateCount::zero();
    //     let mut to_be_added = Vec::new();
    //     for (s, base) in zip(scalars, bases) {
    //         let (result, gc) =
    //             Self::scalar_mul_by_constant_base_evaluate_montgomery::<W>(s, base);
    //         to_be_added.push(result);
    //         gate_count += gc;
    //     }

    //     let mut acc = to_be_added[0].clone();
    //     for add in to_be_added.iter().skip(1) {
    //         let (new_acc, gc) = Self::add_evaluate_montgomery(acc, add.clone());
    //         gate_count += gc;
    //         acc = new_acc;
    //     }

    //     (acc, gate_count)
    // }

    pub fn msm_with_constant_bases_montgomery<const W: usize, C: CircuitContext>(
        circuit: &mut C,
        scalars: &Vec<Fr>,
        bases: &Vec<ark_bn254::G1Projective>,
    ) -> G1Projective {
        assert_eq!(scalars.len(), bases.len());
        let mut to_be_added = Vec::new();
        for (s, base) in zip(scalars, bases) {
            let result = Self::scalar_mul_by_constant_base_montgomery::<W, _>(circuit, s, base);
            to_be_added.push(result);
        }

        let mut acc = to_be_added[0].clone();
        for add in to_be_added.iter().skip(1) {
            let new_acc = Self::add_montgomery(circuit, &acc, add);
            acc = new_acc;
        }
        acc
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::OnceCell, collections::HashMap};

    use ark_ec::{CurveGroup, VariableBaseMSM};
    use ark_ff::BigInt;
    use rand::SeedableRng;

    use super::*;
    use crate::{CircuitContext, circuit::streaming::{CircuitBuilder, Execute, modes::CircuitMode}, test_utils::trng};

    fn rnd() -> ark_bn254::G1Projective {
        use ark_ec::PrimeGroup;
        let g1 = ark_bn254::G1Projective::generator();
        g1.mul_bigint(<rand::rngs::StdRng as SeedableRng>::seed_from_u64(1).r#gen::<[u64; 4]>())
    }

    #[test]
    fn test_g1p_add_montgomery() {
        // Generate random G1 points
        let a = G1Projective::random(&mut trng());
        let b = G1Projective::random(&mut trng());
        let c = a + b;

        // Convert to Montgomery form
        let a_mont = G1Projective::as_montgomery(a);
        let b_mont = G1Projective::as_montgomery(b);
        let c_mont = G1Projective::as_montgomery(c);

        // Define input structure
        struct TwoG1Inputs {
            a: ark_bn254::G1Projective,
            b: ark_bn254::G1Projective,
        }
        struct TwoG1InputsWire {
            a: G1Projective,
            b: G1Projective,
        }
        impl crate::circuit::streaming::CircuitInput for TwoG1Inputs {
            type WireRepr = TwoG1InputsWire;
            fn allocate<C: CircuitContext>(&self, ctx: &mut C) -> Self::WireRepr {
                TwoG1InputsWire {
                    a: G1Projective::new(ctx),
                    b: G1Projective::new(ctx),
                }
            }
            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                let mut wires = Vec::new();
                wires.extend(repr.a.x.iter());
                wires.extend(repr.a.y.iter());
                wires.extend(repr.a.z.iter());
                wires.extend(repr.b.x.iter());
                wires.extend(repr.b.y.iter());
                wires.extend(repr.b.z.iter());
                wires
            }
        }
        impl crate::circuit::streaming::EncodeInput<Execute> for TwoG1Inputs {
            fn encode(self, repr: &TwoG1InputsWire, cache: &mut Execute) {
                let a_fn = G1Projective::get_wire_bits_fn(&repr.a, &self.a).unwrap();
                let b_fn = G1Projective::get_wire_bits_fn(&repr.b, &self.b).unwrap();
                for &wire_id in repr.a.x.iter().chain(repr.a.y.iter()).chain(repr.a.z.iter()) {
                    if let Some(bit) = a_fn(wire_id) {
                        cache.feed_wire(wire_id, bit);
                    }
                }
                for &wire_id in repr.b.x.iter().chain(repr.b.y.iter()).chain(repr.b.z.iter()) {
                    if let Some(bit) = b_fn(wire_id) {
                        cache.feed_wire(wire_id, bit);
                    }
                }
            }
        }

        let inputs = TwoG1Inputs { a: a_mont, b: b_mont };
        let result = CircuitBuilder::<Execute>::streaming_execute(inputs, |root, inputs_wire| {
            let result_wires = G1Projective::add_montgomery(root, &inputs_wire.a, &inputs_wire.b);
            let mut output_ids = Vec::new();
            output_ids.extend(result_wires.x.iter());
            output_ids.extend(result_wires.y.iter());
            output_ids.extend(result_wires.z.iter());
            output_ids
        });

        let actual_result = G1Projective::from_bits_unchecked(
            result.output_wires.clone()
        );
        assert_eq!(actual_result, c_mont);
    }

    #[test]
    fn test_g1p_double_montgomery() {
        // Generate random G1 points
        let a = rnd();
        let c = a + a;

        // Convert to Montgomery form
        let a_mont = G1Projective::as_montgomery(a);
        let c_mont = G1Projective::as_montgomery(c);

        // Define input structure
        struct OneG1Input {
            a: ark_bn254::G1Projective,
        }
        struct OneG1InputWire {
            a: G1Projective,
        }
        impl crate::circuit::streaming::CircuitInput for OneG1Input {
            type WireRepr = OneG1InputWire;
            fn allocate<C: CircuitContext>(&self, ctx: &mut C) -> Self::WireRepr {
                OneG1InputWire {
                    a: G1Projective::new(ctx),
                }
            }
            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                let mut wires = Vec::new();
                wires.extend(repr.a.x.iter());
                wires.extend(repr.a.y.iter());
                wires.extend(repr.a.z.iter());
                wires
            }
        }
        impl crate::circuit::streaming::EncodeInput<Execute> for OneG1Input {
            fn encode(self, repr: &OneG1InputWire, cache: &mut Execute) {
                let a_fn = G1Projective::get_wire_bits_fn(&repr.a, &self.a).unwrap();
                for &wire_id in repr.a.x.iter().chain(repr.a.y.iter()).chain(repr.a.z.iter()) {
                    if let Some(bit) = a_fn(wire_id) {
                        cache.feed_wire(wire_id, bit);
                    }
                }
            }
        }

        let inputs = OneG1Input { a: a_mont };
        let result = CircuitBuilder::<Execute>::streaming_execute(inputs, |root, inputs_wire| {
            let result_wires = G1Projective::double_montgomery(root, &inputs_wire.a);
            let mut output_ids = Vec::new();
            output_ids.extend(result_wires.x.iter());
            output_ids.extend(result_wires.y.iter());
            output_ids.extend(result_wires.z.iter());
            output_ids
        });

        let actual_result = G1Projective::from_bits_unchecked(
            result.output_wires.clone()
        );
        assert_eq!(actual_result, c_mont);
    }

    // #[test]
    // fn test_g1_projective_to_affine_montgomery() {
    //     let p_projective = G1Projective::random().double();
    //     assert_ne!(p_projective.z, ark_bn254::Fq::ONE);
    //     let p_affine = p_projective.into_affine();
    //     let circuit =
    //         projective_to_affine_montgomery(G1Projective::wires_set_montgomery(p_projective));
    //     circuit.gate_counts().print();
    //     for mut gate in circuit.1 {
    //         gate.evaluate();
    //     }
    //     let p_affine2 = G1Affine::from_montgomery_wires_unchecked(circuit.0);
    //     assert_eq!(p_affine, p_affine2);
    // }

    #[test]
    fn test_g1p_multiplexer() {
        let w = 2;
        let n = 2_usize.pow(w as u32);
        let a_val = (0..n)
            .map(|_| G1Projective::as_montgomery(G1Projective::random(&mut trng())))
            .collect::<Vec<_>>();
        let s_val = (0..w).map(|_| trng().r#gen()).collect::<Vec<_>>();

        let mut u = 0;
        for i in s_val.iter().rev() {
            u = u + u + if *i { 1 } else { 0 };
        }
        let expected = a_val[u];

        // Define input structure
        struct MultiplexerInputs {
            a: Vec<ark_bn254::G1Projective>,
            s: Vec<bool>,
        }
        struct MultiplexerInputsWire {
            a: Vec<G1Projective>,
            s: Vec<WireId>,
        }
        impl crate::circuit::streaming::CircuitInput for MultiplexerInputs {
            type WireRepr = MultiplexerInputsWire;
            fn allocate<C: CircuitContext>(&self, ctx: &mut C) -> Self::WireRepr {
                MultiplexerInputsWire {
                    a: (0..self.a.len()).map(|_| G1Projective::new(ctx)).collect(),
                    s: (0..self.s.len()).map(|_| ctx.issue_wire()).collect(),
                }
            }
            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                let mut wires = Vec::new();
                for g1 in &repr.a {
                    wires.extend(g1.x.iter());
                    wires.extend(g1.y.iter());
                    wires.extend(g1.z.iter());
                }
                wires.extend(&repr.s);
                wires
            }
        }
        impl crate::circuit::streaming::EncodeInput<Execute> for MultiplexerInputs {
            fn encode(self, repr: &MultiplexerInputsWire, cache: &mut Execute) {
                for (g1_wire, g1_val) in repr.a.iter().zip(self.a.iter()) {
                    let g1_fn = G1Projective::get_wire_bits_fn(g1_wire, g1_val).unwrap();
                    for &wire_id in g1_wire.x.iter().chain(g1_wire.y.iter()).chain(g1_wire.z.iter()) {
                        if let Some(bit) = g1_fn(wire_id) {
                            cache.feed_wire(wire_id, bit);
                        }
                    }
                }
                for (&wire_id, &bit) in repr.s.iter().zip(self.s.iter()) {
                    cache.feed_wire(wire_id, bit);
                }
            }
        }

        let inputs = MultiplexerInputs { a: a_val, s: s_val };
        let result = CircuitBuilder::<Execute>::streaming_execute(inputs, |root, inputs_wire| {
            let result_wires = G1Projective::multiplexer(root, &inputs_wire.a, inputs_wire.s.clone(), w);
            let mut output_ids = Vec::new();
            output_ids.extend(result_wires.x.iter());
            output_ids.extend(result_wires.y.iter());
            output_ids.extend(result_wires.z.iter());
            output_ids
        });

        let actual_result = G1Projective::from_bits_unchecked(
            result.output_wires.clone()
        );
        assert_eq!(actual_result, expected);
    }

    #[test]
    fn test_g1p_scalar_mul_with_constant_base_montgomery() {
        let s = Fr::random(&mut trng());
        let p = G1Projective::random(&mut trng());
        let result = p * s;

        // Define input structure
        struct ScalarInput {
            s: ark_bn254::Fr,
        }
        struct ScalarInputWire {
            s: Fr,
        }
        impl crate::circuit::streaming::CircuitInput for ScalarInput {
            type WireRepr = ScalarInputWire;
            fn allocate<C: CircuitContext>(&self, ctx: &mut C) -> Self::WireRepr {
                ScalarInputWire {
                    s: Fr::new(ctx),
                }
            }
            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                repr.s.iter().cloned().collect()
            }
        }
        impl crate::circuit::streaming::EncodeInput<Execute> for ScalarInput {
            fn encode(self, repr: &ScalarInputWire, cache: &mut Execute) {
                let s_fn = Fr::get_wire_bits_fn(&repr.s, &self.s).unwrap();
                for &wire_id in repr.s.iter() {
                    if let Some(bit) = s_fn(wire_id) {
                        cache.feed_wire(wire_id, bit);
                    }
                }
            }
        }

        let inputs = ScalarInput { s };
        let circuit_result = CircuitBuilder::<Execute>::streaming_execute(inputs, |root, inputs_wire| {
            let result_wires = G1Projective::scalar_mul_by_constant_base_montgomery::<10, _>(root, &inputs_wire.s, &p);
            let mut output_ids = Vec::new();
            output_ids.extend(result_wires.x.iter());
            output_ids.extend(result_wires.y.iter());
            output_ids.extend(result_wires.z.iter());
            output_ids
        });

        let actual_result = G1Projective::from_bits_unchecked(
            circuit_result.output_wires.clone()
        );
        assert_eq!(actual_result, G1Projective::as_montgomery(result));
    }

    #[test]
    fn test_msm_with_constant_bases_montgomery() {
        let n = 1;
        let scalars = (0..n).map(|_| Fr::random(&mut trng())).collect::<Vec<_>>();
        let bases = (0..n)
            .map(|_| G1Projective::random(&mut trng()))
            .collect::<Vec<_>>();
        let bases_affine = bases.iter().map(|g| g.into_affine()).collect::<Vec<_>>();
        let result = ark_bn254::G1Projective::msm(&bases_affine, &scalars).unwrap();

        // Define input structure
        struct MsmInputs {
            scalars: Vec<ark_bn254::Fr>,
        }
        struct MsmInputsWire {
            scalars: Vec<Fr>,
        }
        impl crate::circuit::streaming::CircuitInput for MsmInputs {
            type WireRepr = MsmInputsWire;
            fn allocate<C: CircuitContext>(&self, ctx: &mut C) -> Self::WireRepr {
                MsmInputsWire {
                    scalars: (0..self.scalars.len()).map(|_| Fr::new(ctx)).collect(),
                }
            }
            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                repr.scalars.iter().flat_map(|fr| fr.iter().cloned()).collect()
            }
        }
        impl crate::circuit::streaming::EncodeInput<Execute> for MsmInputs {
            fn encode(self, repr: &MsmInputsWire, cache: &mut Execute) {
                for (fr_wire, fr_val) in repr.scalars.iter().zip(self.scalars.iter()) {
                    let fr_fn = Fr::get_wire_bits_fn(fr_wire, fr_val).unwrap();
                    for &wire_id in fr_wire.iter() {
                        if let Some(bit) = fr_fn(wire_id) {
                            cache.feed_wire(wire_id, bit);
                        }
                    }
                }
            }
        }

        let inputs = MsmInputs { scalars };
        let circuit_result = CircuitBuilder::<Execute>::streaming_execute(inputs, |root, inputs_wire| {
            let result_wires = G1Projective::msm_with_constant_bases_montgomery::<10, _>(
                root,
                &inputs_wire.scalars,
                &bases,
            );
            let mut output_ids = Vec::new();
            output_ids.extend(result_wires.x.iter());
            output_ids.extend(result_wires.y.iter());
            output_ids.extend(result_wires.z.iter());
            output_ids
        });

        let actual_result = G1Projective::from_bits_unchecked(
            circuit_result.output_wires.clone()
        );
        assert_eq!(actual_result, G1Projective::as_montgomery(result));
    }
}
