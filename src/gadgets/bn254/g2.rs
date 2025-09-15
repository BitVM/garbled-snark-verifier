use std::{cmp::min, collections::HashMap, iter::zip};

use ark_ff::Zero;
use circuit_component_macro::component;

use crate::{
    CircuitContext, WireId,
    circuit::{FromWires, WiresObject},
    gadgets::{
        bigint::Error,
        bn254::{fp254impl::Fp254Impl, fq::Fq, fq2::Fq2, fr::Fr},
    },
};

#[derive(Clone, Debug)]
pub struct G2Projective {
    pub x: Fq2,
    pub y: Fq2,
    pub z: Fq2,
}

impl WiresObject for G2Projective {
    fn to_wires_vec(&self) -> Vec<WireId> {
        let mut wires = Vec::new();
        wires.extend(self.x.to_wires_vec());
        wires.extend(self.y.to_wires_vec());
        wires.extend(self.z.to_wires_vec());
        wires
    }

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        let Self { x, y, z } = self;

        Self {
            x: x.clone_from(wire_gen),
            y: y.clone_from(wire_gen),
            z: z.clone_from(wire_gen),
        }
    }
}

impl FromWires for G2Projective {
    fn from_wires(wires: &[WireId]) -> Option<Self> {
        let len = wires.len() / 3;
        let mut chunks = wires.chunks(len);
        Some(Self {
            x: Fq2::from_wires(chunks.next()?)?,
            y: Fq2::from_wires(chunks.next()?)?,
            z: Fq2::from_wires(chunks.next()?)?,
        })
    }
}

impl G2Projective {
    pub const N_BITS: usize = 3 * Fq2::N_BITS;

    pub fn from_ctx<C: CircuitContext>(circuit: &mut C) -> Self {
        Self {
            x: Fq2::from_ctx(circuit),
            y: Fq2::from_ctx(circuit),
            z: Fq2::from_ctx(circuit),
        }
    }

    pub fn new(mut issue: impl FnMut() -> WireId) -> Self {
        Self {
            x: Fq2::new(&mut issue),
            y: Fq2::new(&mut issue),
            z: Fq2::new(issue),
        }
    }

    pub fn new_constant(u: &ark_bn254::G2Projective) -> Result<Self, Error> {
        Ok(Self {
            x: Fq2::from_components(
                Fq::new_constant(&u.x.c0).unwrap(),
                Fq::new_constant(&u.x.c1).unwrap(),
            ),
            y: Fq2::from_components(
                Fq::new_constant(&u.y.c0).unwrap(),
                Fq::new_constant(&u.y.c1).unwrap(),
            ),
            z: Fq2::from_components(
                Fq::new_constant(&u.z.c0).unwrap(),
                Fq::new_constant(&u.z.c1).unwrap(),
            ),
        })
    }

    pub fn from_bits_unchecked(bits: Vec<bool>) -> ark_bn254::G2Projective {
        let bits1_c0 = bits[0..Fq::N_BITS].to_vec();
        let bits1_c1 = bits[Fq::N_BITS..Fq2::N_BITS].to_vec();
        let bits2_c0 = bits[Fq2::N_BITS..Fq2::N_BITS + Fq::N_BITS].to_vec();
        let bits2_c1 = bits[Fq2::N_BITS + Fq::N_BITS..Fq2::N_BITS * 2].to_vec();
        let bits3_c0 = bits[Fq2::N_BITS * 2..Fq2::N_BITS * 2 + Fq::N_BITS].to_vec();
        let bits3_c1 = bits[Fq2::N_BITS * 2 + Fq::N_BITS..Fq2::N_BITS * 3].to_vec();
        ark_bn254::G2Projective {
            x: Fq2::from_bits((bits1_c0, bits1_c1)),
            y: Fq2::from_bits((bits2_c0, bits2_c1)),
            z: Fq2::from_bits((bits3_c0, bits3_c1)),
        }
    }

    pub fn to_bitmask(&self, get_val: impl Fn(WireId) -> bool) -> String {
        let to_char = |wire_id: &WireId| if (get_val)(*wire_id) { '1' } else { '0' };
        let x = self
            .x
            .c0()
            .iter()
            .chain(self.x.c1().iter())
            .map(to_char)
            .collect::<String>();
        let y = self
            .y
            .c0()
            .iter()
            .chain(self.y.c1().iter())
            .map(to_char)
            .collect::<String>();
        let z = self
            .z
            .c0()
            .iter()
            .chain(self.z.c1().iter())
            .map(to_char)
            .collect::<String>();

        format!("x: {x}, y: {y}, z: {z}")
    }

    pub fn to_bitvec(&self, get_val: impl Fn(WireId) -> bool) -> Vec<bool> {
        let to_char = |wire_id: &WireId| (get_val)(*wire_id);
        let x = self
            .x
            .c0()
            .iter()
            .chain(self.x.c1().iter())
            .map(to_char)
            .collect::<Vec<bool>>();
        let y = self
            .y
            .c0()
            .iter()
            .chain(self.y.c1().iter())
            .map(to_char)
            .collect::<Vec<bool>>();
        let z = self
            .z
            .c0()
            .iter()
            .chain(self.z.c1().iter())
            .map(to_char)
            .collect::<Vec<bool>>();

        let mut v = Vec::new();
        v.extend(x);
        v.extend(y);
        v.extend(z);

        v
    }

    pub fn as_montgomery(p: ark_bn254::G2Projective) -> ark_bn254::G2Projective {
        ark_bn254::G2Projective {
            x: Fq2::as_montgomery(p.x),
            y: Fq2::as_montgomery(p.y),
            z: Fq2::as_montgomery(p.z),
        }
    }

    pub fn from_montgomery(p: ark_bn254::G2Projective) -> ark_bn254::G2Projective {
        ark_bn254::G2Projective {
            x: Fq2::from_montgomery(p.x),
            y: Fq2::from_montgomery(p.y),
            z: Fq2::from_montgomery(p.z),
        }
    }

    pub fn get_wire_bits_fn(
        wires: &G2Projective,
        value: &ark_bn254::G2Projective,
    ) -> Result<impl Fn(WireId) -> Option<bool> + use<>, crate::gadgets::bigint::Error> {
        let G2Projective {
            x: wires_x,
            y: wires_y,
            z: wires_z,
        } = wires;
        let (x_c0, x_c1) = Fq2::to_bits(value.x);
        let (y_c0, y_c1) = Fq2::to_bits(value.y);
        let (z_c0, z_c1) = Fq2::to_bits(value.z);

        let bits = wires_x
            .c0()
            .iter()
            .zip(x_c0.iter())
            .chain(wires_x.c1().iter().zip(x_c1.iter()))
            .chain(wires_y.c0().iter().zip(y_c0.iter()))
            .chain(wires_y.c1().iter().zip(y_c1.iter()))
            .chain(wires_z.c0().iter().zip(z_c0.iter()))
            .chain(wires_z.c1().iter().zip(z_c1.iter()))
            .map(|(wire_id, value)| (*wire_id, *value))
            .collect::<HashMap<WireId, bool>>();

        Ok(move |wire_id: WireId| bits.get(&wire_id).copied())
    }
}

impl G2Projective {
    // http://koclab.cs.ucsb.edu/teaching/ccs130h/2018/09projective.pdf
    #[component]
    pub fn add_montgomery<C: CircuitContext>(
        circuit: &mut C,
        p: &G2Projective,
        q: &G2Projective,
    ) -> G2Projective {
        assert_eq!(p.x.c0().len() + p.x.c1().len(), Fq2::N_BITS);
        assert_eq!(p.y.c0().len() + p.y.c1().len(), Fq2::N_BITS);
        assert_eq!(p.z.c0().len() + p.z.c1().len(), Fq2::N_BITS);

        assert_eq!(q.x.c0().len() + q.x.c1().len(), Fq2::N_BITS);
        assert_eq!(q.y.c0().len() + q.y.c1().len(), Fq2::N_BITS);
        assert_eq!(q.z.c0().len() + q.z.c1().len(), Fq2::N_BITS);

        let G2Projective {
            x: x1,
            y: y1,
            z: z1,
        } = p;
        let G2Projective {
            x: x2,
            y: y2,
            z: z2,
        } = q;

        let z1s = Fq2::square_montgomery(circuit, z1);
        let z2s = Fq2::square_montgomery(circuit, z2);
        let z1c = Fq2::mul_montgomery(circuit, &z1s, z1);
        let z2c = Fq2::mul_montgomery(circuit, &z2s, z2);
        let u1 = Fq2::mul_montgomery(circuit, x1, &z2s);
        let u2 = Fq2::mul_montgomery(circuit, x2, &z1s);
        let s1 = Fq2::mul_montgomery(circuit, y1, &z2c);
        let s2 = Fq2::mul_montgomery(circuit, y2, &z1c);
        let r = Fq2::sub(circuit, &s1, &s2);
        let h = Fq2::sub(circuit, &u1, &u2);
        let h2 = Fq2::square_montgomery(circuit, &h);
        let g = Fq2::mul_montgomery(circuit, &h, &h2);
        let v = Fq2::mul_montgomery(circuit, &u1, &h2);
        let r2 = Fq2::square_montgomery(circuit, &r);
        let r2g = Fq2::add(circuit, &r2, &g);
        let vd = Fq2::double(circuit, &v);
        let x3 = Fq2::sub(circuit, &r2g, &vd);
        let vx3 = Fq2::sub(circuit, &v, &x3);
        let w = Fq2::mul_montgomery(circuit, &r, &vx3);
        let s1g = Fq2::mul_montgomery(circuit, &s1, &g);
        let y3 = Fq2::sub(circuit, &w, &s1g);
        let z1z2 = Fq2::mul_montgomery(circuit, z1, z2);
        let z3 = Fq2::mul_montgomery(circuit, &z1z2, &h);

        let z1_0 = Fq2::equal_constant(circuit, z1, &ark_bn254::Fq2::zero());
        let z2_0 = Fq2::equal_constant(circuit, z2, &ark_bn254::Fq2::zero());

        let zero = Fq2::from_components(
            Fq::new_constant(&ark_bn254::Fq::zero()).unwrap(),
            Fq::new_constant(&ark_bn254::Fq::zero()).unwrap(),
        );

        let s = [z1_0, z2_0];

        // Implement multiplexer for Fq2 by multiplexing each component
        let x_c0 = Fq::multiplexer(
            circuit,
            &[
                x3.c0().clone(),
                x2.c0().clone(),
                x1.c0().clone(),
                zero.c0().clone(),
            ],
            &s,
            2,
        );
        let x_c1 = Fq::multiplexer(
            circuit,
            &[
                x3.c1().clone(),
                x2.c1().clone(),
                x1.c1().clone(),
                zero.c1().clone(),
            ],
            &s,
            2,
        );
        let x = Fq2::from_components(x_c0, x_c1);

        let y_c0 = Fq::multiplexer(
            circuit,
            &[
                y3.c0().clone(),
                y2.c0().clone(),
                y1.c0().clone(),
                zero.c0().clone(),
            ],
            &s,
            2,
        );
        let y_c1 = Fq::multiplexer(
            circuit,
            &[
                y3.c1().clone(),
                y2.c1().clone(),
                y1.c1().clone(),
                zero.c1().clone(),
            ],
            &s,
            2,
        );
        let y = Fq2::from_components(y_c0, y_c1);

        let z_c0 = Fq::multiplexer(
            circuit,
            &[
                z3.c0().clone(),
                z2.c0().clone(),
                z1.c0().clone(),
                zero.c0().clone(),
            ],
            &s,
            2,
        );
        let z_c1 = Fq::multiplexer(
            circuit,
            &[
                z3.c1().clone(),
                z2.c1().clone(),
                z1.c1().clone(),
                zero.c1().clone(),
            ],
            &s,
            2,
        );
        let z = Fq2::from_components(z_c0, z_c1);

        G2Projective { x, y, z }
    }

    #[component]
    pub fn double_montgomery<C: CircuitContext>(circuit: &mut C, p: &G2Projective) -> G2Projective {
        assert_eq!(p.x.c0().len() + p.x.c1().len(), Fq2::N_BITS);
        assert_eq!(p.y.c0().len() + p.y.c1().len(), Fq2::N_BITS);
        assert_eq!(p.z.c0().len() + p.z.c1().len(), Fq2::N_BITS);

        let G2Projective {
            x: x1,
            y: y1,
            z: z1,
        } = p;

        let x2 = Fq2::square_montgomery(circuit, x1);
        let y2 = Fq2::square_montgomery(circuit, y1);
        let m = Fq2::triple(circuit, &x2);
        let t = Fq2::square_montgomery(circuit, &y2);
        let xy2 = Fq2::mul_montgomery(circuit, x1, &y2);
        let xy2d = Fq2::double(circuit, &xy2);
        let s = Fq2::double(circuit, &xy2d);
        let m2 = Fq2::square_montgomery(circuit, &m);
        let sd = Fq2::double(circuit, &s);
        let xr = Fq2::sub(circuit, &m2, &sd);
        let sxr = Fq2::sub(circuit, &s, &xr);
        let msxr = Fq2::mul_montgomery(circuit, &m, &sxr);
        let td = Fq2::double(circuit, &t);
        let tdd = Fq2::double(circuit, &td);
        let tddd = Fq2::double(circuit, &tdd);
        let yr = Fq2::sub(circuit, &msxr, &tddd);
        let yz = Fq2::mul_montgomery(circuit, y1, z1);
        let zr = Fq2::double(circuit, &yz);

        let z_0 = Fq2::equal_constant(circuit, z1, &ark_bn254::Fq2::zero());
        let zero = Fq2::from_components(
            Fq::new_constant(&ark_bn254::Fq::zero()).unwrap(),
            Fq::new_constant(&ark_bn254::Fq::zero()).unwrap(),
        );
        let z_c0 = Fq::multiplexer(circuit, &[zr.c0().clone(), zero.c0().clone()], &[z_0], 1);
        let z_c1 = Fq::multiplexer(circuit, &[zr.c1().clone(), zero.c1().clone()], &[z_0], 1);
        let z = Fq2::from_components(z_c0, z_c1);

        G2Projective { x: xr, y: yr, z }
    }

    #[component(offcircuit_args = "w")]
    pub fn multiplexer<C: CircuitContext>(
        circuit: &mut C,
        a: &[G2Projective],
        s: &[WireId],
        w: usize,
    ) -> G2Projective {
        let n = 2_usize.pow(w.try_into().unwrap());
        assert_eq!(a.len(), n);
        assert_eq!(s.len(), w);

        // Multiplexer for G2 by component-wise selection
        let x_c0 = Fq::multiplexer(
            circuit,
            &a.iter().map(|p| p.x.c0().clone()).collect::<Vec<_>>(),
            s,
            w,
        );
        let x_c1 = Fq::multiplexer(
            circuit,
            &a.iter().map(|p| p.x.c1().clone()).collect::<Vec<_>>(),
            s,
            w,
        );
        let y_c0 = Fq::multiplexer(
            circuit,
            &a.iter().map(|p| p.y.c0().clone()).collect::<Vec<_>>(),
            s,
            w,
        );
        let y_c1 = Fq::multiplexer(
            circuit,
            &a.iter().map(|p| p.y.c1().clone()).collect::<Vec<_>>(),
            s,
            w,
        );
        let z_c0 = Fq::multiplexer(
            circuit,
            &a.iter().map(|p| p.z.c0().clone()).collect::<Vec<_>>(),
            s,
            w,
        );
        let z_c1 = Fq::multiplexer(
            circuit,
            &a.iter().map(|p| p.z.c1().clone()).collect::<Vec<_>>(),
            s,
            w,
        );
        G2Projective {
            x: Fq2::from_components(x_c0, x_c1),
            y: Fq2::from_components(y_c0, y_c1),
            z: Fq2::from_components(z_c0, z_c1),
        }
    }

    #[component(offcircuit_args = "base")]
    pub fn scalar_mul_by_constant_base_montgomery<C: CircuitContext, const W: usize>(
        circuit: &mut C,
        s: &Fr,
        base: &ark_bn254::G2Projective,
    ) -> G2Projective {
        assert_eq!(s.len(), Fr::N_BITS);
        let n = 2_usize.pow(W as u32);

        let mut bases = Vec::new();
        let mut p = ark_bn254::G2Projective::default();

        for _ in 0..n {
            bases.push(p);
            p += base;
        }

        let mut bases_wires = bases
            .iter()
            .map(|p| G2Projective::new_constant(p).unwrap())
            .collect::<Vec<_>>();

        let mut to_be_added = Vec::new();

        let mut index = 0;
        while index < Fr::N_BITS {
            let w = min(W, Fr::N_BITS - index);
            let m = 2_usize.pow(w as u32);
            let selector: Vec<WireId> = s.iter().skip(index).take(w).copied().collect();
            let result = Self::multiplexer(circuit, &bases_wires[0..m], &selector, w);
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
                .map(|p| G2Projective::new_constant(p).unwrap())
                .collect::<Vec<_>>();
        }

        let mut acc = to_be_added[0].clone();
        for add in to_be_added.iter().skip(1) {
            let new_acc = Self::add_montgomery(circuit, &acc, add);
            acc = new_acc;
        }

        acc
    }

    pub fn msm_with_constant_bases_montgomery<const W: usize, C: CircuitContext>(
        circuit: &mut C,
        scalars: &Vec<Fr>,
        bases: &Vec<ark_bn254::G2Projective>,
    ) -> G2Projective {
        assert_eq!(scalars.len(), bases.len());
        let mut to_be_added = Vec::new();
        for (s, base) in zip(scalars, bases) {
            let result = Self::scalar_mul_by_constant_base_montgomery::<_, W>(circuit, s, base);
            to_be_added.push(result);
        }

        let mut acc = to_be_added[0].clone();
        for add in to_be_added.iter().skip(1) {
            let new_acc = Self::add_montgomery(circuit, &acc, add);
            acc = new_acc;
        }
        acc
    }

    #[component]
    pub fn neg<C: CircuitContext>(circuit: &mut C, p: &G2Projective) -> G2Projective {
        G2Projective {
            x: p.x.clone(),
            y: Fq2::neg(circuit, p.y.clone()),
            z: p.z.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_ec::{CurveGroup, VariableBaseMSM};
    use ark_ff::UniformRand;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::{
        circuit::{CircuitBuilder, CircuitInput, EncodeInput, modes::CircuitMode},
        test_utils::trng,
    };

    pub fn rnd_fr(rng: &mut impl Rng) -> ark_bn254::Fr {
        let mut prng = ChaCha20Rng::seed_from_u64(rng.r#gen());
        ark_bn254::Fr::rand(&mut prng)
    }

    pub fn rnd_g2(rng: &mut impl Rng) -> ark_bn254::G2Projective {
        ark_bn254::G2Projective::default() * rnd_fr(rng)
    }

    // Standardized input/output structures for G2 tests
    pub struct G2Input<const N: usize> {
        pub points: [ark_bn254::G2Projective; N],
    }

    pub struct G2InputWire<const N: usize> {
        pub points: [G2Projective; N],
    }

    impl<const N: usize> CircuitInput for G2Input<N> {
        type WireRepr = G2InputWire<N>;

        fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
            G2InputWire {
                points: std::array::from_fn(|_| G2Projective::new(&mut issue)),
            }
        }

        fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
            let mut wires = Vec::new();
            for point in &repr.points {
                wires.extend(point.to_wires_vec());
            }
            wires
        }
    }

    impl<const N: usize, M: CircuitMode<WireValue = bool>> EncodeInput<M> for G2Input<N> {
        fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
            for (point_wire, point_val) in repr.points.iter().zip(self.points.iter()) {
                let point_fn = G2Projective::get_wire_bits_fn(point_wire, point_val).unwrap();
                for &wire_id in point_wire
                    .x
                    .c0()
                    .iter()
                    .chain(point_wire.x.c1().iter())
                    .chain(point_wire.y.c0().iter())
                    .chain(point_wire.y.c1().iter())
                    .chain(point_wire.z.c0().iter())
                    .chain(point_wire.z.c1().iter())
                {
                    if let Some(bit) = point_fn(wire_id) {
                        cache.feed_wire(wire_id, bit);
                    }
                }
            }
        }
    }

    pub struct ScalarInput<const N: usize> {
        pub scalars: [ark_bn254::Fr; N],
    }

    pub struct ScalarInputWire<const N: usize> {
        pub scalars: [Fr; N],
    }

    impl<const N: usize> CircuitInput for ScalarInput<N> {
        type WireRepr = ScalarInputWire<N>;

        fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
            ScalarInputWire {
                scalars: std::array::from_fn(|_| Fr::new(&mut issue)),
            }
        }

        fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
            let mut wires = Vec::new();
            for scalar in &repr.scalars {
                wires.extend(scalar.iter().cloned());
            }
            wires
        }
    }

    impl<const N: usize, M: CircuitMode<WireValue = bool>> EncodeInput<M> for ScalarInput<N> {
        fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
            for (scalar_wire, scalar_val) in repr.scalars.iter().zip(self.scalars.iter()) {
                let scalar_fn = Fr::get_wire_bits_fn(scalar_wire, scalar_val).unwrap();
                for &wire_id in scalar_wire.iter() {
                    if let Some(bit) = scalar_fn(wire_id) {
                        cache.feed_wire(wire_id, bit);
                    }
                }
            }
        }
    }

    fn rnd() -> ark_bn254::G2Projective {
        use ark_ec::PrimeGroup;
        let g2 = ark_bn254::G2Projective::generator();
        g2.mul_bigint(<rand::rngs::StdRng as SeedableRng>::seed_from_u64(1).r#gen::<[u64; 4]>())
    }

    #[test]
    fn test_g2p_add_montgomery() {
        // Generate random G2 points
        let a = rnd_g2(&mut trng());
        let b = rnd_g2(&mut trng());
        let c = a + b;

        // Convert to Montgomery form
        let a_mont = G2Projective::as_montgomery(a);
        let b_mont = G2Projective::as_montgomery(b);
        let c_mont = G2Projective::as_montgomery(c);

        let inputs = G2Input {
            points: [a_mont, b_mont],
        };
        let result: crate::circuit::StreamingResult<_, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 10_000, |root, inputs_wire| {
                let result_wires = G2Projective::add_montgomery(
                    root,
                    &inputs_wire.points[0],
                    &inputs_wire.points[1],
                );
                result_wires.to_wires_vec()
            });

        let actual_result = G2Projective::from_bits_unchecked(result.output_value.clone());
        assert_eq!(actual_result, c_mont);
    }

    #[test]
    fn test_g2p_double_montgomery() {
        // Generate random G2 point
        let a = rnd();
        let c = a + a;

        // Convert to Montgomery form
        let a_mont = G2Projective::as_montgomery(a);
        let c_mont = G2Projective::as_montgomery(c);

        let inputs = G2Input { points: [a_mont] };
        let result: crate::circuit::StreamingResult<_, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 10_000, |root, inputs_wire| {
                let result_wires = G2Projective::double_montgomery(root, &inputs_wire.points[0]);
                result_wires.to_wires_vec()
            });

        let actual_result = G2Projective::from_bits_unchecked(result.output_value.clone());
        assert_eq!(actual_result, c_mont);
    }

    #[test]
    fn test_g2p_neg() {
        // Generate random G2 point
        let a = rnd_g2(&mut trng());
        let neg_a = -a;

        // Convert to Montgomery form
        let a_mont = G2Projective::as_montgomery(a);
        let neg_a_mont = G2Projective::as_montgomery(neg_a);

        let inputs = G2Input { points: [a_mont] };
        let result: crate::circuit::StreamingResult<_, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 10_000, |root, inputs_wire| {
                let result_wires = G2Projective::neg(root, &inputs_wire.points[0]);
                result_wires.to_wires_vec()
            });

        let actual_result = G2Projective::from_bits_unchecked(result.output_value.clone());
        assert_eq!(actual_result, neg_a_mont);
    }

    #[test]
    fn test_g2p_multiplexer() {
        let w = 2;
        let n = 2_usize.pow(w as u32);
        let a_val = (0..n)
            .map(|_| G2Projective::as_montgomery(rnd_g2(&mut trng())))
            .collect::<Vec<_>>();
        let s_val = (0..w).map(|_| trng().r#gen()).collect::<Vec<_>>();

        let mut u = 0;
        for i in s_val.iter().rev() {
            u = u + u + if *i { 1 } else { 0 };
        }
        let expected = a_val[u];

        // Define input structure
        struct MultiplexerInputs {
            a: Vec<ark_bn254::G2Projective>,
            s: Vec<bool>,
        }
        struct MultiplexerInputsWire {
            a: Vec<G2Projective>,
            s: Vec<WireId>,
        }
        impl crate::circuit::CircuitInput for MultiplexerInputs {
            type WireRepr = MultiplexerInputsWire;
            fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
                MultiplexerInputsWire {
                    a: (0..self.a.len())
                        .map(|_| G2Projective::new(&mut issue))
                        .collect(),
                    s: (0..self.s.len()).map(|_| (issue)()).collect(),
                }
            }
            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                let mut wires = Vec::new();
                for g2 in &repr.a {
                    wires.extend(g2.to_wires_vec());
                }
                wires.extend(&repr.s);
                wires
            }
        }
        impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for MultiplexerInputs {
            fn encode(&self, repr: &MultiplexerInputsWire, cache: &mut M) {
                for (g2_wire, g2_val) in repr.a.iter().zip(self.a.iter()) {
                    let g2_fn = G2Projective::get_wire_bits_fn(g2_wire, g2_val).unwrap();
                    for &wire_id in g2_wire
                        .x
                        .c0()
                        .iter()
                        .chain(g2_wire.x.c1().iter())
                        .chain(g2_wire.y.c0().iter())
                        .chain(g2_wire.y.c1().iter())
                        .chain(g2_wire.z.c0().iter())
                        .chain(g2_wire.z.c1().iter())
                    {
                        if let Some(bit) = g2_fn(wire_id) {
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
        let result: crate::circuit::StreamingResult<_, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 10_000, |root, inputs_wire| {
                let result_wires =
                    G2Projective::multiplexer(root, &inputs_wire.a, &inputs_wire.s, w);
                result_wires.to_wires_vec()
            });

        let actual_result = G2Projective::from_bits_unchecked(result.output_value.clone());
        assert_eq!(actual_result, expected);
    }

    #[test]
    fn test_g2p_scalar_mul_with_constant_base_montgomery() {
        let s = rnd_fr(&mut trng());
        let p = rnd_g2(&mut trng());
        let result = p * s;

        let inputs = ScalarInput { scalars: [s] };
        let circuit_result: crate::circuit::StreamingResult<_, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 10_000, |root, inputs_wire| {
                let result_wires = G2Projective::scalar_mul_by_constant_base_montgomery::<_, 10>(
                    root,
                    &inputs_wire.scalars[0],
                    &p,
                );
                result_wires.to_wires_vec()
            });

        let actual_result = G2Projective::from_bits_unchecked(circuit_result.output_value.clone());
        assert_eq!(actual_result, G2Projective::as_montgomery(result));
    }

    #[test]
    fn test_msm_with_constant_bases_montgomery() {
        let n = 1;
        let scalars = (0..n).map(|_| rnd_fr(&mut trng())).collect::<Vec<_>>();
        let bases = (0..n).map(|_| rnd_g2(&mut trng())).collect::<Vec<_>>();
        let bases_affine = bases.iter().map(|g| g.into_affine()).collect::<Vec<_>>();
        let result = ark_bn254::G2Projective::msm(&bases_affine, &scalars).unwrap();

        // Define input structure
        struct MsmInputs {
            scalars: Vec<ark_bn254::Fr>,
        }
        struct MsmInputsWire {
            scalars: Vec<Fr>,
        }
        impl crate::circuit::CircuitInput for MsmInputs {
            type WireRepr = MsmInputsWire;
            fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
                MsmInputsWire {
                    scalars: (0..self.scalars.len())
                        .map(|_| Fr::new(&mut issue))
                        .collect(),
                }
            }

            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                repr.scalars
                    .iter()
                    .flat_map(|fr| fr.iter().cloned())
                    .collect()
            }
        }
        impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for MsmInputs {
            fn encode(&self, repr: &MsmInputsWire, cache: &mut M) {
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
        let circuit_result: crate::circuit::StreamingResult<_, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 10_000, |root, inputs_wire| {
                let result_wires = G2Projective::msm_with_constant_bases_montgomery::<10, _>(
                    root,
                    &inputs_wire.scalars,
                    &bases,
                );
                result_wires.to_wires_vec()
            });

        let actual_result = G2Projective::from_bits_unchecked(circuit_result.output_value.clone());
        assert_eq!(actual_result, G2Projective::as_montgomery(result));
    }
}
