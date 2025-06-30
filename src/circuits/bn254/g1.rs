use crate::{
    bag::*,
    circuits::{
        basic::multiplexer,
        bn254::{fp254impl::Fp254Impl, fq::Fq, fr::Fr},
    },
};
use ark_ff::{AdditiveGroup, UniformRand};
use ark_std::rand::SeedableRng;
use rand::{Rng, rng};
use rand_chacha::ChaCha20Rng;
use std::{cmp::min, iter::zip};

pub struct G1Projective;

impl G1Projective {
    pub const N_BITS: usize = 3 * Fq::N_BITS;

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

    pub fn random() -> ark_bn254::G1Projective {
        let mut prng = ChaCha20Rng::seed_from_u64(rng().random());
        ark_bn254::G1Projective::rand(&mut prng)
    }

    pub fn to_bits(u: ark_bn254::G1Projective) -> Vec<bool> {
        let mut bits = Vec::new();
        bits.extend(Fq::to_bits(u.x));
        bits.extend(Fq::to_bits(u.y));
        bits.extend(Fq::to_bits(u.z));
        bits
    }

    pub fn from_bits(bits: Vec<bool>) -> ark_bn254::G1Projective {
        let bits1 = &bits[0..Fq::N_BITS].to_vec();
        let bits2 = &bits[Fq::N_BITS..Fq::N_BITS * 2].to_vec();
        let bits3 = &bits[Fq::N_BITS * 2..Fq::N_BITS * 3].to_vec();
        ark_bn254::G1Projective::new(
            Fq::from_bits(bits1.clone()),
            Fq::from_bits(bits2.clone()),
            Fq::from_bits(bits3.clone()),
        )
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

    pub fn wires() -> Wires {
        (0..Self::N_BITS).map(|_| new_wirex()).collect()
    }

    pub fn wires_set(u: ark_bn254::G1Projective) -> Wires {
        Self::to_bits(u)[0..Self::N_BITS]
            .iter()
            .map(|bit| {
                let wire = new_wirex();
                wire.borrow_mut().set(*bit);
                wire
            })
            .collect()
    }

    pub fn wires_set_montgomery(u: ark_bn254::G1Projective) -> Wires {
        Self::wires_set(Self::as_montgomery(u))
    }

    pub fn from_wires(wires: Wires) -> ark_bn254::G1Projective {
        Self::from_bits(wires.iter().map(|wire| wire.borrow().get_value()).collect())
    }

    pub fn from_wires_unchecked(wires: Wires) -> ark_bn254::G1Projective {
        Self::from_bits_unchecked(wires.iter().map(|wire| wire.borrow().get_value()).collect())
    }

    pub fn from_montgomery_wires_unchecked(wires: Wires) -> ark_bn254::G1Projective {
        Self::from_montgomery(Self::from_wires_unchecked(wires))
    }
}

impl G1Projective {
    // http://koclab.cs.ucsb.edu/teaching/ccs130h/2018/09projective.pdf
    pub fn add(p: Wires, q: Wires) -> Circuit {
        assert_eq!(p.len(), Self::N_BITS);
        assert_eq!(q.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let x1 = p[0..Fq::N_BITS].to_vec();
        let y1 = p[Fq::N_BITS..2 * Fq::N_BITS].to_vec();
        let z1 = p[2 * Fq::N_BITS..3 * Fq::N_BITS].to_vec();
        let x2 = q[0..Fq::N_BITS].to_vec();
        let y2 = q[Fq::N_BITS..2 * Fq::N_BITS].to_vec();
        let z2 = q[2 * Fq::N_BITS..3 * Fq::N_BITS].to_vec();

        let z1s = circuit.extend(Fq::square(z1.clone()));
        let z2s = circuit.extend(Fq::square(z2.clone()));
        let z1c = circuit.extend(Fq::mul(z1s.clone(), z1.clone()));
        let z2c = circuit.extend(Fq::mul(z2s.clone(), z2.clone()));
        let u1 = circuit.extend(Fq::mul(x1.clone(), z2s.clone()));
        let u2 = circuit.extend(Fq::mul(x2.clone(), z1s.clone()));
        let s1 = circuit.extend(Fq::mul(y1.clone(), z2c.clone()));
        let s2 = circuit.extend(Fq::mul(y2.clone(), z1c.clone()));
        let r = circuit.extend(Fq::sub(s1.clone(), s2.clone()));
        let h = circuit.extend(Fq::sub(u1.clone(), u2.clone()));
        let h2 = circuit.extend(Fq::square(h.clone()));
        let g = circuit.extend(Fq::mul(h.clone(), h2.clone()));
        let v = circuit.extend(Fq::mul(u1.clone(), h2.clone()));
        let r2 = circuit.extend(Fq::square(r.clone()));
        let r2g = circuit.extend(Fq::add(r2.clone(), g.clone()));
        let vd = circuit.extend(Fq::double(v.clone()));
        let x3 = circuit.extend(Fq::sub(r2g.clone(), vd.clone()));
        let vx3 = circuit.extend(Fq::sub(v.clone(), x3.clone()));
        let w = circuit.extend(Fq::mul(r.clone(), vx3.clone()));
        let s1g = circuit.extend(Fq::mul(s1.clone(), g.clone()));
        let y3 = circuit.extend(Fq::sub(w.clone(), s1g.clone()));
        let z1z2 = circuit.extend(Fq::mul(z1.clone(), z2.clone()));
        let z3 = circuit.extend(Fq::mul(z1z2.clone(), h.clone()));

        let z1_0 = circuit.extend(Fq::equal_zero(z1.clone()))[0].clone();
        let z2_0 = circuit.extend(Fq::equal_zero(z2.clone()))[0].clone();
        let zero = Fq::wires_set(ark_bn254::Fq::ZERO);
        let s = vec![z1_0, z2_0];
        let x = circuit.extend(Fq::multiplexer(
            vec![x3, x2, x1, zero.clone()],
            s.clone(),
            2,
        ));
        let y = circuit.extend(Fq::multiplexer(
            vec![y3, y2, y1, zero.clone()],
            s.clone(),
            2,
        ));
        let z = circuit.extend(Fq::multiplexer(
            vec![z3, z2, z1, zero.clone()],
            s.clone(),
            2,
        ));

        circuit.add_wires(x);
        circuit.add_wires(y);
        circuit.add_wires(z);

        circuit
    }

    pub fn add_montgomery(p: Wires, q: Wires) -> Circuit {
        assert_eq!(p.len(), Self::N_BITS);
        assert_eq!(q.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let x1 = p[0..Fq::N_BITS].to_vec();
        let y1 = p[Fq::N_BITS..2 * Fq::N_BITS].to_vec();
        let z1 = p[2 * Fq::N_BITS..3 * Fq::N_BITS].to_vec();
        let x2 = q[0..Fq::N_BITS].to_vec();
        let y2 = q[Fq::N_BITS..2 * Fq::N_BITS].to_vec();
        let z2 = q[2 * Fq::N_BITS..3 * Fq::N_BITS].to_vec();

        let z1s = circuit.extend(Fq::square_montgomery(z1.clone()));
        let z2s = circuit.extend(Fq::square_montgomery(z2.clone()));
        let z1c = circuit.extend(Fq::mul_montgomery(z1s.clone(), z1.clone()));
        let z2c = circuit.extend(Fq::mul_montgomery(z2s.clone(), z2.clone()));
        let u1 = circuit.extend(Fq::mul_montgomery(x1.clone(), z2s.clone()));
        let u2 = circuit.extend(Fq::mul_montgomery(x2.clone(), z1s.clone()));
        let s1 = circuit.extend(Fq::mul_montgomery(y1.clone(), z2c.clone()));
        let s2 = circuit.extend(Fq::mul_montgomery(y2.clone(), z1c.clone()));
        let r = circuit.extend(Fq::sub(s1.clone(), s2.clone()));
        let h = circuit.extend(Fq::sub(u1.clone(), u2.clone()));
        let h2 = circuit.extend(Fq::square_montgomery(h.clone()));
        let g = circuit.extend(Fq::mul_montgomery(h.clone(), h2.clone()));
        let v = circuit.extend(Fq::mul_montgomery(u1.clone(), h2.clone()));
        let r2 = circuit.extend(Fq::square_montgomery(r.clone()));
        let r2g = circuit.extend(Fq::add(r2.clone(), g.clone()));
        let vd = circuit.extend(Fq::double(v.clone()));
        let x3 = circuit.extend(Fq::sub(r2g.clone(), vd.clone()));
        let vx3 = circuit.extend(Fq::sub(v.clone(), x3.clone()));
        let w = circuit.extend(Fq::mul_montgomery(r.clone(), vx3.clone()));
        let s1g = circuit.extend(Fq::mul_montgomery(s1.clone(), g.clone()));
        let y3 = circuit.extend(Fq::sub(w.clone(), s1g.clone()));
        let z1z2 = circuit.extend(Fq::mul_montgomery(z1.clone(), z2.clone()));
        let z3 = circuit.extend(Fq::mul_montgomery(z1z2.clone(), h.clone()));

        let z1_0 = circuit.extend(Fq::equal_zero(z1.clone()))[0].clone();
        let z2_0 = circuit.extend(Fq::equal_zero(z2.clone()))[0].clone();
        let zero = Fq::wires_set(ark_bn254::Fq::ZERO);
        let s = vec![z1_0, z2_0];
        let x = circuit.extend(Fq::multiplexer(
            vec![x3, x2, x1, zero.clone()],
            s.clone(),
            2,
        ));
        let y = circuit.extend(Fq::multiplexer(
            vec![y3, y2, y1, zero.clone()],
            s.clone(),
            2,
        ));
        let z = circuit.extend(Fq::multiplexer(
            vec![z3, z2, z1, zero.clone()],
            s.clone(),
            2,
        ));

        circuit.add_wires(x);
        circuit.add_wires(y);
        circuit.add_wires(z);

        circuit
    }

    pub fn add_evaluate(p: Wires, q: Wires) -> (Wires, GateCount) {
        let circuit = Self::add(p, q);
        let n = circuit.gate_counts();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        (circuit.0, n)
    }

    pub fn add_evaluate_montgomery(p: Wires, q: Wires) -> (Wires, GateCount) {
        let circuit = Self::add_montgomery(p, q);
        let n = circuit.gate_counts();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        (circuit.0, n)
    }

    pub fn double(p: Wires) -> Circuit {
        assert_eq!(p.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let x = p[0..Fq::N_BITS].to_vec();
        let y = p[Fq::N_BITS..2 * Fq::N_BITS].to_vec();
        let z = p[2 * Fq::N_BITS..3 * Fq::N_BITS].to_vec();

        let x2 = circuit.extend(Fq::square(x.clone()));
        let y2 = circuit.extend(Fq::square(y.clone()));
        let m = circuit.extend(Fq::triple(x2.clone()));
        let t = circuit.extend(Fq::square(y2.clone()));
        let xy2 = circuit.extend(Fq::mul(x.clone(), y2.clone()));
        let xy2d = circuit.extend(Fq::double(xy2.clone()));
        let s = circuit.extend(Fq::double(xy2d.clone()));
        let m2 = circuit.extend(Fq::square(m.clone()));
        let sd = circuit.extend(Fq::double(s.clone()));
        let xr = circuit.extend(Fq::sub(m2.clone(), sd.clone()));
        let sxr = circuit.extend(Fq::sub(s.clone(), xr.clone()));
        let msxr = circuit.extend(Fq::mul(m.clone(), sxr.clone()));
        let td = circuit.extend(Fq::double(t.clone()));
        let tdd = circuit.extend(Fq::double(td.clone()));
        let tddd = circuit.extend(Fq::double(tdd.clone()));
        let yr = circuit.extend(Fq::sub(msxr.clone(), tddd.clone()));
        let yz = circuit.extend(Fq::mul(y.clone(), z.clone()));
        let zr = circuit.extend(Fq::double(yz.clone()));

        let z_0 = circuit.extend(Fq::equal_zero(z));
        let zero = Fq::wires_set(ark_bn254::Fq::ZERO);
        let z = circuit.extend(Fq::multiplexer(vec![zr, zero], z_0, 1));

        circuit.add_wires(xr);
        circuit.add_wires(yr);
        circuit.add_wires(z);

        circuit
    }

    pub fn double_montgomery(p: Wires) -> Circuit {
        assert_eq!(p.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let x = p[0..Fq::N_BITS].to_vec();
        let y = p[Fq::N_BITS..2 * Fq::N_BITS].to_vec();
        let z = p[2 * Fq::N_BITS..3 * Fq::N_BITS].to_vec();

        let x2 = circuit.extend(Fq::square_montgomery(x.clone()));
        let y2 = circuit.extend(Fq::square_montgomery(y.clone()));
        let m = circuit.extend(Fq::triple(x2.clone()));
        let t = circuit.extend(Fq::square_montgomery(y2.clone()));
        let xy2 = circuit.extend(Fq::mul_montgomery(x.clone(), y2.clone()));
        let xy2d = circuit.extend(Fq::double(xy2.clone()));
        let s = circuit.extend(Fq::double(xy2d.clone()));
        let m2 = circuit.extend(Fq::square_montgomery(m.clone()));
        let sd = circuit.extend(Fq::double(s.clone()));
        let xr = circuit.extend(Fq::sub(m2.clone(), sd.clone()));
        let sxr = circuit.extend(Fq::sub(s.clone(), xr.clone()));
        let msxr = circuit.extend(Fq::mul_montgomery(m.clone(), sxr.clone()));
        let td = circuit.extend(Fq::double(t.clone()));
        let tdd = circuit.extend(Fq::double(td.clone()));
        let tddd = circuit.extend(Fq::double(tdd.clone()));
        let yr = circuit.extend(Fq::sub(msxr.clone(), tddd.clone()));
        let yz = circuit.extend(Fq::mul_montgomery(y.clone(), z.clone()));
        let zr = circuit.extend(Fq::double(yz.clone()));

        let z_0 = circuit.extend(Fq::equal_zero(z));
        let zero = Fq::wires_set(ark_bn254::Fq::ZERO);
        let z = circuit.extend(Fq::multiplexer(vec![zr, zero], z_0, 1));

        circuit.add_wires(xr);
        circuit.add_wires(yr);
        circuit.add_wires(z);

        circuit
    }

    pub fn multiplexer(a: Vec<Wires>, s: Wires, w: usize) -> Circuit {
        let n = 2_usize.pow(w.try_into().unwrap());
        assert_eq!(a.len(), n);
        for x in a.clone() {
            assert_eq!(x.len(), Self::N_BITS);
        }
        assert_eq!(s.len(), w);
        let mut circuit = Circuit::empty();

        for i in 0..Self::N_BITS {
            let ith_wires = a.iter().map(|x| x[i].clone()).collect();
            let ith_result = circuit.extend(multiplexer(ith_wires, s.clone(), w))[0].clone();
            circuit.add_wire(ith_result);
        }

        circuit
    }

    pub fn multiplexer_evaluate(a: Vec<Wires>, s: Wires, w: usize) -> (Wires, GateCount) {
        let circuit = Self::multiplexer(a, s, w);
        let n = circuit.gate_counts();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        (circuit.0, n)
    }

    pub fn scalar_mul_by_constant_base<const W: usize>(
        s: Wires,
        base: ark_bn254::G1Projective,
    ) -> Circuit {
        assert_eq!(s.len(), Fr::N_BITS);
        let mut circuit = Circuit::empty();
        let n = 2_usize.pow(W as u32);

        let mut bases = Vec::new();
        let mut p = ark_bn254::G1Projective::default();

        for _ in 0..n {
            bases.push(p);
            p += base;
        }

        let bases_wires = bases
            .iter()
            .map(|p| G1Projective::wires_set(*p))
            .collect::<Vec<Wires>>();

        let mut to_be_added = Vec::new();

        let mut index = 0;
        while index < Fr::N_BITS {
            let w = min(W, Fr::N_BITS - index);
            let m = 2_usize.pow(w as u32);
            let selector = s[index..(index + w)].to_vec();
            let result = circuit.extend(Self::multiplexer(
                bases_wires.clone()[0..m].to_vec(),
                selector,
                w,
            ));
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
        }

        let mut acc = circuit.extend(Self::add(to_be_added[0].clone(), to_be_added[1].clone()));
        for add in to_be_added.iter().skip(2) {
            acc = circuit.extend(Self::add(acc, add.clone()));
        }

        circuit.add_wires(acc);

        circuit
    }

    pub fn scalar_mul_by_constant_base_evaluate<const W: usize>(
        s: Wires,
        base: ark_bn254::G1Projective,
    ) -> (Wires, GateCount) {
        assert_eq!(s.len(), Fr::N_BITS);
        let mut gate_count = GateCount::zero();
        let n = 2_usize.pow(W as u32);

        let mut bases = Vec::new();
        let mut p = ark_bn254::G1Projective::default();

        for _ in 0..n {
            bases.push(p);
            p += base;
        }

        let mut bases_wires = bases
            .iter()
            .map(|p| G1Projective::wires_set(*p))
            .collect::<Vec<Wires>>();

        let mut to_be_added = Vec::new();

        let mut index = 0;
        while index < Fr::N_BITS {
            let w = min(W, Fr::N_BITS - index);
            let m = 2_usize.pow(w as u32);
            let selector = s[index..(index + w)].to_vec();
            let (result, gc) =
                Self::multiplexer_evaluate(bases_wires.clone()[0..m].to_vec(), selector, w);
            gate_count += gc;
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
                .map(|p| G1Projective::wires_set(*p))
                .collect::<Vec<Wires>>();
        }

        let mut acc = to_be_added[0].clone();
        for add in to_be_added.iter().skip(1) {
            let (new_acc, gc) = Self::add_evaluate(acc, add.clone());
            gate_count += gc;
            acc = new_acc;
        }

        (acc, gate_count)
    }

    pub fn scalar_mul_by_constant_base_evaluate_montgomery<const W: usize>(
        s: Wires,
        base: ark_bn254::G1Projective,
    ) -> (Wires, GateCount) {
        assert_eq!(s.len(), Fr::N_BITS);
        let mut gate_count = GateCount::zero();
        let n = 2_usize.pow(W as u32);

        let mut bases = Vec::new();
        let mut p = ark_bn254::G1Projective::default();

        for _ in 0..n {
            bases.push(p);
            p += base;
        }

        let mut bases_wires = bases
            .iter()
            .map(|p| G1Projective::wires_set_montgomery(*p))
            .collect::<Vec<Wires>>();

        let mut to_be_added = Vec::new();

        let mut index = 0;
        while index < Fr::N_BITS {
            let w = min(W, Fr::N_BITS - index);
            let m = 2_usize.pow(w as u32);
            let selector = s[index..(index + w)].to_vec();
            let (result, gc) =
                Self::multiplexer_evaluate(bases_wires.clone()[0..m].to_vec(), selector, w);
            gate_count += gc;
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
                .map(|p| G1Projective::wires_set_montgomery(*p))
                .collect::<Vec<Wires>>();
        }

        let mut acc = to_be_added[0].clone();
        for add in to_be_added.iter().skip(1) {
            let (new_acc, gc) = Self::add_evaluate_montgomery(acc, add.clone());
            gate_count += gc;
            acc = new_acc;
        }

        (acc, gate_count)
    }

    pub fn msm_with_constant_bases_evaluate<const W: usize>(
        scalars: Vec<Wires>,
        bases: Vec<ark_bn254::G1Projective>,
    ) -> (Wires, GateCount) {
        assert_eq!(scalars.len(), bases.len());
        let mut gate_count = GateCount::zero();
        let mut to_be_added = Vec::new();
        for (s, base) in zip(scalars, bases) {
            let (result, gc) = Self::scalar_mul_by_constant_base_evaluate::<W>(s, base);
            to_be_added.push(result);
            gate_count += gc;
        }

        let mut acc = to_be_added[0].clone();
        for add in to_be_added.iter().skip(1) {
            let (new_acc, gc) = Self::add_evaluate(acc, add.clone());
            gate_count += gc;
            acc = new_acc;
        }

        (acc, gate_count)
    }

    pub fn msm_with_constant_bases_evaluate_montgomery<const W: usize>(
        scalars: Vec<Wires>,
        bases: Vec<ark_bn254::G1Projective>,
    ) -> (Wires, GateCount) {
        assert_eq!(scalars.len(), bases.len());
        let mut gate_count = GateCount::zero();
        let mut to_be_added = Vec::new();
        for (s, base) in zip(scalars, bases) {
            let (result, gc) = Self::scalar_mul_by_constant_base_evaluate_montgomery::<W>(s, base);
            to_be_added.push(result);
            gate_count += gc;
        }

        let mut acc = to_be_added[0].clone();
        for add in to_be_added.iter().skip(1) {
            let (new_acc, gc) = Self::add_evaluate_montgomery(acc, add.clone());
            gate_count += gc;
            acc = new_acc;
        }

        (acc, gate_count)
    }
}

pub struct G1Affine;

impl G1Affine {
    pub const N_BITS: usize = 2 * Fq::N_BITS;

    pub fn as_montgomery(p: ark_bn254::G1Affine) -> ark_bn254::G1Affine {
        ark_bn254::G1Affine {
            x: Fq::as_montgomery(p.x),
            y: Fq::as_montgomery(p.y),
            infinity: false,
        }
    }

    pub fn from_montgomery(p: ark_bn254::G1Affine) -> ark_bn254::G1Affine {
        ark_bn254::G1Affine {
            x: Fq::from_montgomery(p.x),
            y: Fq::from_montgomery(p.y),
            infinity: false,
        }
    }

    pub fn random() -> ark_bn254::G1Affine {
        let mut prng = ChaCha20Rng::seed_from_u64(rng().random());
        ark_bn254::G1Affine::rand(&mut prng)
    }

    pub fn to_bits(u: ark_bn254::G1Affine) -> Vec<bool> {
        let mut bits = Vec::new();
        bits.extend(Fq::to_bits(u.x));
        bits.extend(Fq::to_bits(u.y));
        bits
    }

    pub fn from_bits(bits: Vec<bool>) -> ark_bn254::G1Affine {
        let bits1 = &bits[0..Fq::N_BITS].to_vec();
        let bits2 = &bits[Fq::N_BITS..Fq::N_BITS * 2].to_vec();
        ark_bn254::G1Affine::new(Fq::from_bits(bits1.clone()), Fq::from_bits(bits2.clone()))
    }

    pub fn from_bits_unchecked(bits: Vec<bool>) -> ark_bn254::G1Affine {
        let bits1 = &bits[0..Fq::N_BITS].to_vec();
        let bits2 = &bits[Fq::N_BITS..Fq::N_BITS * 2].to_vec();
        ark_bn254::G1Affine {
            x: Fq::from_bits(bits1.clone()),
            y: Fq::from_bits(bits2.clone()),
            infinity: false,
        }
    }

    pub fn wires() -> Wires {
        (0..Self::N_BITS).map(|_| new_wirex()).collect()
    }

    pub fn wires_set(u: ark_bn254::G1Affine) -> Wires {
        Self::to_bits(u)[0..Self::N_BITS]
            .iter()
            .map(|bit| {
                let wire = new_wirex();
                wire.borrow_mut().set(*bit);
                wire
            })
            .collect()
    }

    pub fn wires_set_montgomery(u: ark_bn254::G1Affine) -> Wires {
        Self::wires_set(Self::as_montgomery(u))
    }

    pub fn from_wires(wires: Wires) -> ark_bn254::G1Affine {
        Self::from_bits(wires.iter().map(|wire| wire.borrow().get_value()).collect())
    }

    pub fn from_wires_unchecked(wires: Wires) -> ark_bn254::G1Affine {
        Self::from_bits_unchecked(wires.iter().map(|wire| wire.borrow().get_value()).collect())
    }

    pub fn from_montgomery_wires_unchecked(wires: Wires) -> ark_bn254::G1Affine {
        Self::from_montgomery(Self::from_wires_unchecked(wires))
    }
}

pub fn projective_to_affine(p: Wires) -> Circuit {
    assert_eq!(p.len(), G1Projective::N_BITS);
    let mut circuit = Circuit::empty();

    let x = p[0..Fq::N_BITS].to_vec();
    let y = p[Fq::N_BITS..2 * Fq::N_BITS].to_vec();
    let z = p[2 * Fq::N_BITS..3 * Fq::N_BITS].to_vec();

    let z_inverse = circuit.extend(Fq::inverse(z));
    let z_inverse_square = circuit.extend(Fq::square(z_inverse.clone()));
    let z_inverse_cube = circuit.extend(Fq::mul(z_inverse, z_inverse_square.clone()));
    let new_x = circuit.extend(Fq::mul(x, z_inverse_square.clone()));
    let new_y = circuit.extend(Fq::mul(y, z_inverse_cube.clone()));

    circuit.add_wires(new_x);
    circuit.add_wires(new_y);

    circuit
}

pub fn projective_to_affine_evaluate(p: Wires) -> (Wires, GateCount) {
    let circuit = projective_to_affine(p);
    let n = circuit.gate_counts();
    for mut gate in circuit.1 {
        gate.evaluate();
    }
    (circuit.0, n)
}

pub fn projective_to_affine_montgomery(p: Wires) -> Circuit {
    assert_eq!(p.len(), G1Projective::N_BITS);
    let mut circuit = Circuit::empty();

    let x = p[0..Fq::N_BITS].to_vec();
    let y = p[Fq::N_BITS..2 * Fq::N_BITS].to_vec();
    let z = p[2 * Fq::N_BITS..3 * Fq::N_BITS].to_vec();

    let z_inverse = circuit.extend(Fq::inverse_montgomery(z));
    let z_inverse_square = circuit.extend(Fq::square_montgomery(z_inverse.clone()));
    let z_inverse_cube = circuit.extend(Fq::mul_montgomery(z_inverse, z_inverse_square.clone()));
    let new_x = circuit.extend(Fq::mul_montgomery(x, z_inverse_square.clone()));
    let new_y = circuit.extend(Fq::mul_montgomery(y, z_inverse_cube.clone()));

    circuit.add_wires(new_x);
    circuit.add_wires(new_y);

    circuit
}

pub fn projective_to_affine_evaluate_montgomery(p: Wires) -> (Wires, GateCount) {
    let circuit = projective_to_affine_montgomery(p);
    let n = circuit.gate_counts();
    for mut gate in circuit.1 {
        gate.evaluate();
    }
    (circuit.0, n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::{CurveGroup, scalar_mul::variable_base::VariableBaseMSM};
    use ark_ff::Field;
    use rand::{Rng, rng};

    #[test]
    fn test_g1a_random() {
        let u = G1Affine::random();
        println!("u: {:?}", u);
        let b = G1Affine::to_bits(u);
        let v = G1Affine::from_bits(b);
        println!("v: {:?}", v);
        assert_eq!(u, v);
    }

    #[test]
    fn test_g1p_random() {
        let u = G1Projective::random();
        println!("u: {:?}", u);
        let b = G1Projective::to_bits(u);
        let v = G1Projective::from_bits(b);
        println!("v: {:?}", v);
        assert_eq!(u, v);
    }

    #[test]
    fn test_g1_projective_to_affine() {
        let p_projective = G1Projective::random().double();
        assert_ne!(p_projective.z, ark_bn254::Fq::ONE);
        let p_affine = p_projective.into_affine();
        let circuit = projective_to_affine(G1Projective::wires_set(p_projective));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let p_affine2 = G1Affine::from_wires(circuit.0);
        assert_eq!(p_affine, p_affine2);
    }

    #[test]
    fn test_g1_projective_to_affine_montgomery() {
        let p_projective = G1Projective::random().double();
        assert_ne!(p_projective.z, ark_bn254::Fq::ONE);
        let p_affine = p_projective.into_affine();
        let circuit =
            projective_to_affine_montgomery(G1Projective::wires_set_montgomery(p_projective));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let p_affine2 = G1Affine::from_montgomery_wires_unchecked(circuit.0);
        assert_eq!(p_affine, p_affine2);
    }

    #[test]
    #[ignore]
    fn test_g1p_add() {
        let a = G1Projective::random();
        let b = G1Projective::random();
        let c = ark_bn254::G1Projective::ZERO;
        let circuit = G1Projective::add(G1Projective::wires_set(a), G1Projective::wires_set(b));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let d = G1Projective::from_wires(circuit.0);
        assert_eq!(d, a + b);

        let circuit = G1Projective::add(G1Projective::wires_set(a), G1Projective::wires_set(c));
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let d = G1Projective::from_wires(circuit.0);
        assert_eq!(d, a);

        let circuit = G1Projective::add(G1Projective::wires_set(c), G1Projective::wires_set(b));
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let d = G1Projective::from_wires(circuit.0);
        assert_eq!(d, b);

        let circuit = G1Projective::add(G1Projective::wires_set(c), G1Projective::wires_set(c));
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let d = G1Projective::from_wires(circuit.0);
        assert_eq!(d, c);
    }

    #[test]
    #[ignore]
    fn test_g1p_add_montgomery() {
        let a = G1Projective::random();
        let b = G1Projective::random();
        let c = ark_bn254::G1Projective::ZERO;
        let circuit = G1Projective::add_montgomery(
            G1Projective::wires_set_montgomery(a),
            G1Projective::wires_set_montgomery(b),
        );
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let d = G1Projective::from_wires_unchecked(circuit.0);
        assert_eq!(d, G1Projective::as_montgomery(a + b));

        let circuit = G1Projective::add(
            G1Projective::wires_set_montgomery(a),
            G1Projective::wires_set_montgomery(c),
        );
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let d = G1Projective::from_wires_unchecked(circuit.0);
        assert_eq!(d, G1Projective::as_montgomery(a));

        let circuit = G1Projective::add(
            G1Projective::wires_set_montgomery(c),
            G1Projective::wires_set_montgomery(b),
        );
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let d = G1Projective::from_wires_unchecked(circuit.0);
        assert_eq!(d, G1Projective::as_montgomery(b));

        let circuit = G1Projective::add(
            G1Projective::wires_set_montgomery(c),
            G1Projective::wires_set_montgomery(c),
        );
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let d = G1Projective::from_wires_unchecked(circuit.0);
        assert_eq!(d, G1Projective::as_montgomery(c));
    }

    #[test]
    fn test_g1p_add_evaluate() {
        let a = G1Projective::random();
        let b = G1Projective::random();
        let (c_wires, gate_count) =
            G1Projective::add_evaluate(G1Projective::wires_set(a), G1Projective::wires_set(b));
        gate_count.print();
        let c = G1Projective::from_wires(c_wires);
        assert_eq!(c, a + b);
    }

    #[test]
    fn test_g1p_add_evaluate_montgomery() {
        let a = G1Projective::random();
        let b = G1Projective::random();
        let (c_wires, gate_count) = G1Projective::add_evaluate_montgomery(
            G1Projective::wires_set_montgomery(a),
            G1Projective::wires_set_montgomery(b),
        );
        gate_count.print();
        let c = G1Projective::from_wires_unchecked(c_wires);
        assert_eq!(c, G1Projective::as_montgomery(a + b));
    }

    #[test]
    fn test_g1p_double() {
        let a = G1Projective::random();
        let circuit = G1Projective::double(G1Projective::wires_set(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = G1Projective::from_wires(circuit.0);
        assert_eq!(c, a + a);

        let b = ark_bn254::G1Projective::ZERO;
        let circuit = G1Projective::double(G1Projective::wires_set(b));
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = G1Projective::from_wires(circuit.0);
        assert_eq!(c, b);
    }

    #[test]
    fn test_g1p_double_montgomery() {
        let a = G1Projective::random();
        let circuit = G1Projective::double_montgomery(G1Projective::wires_set_montgomery(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = G1Projective::from_wires_unchecked(circuit.0);
        assert_eq!(c, G1Projective::as_montgomery(a + a));

        let b = ark_bn254::G1Projective::ZERO;
        let circuit = G1Projective::double(G1Projective::wires_set_montgomery(b));
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = G1Projective::from_wires_unchecked(circuit.0);
        assert_eq!(c, G1Projective::as_montgomery(b));
    }

    #[test]
    #[ignore]
    fn test_g1p_multiplexer() {
        let w = 10;
        let n = 2_usize.pow(w as u32);
        let a: Vec<ark_bn254::G1Projective> = (0..n).map(|_| G1Projective::random()).collect();
        let s: Wires = (0..w).map(|_| new_wirex()).collect();

        let mut a_wires = Vec::new();
        for e in a.clone() {
            a_wires.push(G1Projective::wires_set(e));
        }

        let mut u = 0;
        for wire in s.iter().rev() {
            let x = rng().random();
            u = u + u + if x { 1 } else { 0 };
            wire.borrow_mut().set(x);
        }

        let circuit = G1Projective::multiplexer(a_wires, s.clone(), w);
        circuit.gate_counts().print();

        for mut gate in circuit.1 {
            gate.evaluate();
        }

        let result = G1Projective::from_wires(circuit.0);
        let expected = a[u];

        assert_eq!(result, expected);
    }

    #[test]
    fn test_g1p_multiplexer_evaluate() {
        let w = 10;
        let n = 2_usize.pow(w as u32);
        let a: Vec<ark_bn254::G1Projective> = (0..n).map(|_| G1Projective::random()).collect();
        let s: Wires = (0..w).map(|_| new_wirex()).collect();

        let mut a_wires = Vec::new();
        for e in a.clone() {
            a_wires.push(G1Projective::wires_set(e));
        }

        let mut u = 0;
        for wire in s.iter().rev() {
            let x = rng().random();
            u = u + u + if x { 1 } else { 0 };
            wire.borrow_mut().set(x);
        }

        let (result_wires, gate_count) = G1Projective::multiplexer_evaluate(a_wires, s.clone(), w);
        gate_count.print();
        let result = G1Projective::from_wires(result_wires);
        let expected = a[u];

        assert_eq!(result, expected);
    }

    #[test]
    #[ignore]
    fn test_g1p_scalar_mul() {
        let base = G1Projective::random();
        let s = Fr::random();
        let circuit = G1Projective::scalar_mul_by_constant_base::<10>(Fr::wires_set(s), base);
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let result = G1Projective::from_wires(circuit.0);
        assert_eq!(result, base * s);
    }

    #[test]
    #[ignore]
    fn test_g1p_scalar_mul_with_constant_base_evaluate() {
        let base = G1Projective::random();
        let s = Fr::random();
        let (result_wires, gate_count) =
            G1Projective::scalar_mul_by_constant_base_evaluate::<10>(Fr::wires_set(s), base);
        gate_count.print();
        let result = G1Projective::from_wires(result_wires);
        assert_eq!(result, base * s);
    }

    #[test]
    #[ignore]
    fn test_g1p_scalar_mul_with_constant_base_evaluate_montgomery() {
        let base = G1Projective::random();
        let s = Fr::random();
        let (result_wires, gate_count) =
            G1Projective::scalar_mul_by_constant_base_evaluate_montgomery::<10>(
                Fr::wires_set(s),
                base,
            );
        gate_count.print();
        let result = G1Projective::from_wires_unchecked(result_wires);
        assert_eq!(result, G1Projective::as_montgomery(base * s));
    }

    #[test]
    fn test_msm_with_constant_bases_evaluate() {
        let n = 1;
        let bases = (0..n).map(|_| G1Projective::random()).collect::<Vec<_>>();
        let scalars = (0..n).map(|_| Fr::random()).collect::<Vec<_>>();
        let (result_wires, gate_count) = G1Projective::msm_with_constant_bases_evaluate::<10>(
            scalars.iter().map(|s| Fr::wires_set(*s)).collect(),
            bases.clone(),
        );
        gate_count.print();
        let result = G1Projective::from_wires(result_wires);
        let bases_affine = bases.iter().map(|g| g.into_affine()).collect::<Vec<_>>();
        let expected = ark_bn254::G1Projective::msm(&bases_affine, &scalars).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_msm_with_constant_bases_evaluate_montgomery() {
        let n = 1;
        let bases = (0..n).map(|_| G1Projective::random()).collect::<Vec<_>>();
        let scalars = (0..n).map(|_| Fr::random()).collect::<Vec<_>>();
        let (result_wires, gate_count) =
            G1Projective::msm_with_constant_bases_evaluate_montgomery::<10>(
                scalars.iter().map(|s| Fr::wires_set(*s)).collect(),
                bases.clone(),
            );
        gate_count.print();
        let result = G1Projective::from_wires_unchecked(result_wires);
        let bases_affine = bases.iter().map(|g| g.into_affine()).collect::<Vec<_>>();
        let expected = ark_bn254::G1Projective::msm(&bases_affine, &scalars).unwrap();
        assert_eq!(result, G1Projective::as_montgomery(expected));
    }
}
