use std::{cmp::min, collections::HashMap, iter::zip};

use ark_ff::{AdditiveGroup, Field, UniformRand, Zero};
use digest::typenum::bit;
use num_bigint::BigUint;
use rand::{Rng, rng};

use crate::{
    Circuit, WireId,
    gadgets::{
        bigint::{self, BigIntWires},
        bn254::{fp254impl::Fp254Impl, fq::Fq, fr::Fr},
    },
};

#[derive(Clone)]
pub struct Point<T> {
    x: T,
    y: T,
    z: T,
}

impl Point<BigIntWires> {
    pub fn mark_as_output(&self, circuit: &mut Circuit) {
        self.x.mark_as_output(circuit);
        self.y.mark_as_output(circuit);
        self.z.mark_as_output(circuit);
    }

    pub fn to_bitmask(&self, get_val: impl Fn(WireId) -> bool) -> String {
        let to_char = |wire_id: &WireId| if (get_val)(*wire_id) { '1' } else { '0' };
        let x = self.x.iter().map(to_char).collect::<String>();
        let y = self.y.iter().map(to_char).collect::<String>();
        let z = self.z.iter().map(to_char).collect::<String>();

        format!("x: {x}, y: {y}, z: {z}")
    }
}

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

    pub fn to_bits(u: ark_bn254::G1Projective) -> Point<Vec<bool>> {
        Point {
            x: Fq::to_bits(u.x),
            y: Fq::to_bits(u.y),
            z: Fq::to_bits(u.z),
        }
    }

    pub fn from_bits(bits: &Point<Vec<bool>>) -> ark_bn254::G1Projective {
        let bits = bits.clone();

        ark_bn254::G1Projective::new(
            Fq::from_bits(bits.x),
            Fq::from_bits(bits.y),
            Fq::from_bits(bits.z),
        )
    }

    pub fn new_bn(circuit: &mut Circuit, is_input: bool, is_output: bool) -> Point<BigIntWires> {
        Point {
            x: BigIntWires::new(circuit, Fq::N_BITS, is_input, is_output),
            y: BigIntWires::new(circuit, Fq::N_BITS, is_input, is_output),
            z: BigIntWires::new(circuit, Fq::N_BITS, is_input, is_output),
        }
    }

    pub fn get_wire_bits_fn(
        wires: &Point<BigIntWires>,
        value: &ark_bn254::G1Projective,
    ) -> Result<impl Fn(WireId) -> Option<bool> + use<>, crate::gadgets::bigint::Error> {
        let Point {
            x: wires_x,
            y: wirex_y,
            z: wires_z,
        } = wires;
        let Point { x, y, z } = Self::to_bits(*value);

        let bits = wires_x
            .iter()
            .zip(x.iter())
            .chain(wirex_y.iter().zip(y.iter()))
            .chain(wires_z.iter().zip(z.iter()))
            .map(|(wire_id, value)| (*wire_id, *value))
            .collect::<HashMap<WireId, bool>>();

        Ok(move |wire_id: WireId| bits.get(&wire_id).copied())
    }
}

impl G1Projective {
    // http://koclab.cs.ucsb.edu/teaching/ccs130h/2018/09projective.pdf
    pub fn add_montgomery(
        circuit: &mut Circuit,
        p: &Point<BigIntWires>,
        q: &Point<BigIntWires>,
    ) -> Point<BigIntWires> {
        assert_eq!(p.x.len(), Fq::N_BITS);
        assert_eq!(p.y.len(), Fq::N_BITS);
        assert_eq!(p.z.len(), Fq::N_BITS);

        assert_eq!(q.x.len(), Fq::N_BITS);
        assert_eq!(q.y.len(), Fq::N_BITS);
        assert_eq!(q.z.len(), Fq::N_BITS);

        let Point {
            x: x1,
            y: y1,
            z: z1,
        } = p;
        let Point {
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

        let zero =
            BigIntWires::new_constant(circuit, Fq::N_BITS, &ark_bn254::Fq::zero().into()).unwrap();

        let s = [z1_0, z2_0];

        let x = Fq::multiplexer(circuit, &[&x3, x2, x1, &zero], &s, 2);
        let y = Fq::multiplexer(circuit, &[&y3, y2, y1, &zero], &s, 2);
        let z = Fq::multiplexer(circuit, &[&z3, z2, z1, &zero], &s, 2);

        Point { x, y, z }
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

    /*
    pub fn double_montgomery(p: Wires) -> Circuit {
        assert_eq!(p.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let x = p[0..Fq::N_BITS].to_vec();
        let y = p[Fq::N_BITS..2 * Fq::N_BITS].to_vec();
        let z = p[2 * Fq::N_BITS..3 * Fq::N_BITS].to_vec();

        let x2 = Fq::square_montgomery(x.clone()));
        let y2 = Fq::square_montgomery(y.clone()));
        let m = Fq::triple(x2.clone()));
        let t = Fq::square_montgomery(y2.clone()));
        let xy2 = Fq::mul_montgomery(x.clone(), y2.clone()));
        let xy2d = Fq::double(xy2.clone()));
        let s = Fq::double(xy2d.clone()));
        let m2 = Fq::square_montgomery(m.clone()));
        let sd = Fq::double(s.clone()));
        let xr = Fq::sub(m2.clone(), sd.clone()));
        let sxr = Fq::sub(s.clone(), xr.clone()));
        let msxr = Fq::mul_montgomery(m.clone(), sxr.clone()));
        let td = Fq::double(t.clone()));
        let tdd = Fq::double(td.clone()));
        let tddd = Fq::double(tdd.clone()));
        let yr = Fq::sub(msxr.clone(), tddd.clone()));
        let yz = Fq::mul_montgomery(y.clone(), z.clone()));
        let zr = Fq::double(yz.clone()));

        let z_0 = Fq::equal_zero(z));
        let zero = Fq::wires_set(ark_bn254::Fq::ZERO);
        let z = Fq::multiplexer(vec![zr, zero], z_0, 1));

        circuit.add_wires(xr);
        circuit.add_wires(yr);
        circuit.add_wires(z);

        circuit
    }
    */

    /*
    pub fn multiplexer(a: Vec<Wires>, s: Wires, w: usize) -> Circuit {
        let n = 2_usize.pow(w.try_into().unwrap());
        assert_eq!(a.len(), n);
        for x in a.iter() {
            assert_eq!(x.len(), Self::N_BITS);
        }
        assert_eq!(s.len(), w);
        let mut circuit = Circuit::empty();

        for i in 0..Self::N_BITS {
            let ith_wires = a.iter().map(|x| x[i].clone()).collect();
            let ith_result = multiplexer(ith_wires, s.clone(), w))[0].clone();
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

    pub fn msm_with_constant_bases_evaluate_montgomery<const W: usize>(
        scalars: Vec<Wires>,
        bases: Vec<ark_bn254::G1Projective>,
    ) -> (Wires, GateCount) {
        assert_eq!(scalars.len(), bases.len());
        let mut gate_count = GateCount::zero();
        let mut to_be_added = Vec::new();
        for (s, base) in zip(scalars, bases) {
            let (result, gc) =
                Self::scalar_mul_by_constant_base_evaluate_montgomery::<W>(s, base);
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
    */
}

/*
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

pub fn projective_to_affine_montgomery(p: Wires) -> Circuit {
    assert_eq!(p.len(), G1Projective::N_BITS);
    let mut circuit = Circuit::empty();

    let x = p[0..Fq::N_BITS].to_vec();
    let y = p[Fq::N_BITS..2 * Fq::N_BITS].to_vec();
    let z = p[2 * Fq::N_BITS..3 * Fq::N_BITS].to_vec();

    let z_inverse = Fq::inverse_montgomery(z));
    let z_inverse_square = Fq::square_montgomery(z_inverse.clone()));
    let z_inverse_cube =
        Fq::mul_montgomery(z_inverse, z_inverse_square.clone()));
    let new_x = Fq::mul_montgomery(x, z_inverse_square.clone()));
    let new_y = Fq::mul_montgomery(y, z_inverse_cube.clone()));

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
*/

#[cfg(test)]
mod tests {
    use std::cell::OnceCell;

    use ark_ff::BigInt;
    use rand::{SeedableRng, random};

    use super::*;
    use crate::test_utils::trng;

    fn rnd() -> ark_bn254::G1Projective {
        use ark_ec::PrimeGroup;
        let g1 = ark_bn254::G1Projective::generator();
        g1.mul_bigint(<rand::rngs::StdRng as SeedableRng>::seed_from_u64(1).random::<[u64; 4]>())
    }

    #[test]
    #[ignore = "WIP module temporarily disabled test"]
    fn test_g1p_add_montgomery() {
        let mut circuit = Circuit::default();

        // Create input wires for two G1 points
        let a_wires = G1Projective::new_bn(&mut circuit, true, false);
        let b_wires = G1Projective::new_bn(&mut circuit, true, false);

        // Perform addition
        let result_wires = G1Projective::add_montgomery(&mut circuit, &a_wires, &b_wires);
        result_wires.mark_as_output(&mut circuit);

        //circuit.gates.iter().for_each(|gate| {
        //    println!("{gate}");
        //});

        // Generate random G1 points
        let a = rnd();
        let b = rnd();
        let c = a + b;

        dbg!((&a, &b, &c));

        // Convert to Montgomery form
        let a_mont = G1Projective::as_montgomery(a);
        let b_mont = G1Projective::as_montgomery(b);
        let c_mont = G1Projective::as_montgomery(c);

        dbg!((&a_mont, &b_mont, &c_mont));

        // Set up input and output functions
        let a_input = G1Projective::get_wire_bits_fn(&a_wires, &a_mont).unwrap();
        let b_input = G1Projective::get_wire_bits_fn(&b_wires, &b_mont).unwrap();
        let result_output = G1Projective::get_wire_bits_fn(&result_wires, &c_mont).unwrap();

        let output = circuit
            .simple_evaluate(|wire_id| (a_input)(wire_id).or((b_input)(wire_id)))
            .unwrap()
            .collect::<HashMap<WireId, bool>>();

        let actual_result = result_wires.to_bitmask(|wire_id| *output.get(&wire_id).unwrap());
        let expected_result = result_wires.to_bitmask(|wire_id| result_output(wire_id).unwrap());

        assert_eq!(actual_result, expected_result);
    }

    /*
    use ark_ec::{scalar_mul::variable_base::VariableBaseMSM, CurveGroup};
    use ark_ff::Field;
    use rand::{rng, Rng};

    use super::*;

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

        let circuit = G1Projective::add_montgomery(
            G1Projective::wires_set_montgomery(a),
            G1Projective::wires_set_montgomery(c),
        );
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let d = G1Projective::from_wires_unchecked(circuit.0);
        assert_eq!(d, G1Projective::as_montgomery(a));

        let circuit = G1Projective::add_montgomery(
            G1Projective::wires_set_montgomery(c),
            G1Projective::wires_set_montgomery(b),
        );
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let d = G1Projective::from_wires_unchecked(circuit.0);
        assert_eq!(d, G1Projective::as_montgomery(b));

        let circuit = G1Projective::add_montgomery(
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
        let circuit = G1Projective::double_montgomery(G1Projective::wires_set_montgomery(b));
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = G1Projective::from_wires_unchecked(circuit.0);
        assert_eq!(c, G1Projective::as_montgomery(b));
    }

    #[test]
    fn test_g1p_multiplexer() {
        let w = 10;
        let n = 2_usize.pow(w as u32);
        let a: Vec<ark_bn254::G1Projective> = (0..n).map(|_| G1Projective::random()).collect();
        let s: Wires = (0..w).map(|_| new_wirex()).collect();

        let mut a_wires = Vec::new();
        for e in a.iter() {
            a_wires.push(G1Projective::wires_set(*e));
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
        for e in a.iter() {
            a_wires.push(G1Projective::wires_set(*e));
        }

        let mut u = 0;
        for wire in s.iter().rev() {
            let x = rng().random();
            u = u + u + if x { 1 } else { 0 };
            wire.borrow_mut().set(x);
        }

        let (result_wires, gate_count) =
            G1Projective::multiplexer_evaluate(a_wires, s.clone(), w);
        gate_count.print();
        let result = G1Projective::from_wires(result_wires);
        let expected = a[u];

        assert_eq!(result, expected);
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
    */
}
