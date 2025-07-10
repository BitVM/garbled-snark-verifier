use crate::{bag::*, circuits::bn254::fq12::Fq12};
use ark_ec::bn::BnConfig;
use ark_ff::{BitIteratorBE, CyclotomicMultSubgroup, Field};

pub fn conjugate(f: ark_bn254::Fq12) -> ark_bn254::Fq12 {
    ark_bn254::Fq12::new(f.c0, -f.c1)
}

pub fn cyclotomic_exp(f: ark_bn254::Fq12) -> ark_bn254::Fq12 {
    let mut res = ark_bn254::Fq12::ONE;
    let mut found_nonzero = false;
    for value in BitIteratorBE::without_leading_zeros(ark_bn254::Config::X).map(|e| e as i8) {
        if found_nonzero {
            res.square_in_place(); // cyclotomic_square_in_place
        }

        if value != 0 {
            found_nonzero = true;

            if value > 0 {
                res *= &f;
            }
        }
    }
    res
}

pub fn cyclotomic_exp_evaluate_montgomery_fast(f: Wires) -> (Wires, GateCount) {
    let mut res = Fq12::wires_set_montgomery(ark_bn254::Fq12::ONE);
    let mut gate_count = GateCount::zero();
    let mut found_nonzero = false;
    for value in BitIteratorBE::without_leading_zeros(ark_bn254::Config::X)
        .map(|e| e as i8)
        .collect::<Vec<_>>()
    {
        if found_nonzero {
            let (wires1, gc) = (
                Fq12::wires_set_montgomery(Fq12::from_montgomery_wires(res.clone()).square()),
                GateCount::fq12_cyclotomic_square_montgomery(),
            ); //Fq12::square_evaluate_montgomery(res.clone());
            res = wires1;
            gate_count += gc;
        }

        if value != 0 {
            found_nonzero = true;

            if value > 0 {
                let (wires2, gc) = (
                    Fq12::wires_set_montgomery(
                        Fq12::from_montgomery_wires(res.clone())
                            * Fq12::from_montgomery_wires(f.clone()),
                    ),
                    GateCount::fq12_mul_montgomery(),
                ); // Fq12::mul_evaluate(res.clone(), f.clone());
                res = wires2;
                gate_count += gc;
            }
        }
    }
    (res, gate_count)
}

pub fn cyclotomic_exp_fastinv(f: ark_bn254::Fq12) -> ark_bn254::Fq12 {
    let self_inverse = f.cyclotomic_inverse().unwrap();
    let mut res = ark_bn254::Fq12::ONE;
    let mut found_nonzero = false;
    for value in ark_ff::biginteger::arithmetic::find_naf(ark_bn254::Config::X)
        .into_iter()
        .rev()
    {
        if found_nonzero {
            res.square_in_place(); // cyclotomic_square_in_place
        }

        if value != 0 {
            found_nonzero = true;

            if value > 0 {
                res *= &f;
            } else {
                res *= &self_inverse;
            }
        }
    }
    res
}

pub fn cyclotomic_exp_fast_inverse_evaluate_montgomery_fast(f: Wires) -> (Wires, GateCount) {
    let mut res = Fq12::wires_set_montgomery(ark_bn254::Fq12::ONE);
    let mut gate_count = GateCount::zero();
    let (f_inverse, gc) = (
        Fq12::wires_set_montgomery(Fq12::from_montgomery_wires(f.clone()).inverse().unwrap()),
        GateCount::fq12_inverse_montgomery(),
    ); //Fq12::inverse(res.clone());
    gate_count += gc;
    let mut found_nonzero = false;
    for value in ark_ff::biginteger::arithmetic::find_naf(ark_bn254::Config::X)
        .into_iter()
        .rev()
    {
        if found_nonzero {
            let (wires1, gc) = (
                Fq12::wires_set_montgomery(Fq12::from_montgomery_wires(res.clone()).square()),
                GateCount::fq12_cyclotomic_square_montgomery(),
            ); //Fq12::square_evaluate_montgomery(res.clone());
            res = wires1;
            gate_count += gc;
        }

        if value != 0 {
            found_nonzero = true;

            if value > 0 {
                let (wires2, gc) = (
                    Fq12::wires_set_montgomery(
                        Fq12::from_montgomery_wires(res.clone())
                            * Fq12::from_montgomery_wires(f.clone()),
                    ),
                    GateCount::fq12_mul_montgomery(),
                ); // Fq12::mul_evaluate_montgomery(res.clone(), f.clone());
                res = wires2;
                gate_count += gc;
            } else {
                let (wires2, gc) = (
                    Fq12::wires_set_montgomery(
                        Fq12::from_montgomery_wires(res.clone())
                            * Fq12::from_montgomery_wires(f_inverse.clone()),
                    ),
                    GateCount::fq12_mul_montgomery(),
                ); // Fq12::mul_evaluate_montgomery(res.clone(), f_inverse.clone());
                res = wires2;
                gate_count += gc;
            }
        }
    }
    (res, gate_count)
}

pub fn exp_by_neg_x(f: ark_bn254::Fq12) -> ark_bn254::Fq12 {
    conjugate(cyclotomic_exp(f))
}

pub fn exp_by_neg_x_evaluate_montgomery(f: Wires) -> (Wires, GateCount) {
    let mut gate_count = GateCount::zero();
    let (f2, gc) = cyclotomic_exp_fast_inverse_evaluate_montgomery_fast(f);
    gate_count += gc;
    let (f3, gc) = Fq12::conjugate_evaluate(f2);
    gate_count += gc;
    (f3, gate_count)
}

pub fn final_exponentiation(f: ark_bn254::Fq12) -> ark_bn254::Fq12 {
    let u = f.inverse().unwrap() * conjugate(f);
    let r = u.frobenius_map(2) * u;
    let y0 = exp_by_neg_x(r);
    let y1 = y0.square();
    let y2 = y1.square();
    let y3 = y2 * y1;
    let y4 = exp_by_neg_x(y3);
    let y5 = y4.square();
    let y6 = exp_by_neg_x(y5);
    let y7 = conjugate(y3);
    let y8 = conjugate(y6);
    let y9 = y8 * y4;
    let y10 = y9 * y7;
    let y11 = y10 * y1;
    let y12 = y10 * y4;
    let y13 = y12 * r;
    let y14 = y11.frobenius_map(1);
    let y15 = y14 * y13;
    let y16 = y10.frobenius_map(2);
    let y17 = y16 * y15;
    let r2 = conjugate(r);
    let y18 = r2 * y11;
    let y19 = y18.frobenius_map(3);

    y19 * y17
}

pub fn final_exponentiation_evaluate_montgomery_fast(f: Wires) -> (Wires, GateCount) {
    let mut gate_count = GateCount::zero();
    let (f_inv, gc) = (
        Fq12::wires_set_montgomery(Fq12::from_montgomery_wires(f.clone()).inverse().unwrap()),
        GateCount::fq12_inverse_montgomery(),
    );
    gate_count += gc;
    let (f_conjugate, gc) = Fq12::conjugate_evaluate(f.clone());
    gate_count += gc;
    let (u, gc) = (
        Fq12::wires_set_montgomery(
            Fq12::from_montgomery_wires(f_inv) * Fq12::from_montgomery_wires(f_conjugate),
        ),
        GateCount::fq12_mul_montgomery(),
    ); // Fq12::mul_evaluate_montgomery(f_inv, f_conjugate);
    gate_count += gc;
    let (u_frobenius, gc) = Fq12::frobenius_evaluate_montgomery(u.clone(), 2);
    gate_count += gc;
    let (r, gc) = (
        Fq12::wires_set_montgomery(
            Fq12::from_montgomery_wires(u_frobenius) * Fq12::from_montgomery_wires(u.clone()),
        ),
        GateCount::fq12_mul_montgomery(),
    ); // Fq12::mul_evaluate_montgomery(u_frobenius, u.clone());
    gate_count += gc;
    let (y0, gc) = exp_by_neg_x_evaluate_montgomery(r.clone());
    gate_count += gc;
    let (y1, gc) = (
        Fq12::wires_set_montgomery(Fq12::from_montgomery_wires(y0).square()),
        GateCount::fq12_square_montgomery(),
    ); // Fq12::square_evaluate_montgomery(y0);
    gate_count += gc;
    let (y2, gc) = (
        Fq12::wires_set_montgomery(Fq12::from_montgomery_wires(y1.clone()).square()),
        GateCount::fq12_square_montgomery(),
    ); // Fq12::square_evaluate_montgomery(y1.clone());
    gate_count += gc;
    let (y3, gc) = (
        Fq12::wires_set_montgomery(
            Fq12::from_montgomery_wires(y1.clone()) * Fq12::from_montgomery_wires(y2),
        ),
        GateCount::fq12_mul_montgomery(),
    ); // Fq12::mul_evaluate_montgomery(y1.clone(), y2);
    gate_count += gc;
    let (y4, gc) = exp_by_neg_x_evaluate_montgomery(y3.clone());
    gate_count += gc;
    let (y5, gc) = (
        Fq12::wires_set_montgomery(Fq12::from_montgomery_wires(y4.clone()).square()),
        GateCount::fq12_square_montgomery(),
    ); // Fq12::square_evaluate_montgomery(y4.clone());
    gate_count += gc;
    let (y6, gc) = exp_by_neg_x_evaluate_montgomery(y5);
    gate_count += gc;
    let (y7, gc) = Fq12::conjugate_evaluate(y3);
    gate_count += gc;
    let (y8, gc) = Fq12::conjugate_evaluate(y6);
    gate_count += gc;
    let (y9, gc) = (
        Fq12::wires_set_montgomery(
            Fq12::from_montgomery_wires(y8) * Fq12::from_montgomery_wires(y4.clone()),
        ),
        GateCount::fq12_mul_montgomery(),
    ); // Fq12::mul_evaluate_montgomery(y8, y4.clone());
    gate_count += gc;
    let (y10, gc) = (
        Fq12::wires_set_montgomery(
            Fq12::from_montgomery_wires(y9) * Fq12::from_montgomery_wires(y7),
        ),
        GateCount::fq12_mul_montgomery(),
    ); // Fq12::mul_evaluate_montgomery(y9, y7);
    gate_count += gc;
    let (y11, gc) = (
        Fq12::wires_set_montgomery(
            Fq12::from_montgomery_wires(y10.clone()) * Fq12::from_montgomery_wires(y1),
        ),
        GateCount::fq12_mul_montgomery(),
    ); // Fq12::mul_evaluate_montgomery(y10.clone(), y1);
    gate_count += gc;
    let (y12, gc) = (
        Fq12::wires_set_montgomery(
            Fq12::from_montgomery_wires(y10.clone()) * Fq12::from_montgomery_wires(y4),
        ),
        GateCount::fq12_mul_montgomery(),
    ); // Fq12::mul_evaluate_montgomery(y10.clone(), y4);
    gate_count += gc;
    let (y13, gc) = (
        Fq12::wires_set_montgomery(
            Fq12::from_montgomery_wires(y12) * Fq12::from_montgomery_wires(r.clone()),
        ),
        GateCount::fq12_mul_montgomery(),
    ); // Fq12::mul_evaluate_montgomery(y12, r.clone());
    gate_count += gc;
    let (y14, gc) = Fq12::frobenius_evaluate_montgomery(y11.clone(), 1);
    gate_count += gc;
    let (y15, gc) = (
        Fq12::wires_set_montgomery(
            Fq12::from_montgomery_wires(y14) * Fq12::from_montgomery_wires(y13),
        ),
        GateCount::fq12_mul_montgomery(),
    ); // Fq12::mul_evaluate_montgomery(y14, y13);
    gate_count += gc;
    let (y16, gc) = Fq12::frobenius_evaluate_montgomery(y10, 2);
    gate_count += gc;
    let (y17, gc) = (
        Fq12::wires_set_montgomery(
            Fq12::from_montgomery_wires(y16) * Fq12::from_montgomery_wires(y15),
        ),
        GateCount::fq12_mul_montgomery(),
    ); // Fq12::mul_evaluate_montgomery(y16, y15);
    gate_count += gc;
    let (r2, gc) = Fq12::conjugate_evaluate(r);
    gate_count += gc;
    let (y18, gc) = (
        Fq12::wires_set_montgomery(
            Fq12::from_montgomery_wires(r2) * Fq12::from_montgomery_wires(y11),
        ),
        GateCount::fq12_mul_montgomery(),
    ); // Fq12::mul_evaluate_montgomery(r2, y11);
    gate_count += gc;
    let (y19, gc) = Fq12::frobenius_evaluate_montgomery(y18, 3);
    gate_count += gc;
    let (y20, gc) = (
        Fq12::wires_set_montgomery(
            Fq12::from_montgomery_wires(y19) * Fq12::from_montgomery_wires(y17),
        ),
        GateCount::fq12_mul_montgomery(),
    ); // Fq12::mul_evaluate_montgomery(y19, y17);
    gate_count += gc;
    (y20, gate_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::bn254::{fp254impl::Fp254Impl, fq::Fq, fq12::Fq12};
    use ark_ec::{
        bn::BnConfig,
        pairing::{MillerLoopOutput, Pairing},
    };
    use ark_ff::{CyclotomicMultSubgroup, Field, UniformRand};
    use ark_std::rand::SeedableRng;
    use num_bigint::BigUint;
    use rand_chacha::ChaCha20Rng;
    use std::str::FromStr;

    #[test]
    fn test_cyclotomic_exp() {
        let p = Fq::modulus_as_biguint();
        let u = (p.pow(6) - BigUint::from_str("1").unwrap())
            * (p.pow(2) + BigUint::from_str("1").unwrap());
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let cyclotomic_f = f.pow(u.to_u64_digits());

        let c = cyclotomic_f.cyclotomic_exp(ark_bn254::Config::X);
        let d = cyclotomic_exp(cyclotomic_f);
        let e = cyclotomic_exp_fastinv(cyclotomic_f);
        assert_eq!(c, d);
        assert_eq!(c, e);
    }

    #[test]
    fn test_cyclotomic_exp_evaluate_montgomery_fast() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);

        let c = cyclotomic_exp(f); // f.cyclotomic_exp(ark_bn254::Config::X);
        let (d, gate_count) =
            cyclotomic_exp_evaluate_montgomery_fast(Fq12::wires_set_montgomery(f));
        gate_count.print();
        assert_eq!(c, Fq12::from_montgomery_wires(d));
    }

    #[test]
    fn test_cyclotomic_exp_fast_inverse_evaluate_montgomery_fast() {
        let p = Fq::modulus_as_biguint();
        let u = (p.pow(6) - BigUint::from_str("1").unwrap())
            * (p.pow(2) + BigUint::from_str("1").unwrap());
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let cyclotomic_f = f.pow(u.to_u64_digits());
        let c = cyclotomic_f.cyclotomic_exp(ark_bn254::Config::X);
        let (d, gate_count) = cyclotomic_exp_fast_inverse_evaluate_montgomery_fast(
            Fq12::wires_set_montgomery(cyclotomic_f),
        );
        gate_count.print();
        assert_eq!(c, Fq12::from_montgomery_wires(d));
    }

    #[test]
    fn test_final_exponentiation() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);

        let c = ark_bn254::Bn254::final_exponentiation(MillerLoopOutput(f))
            .unwrap()
            .0;
        let d = final_exponentiation(f);
        assert_eq!(c, d);
    }

    #[test]
    fn test_final_exponentiation_evaluate_montgomery_fast() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);

        let c = ark_bn254::Bn254::final_exponentiation(MillerLoopOutput(f))
            .unwrap()
            .0;
        let (d, gate_count) =
            final_exponentiation_evaluate_montgomery_fast(Fq12::wires_set_montgomery(f));
        gate_count.print();

        assert_eq!(Fq12::from_montgomery_wires(d), c);
    }
}
