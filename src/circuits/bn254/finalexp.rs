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

pub fn cyclotomic_exp_evaluate_fast(f: Wires) -> (Wires, CircuitMetrics) {
    let mut res = Fq12::wires_set(ark_bn254::Fq12::ONE);
    let mut circuit_metrics = CircuitMetrics::zero();
    let mut found_nonzero = false;
    for value in BitIteratorBE::without_leading_zeros(ark_bn254::Config::X)
        .map(|e| e as i8)
        .collect::<Vec<_>>()
    {
        if found_nonzero {
            let (wires1, gc) = (
                Fq12::wires_set(Fq12::from_wires(res.clone()).square()),
                CircuitMetrics::fq12_cyclotomic_square(),
            ); //Fq12::square_evaluate(res.clone());
            res = wires1;
            circuit_metrics += gc;
        }

        if value != 0 {
            found_nonzero = true;

            if value > 0 {
                let (wires2, gc) = (
                    Fq12::wires_set(Fq12::from_wires(res.clone()) * Fq12::from_wires(f.clone())),
                    CircuitMetrics::fq12_mul(),
                ); // Fq12::mul_evaluate(res.clone(), f.clone());
                res = wires2;
                circuit_metrics += gc;
            }
        }
    }
    (res, circuit_metrics)
}

pub fn cyclotomic_exp_evaluate_montgomery_fast(f: Wires) -> (Wires, CircuitMetrics) {
    let mut res = Fq12::wires_set_montgomery(ark_bn254::Fq12::ONE);
    let mut circuit_metrics = CircuitMetrics::zero();
    let mut found_nonzero = false;
    for value in BitIteratorBE::without_leading_zeros(ark_bn254::Config::X)
        .map(|e| e as i8)
        .collect::<Vec<_>>()
    {
        if found_nonzero {
            let (wires1, gc) = (
                Fq12::wires_set_montgomery(Fq12::from_montgomery_wires(res.clone()).square()),
                CircuitMetrics::fq12_cyclotomic_square_montgomery(),
            ); //Fq12::square_evaluate_montgomery(res.clone());
            res = wires1;
            circuit_metrics += gc;
        }

        if value != 0 {
            found_nonzero = true;

            if value > 0 {
                let (wires2, gc) = (
                    Fq12::wires_set_montgomery(
                        Fq12::from_montgomery_wires(res.clone())
                            * Fq12::from_montgomery_wires(f.clone()),
                    ),
                    CircuitMetrics::fq12_mul_montgomery(),
                ); // Fq12::mul_evaluate(res.clone(), f.clone());
                res = wires2;
                circuit_metrics += gc;
            }
        }
    }
    (res, circuit_metrics)
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

pub fn cyclotomic_exp_fast_inverse_evaluate_fast(f: Wires) -> (Wires, CircuitMetrics) {
    let mut res = Fq12::wires_set(ark_bn254::Fq12::ONE);
    let mut circuit_metrics = CircuitMetrics::zero();
    let (f_inverse, gc) = (
        Fq12::wires_set(Fq12::from_wires(f.clone()).inverse().unwrap()),
        CircuitMetrics::fq12_inverse(),
    ); //Fq12::inverse(res.clone());
    circuit_metrics += gc;
    let mut found_nonzero = false;
    for value in ark_ff::biginteger::arithmetic::find_naf(ark_bn254::Config::X)
        .into_iter()
        .rev()
    {
        if found_nonzero {
            let (wires1, gc) = (
                Fq12::wires_set(Fq12::from_wires(res.clone()).square()),
                CircuitMetrics::fq12_cyclotomic_square(),
            ); //Fq12::square_evaluate(res.clone());
            res = wires1;
            circuit_metrics += gc;
        }

        if value != 0 {
            found_nonzero = true;

            if value > 0 {
                let (wires2, gc) = (
                    Fq12::wires_set(Fq12::from_wires(res.clone()) * Fq12::from_wires(f.clone())),
                    CircuitMetrics::fq12_mul(),
                ); // Fq12::mul_evaluate(res.clone(), f.clone());
                res = wires2;
                circuit_metrics += gc;
            } else {
                let (wires2, gc) = (
                    Fq12::wires_set(
                        Fq12::from_wires(res.clone()) * Fq12::from_wires(f_inverse.clone()),
                    ),
                    CircuitMetrics::fq12_mul(),
                ); // Fq12::mul_evaluate(res.clone(), f_inverse.clone());
                res = wires2;
                circuit_metrics += gc;
            }
        }
    }
    (res, circuit_metrics)
}

pub fn cyclotomic_exp_fast_inverse_evaluate_montgomery_fast(f: Wires) -> (Wires, CircuitMetrics) {
    let mut res = Fq12::wires_set_montgomery(ark_bn254::Fq12::ONE);
    let mut circuit_metrics = CircuitMetrics::zero();
    let (f_inverse, gc) = (
        Fq12::wires_set_montgomery(Fq12::from_montgomery_wires(f.clone()).inverse().unwrap()),
        CircuitMetrics::fq12_inverse_montgomery(),
    ); //Fq12::inverse(res.clone());
    circuit_metrics += gc;
    let mut found_nonzero = false;
    for value in ark_ff::biginteger::arithmetic::find_naf(ark_bn254::Config::X)
        .into_iter()
        .rev()
    {
        if found_nonzero {
            let (wires1, gc) = (
                Fq12::wires_set_montgomery(Fq12::from_montgomery_wires(res.clone()).square()),
                CircuitMetrics::fq12_cyclotomic_square_montgomery(),
            ); //Fq12::square_evaluate_montgomery(res.clone());
            res = wires1;
            circuit_metrics += gc;
        }

        if value != 0 {
            found_nonzero = true;

            if value > 0 {
                let (wires2, gc) = (
                    Fq12::wires_set_montgomery(
                        Fq12::from_montgomery_wires(res.clone())
                            * Fq12::from_montgomery_wires(f.clone()),
                    ),
                    CircuitMetrics::fq12_mul_montgomery(),
                ); // Fq12::mul_evaluate_montgomery(res.clone(), f.clone());
                res = wires2;
                circuit_metrics += gc;
            } else {
                let (wires2, gc) = (
                    Fq12::wires_set_montgomery(
                        Fq12::from_montgomery_wires(res.clone())
                            * Fq12::from_montgomery_wires(f_inverse.clone()),
                    ),
                    CircuitMetrics::fq12_mul_montgomery(),
                ); // Fq12::mul_evaluate_montgomery(res.clone(), f_inverse.clone());
                res = wires2;
                circuit_metrics += gc;
            }
        }
    }
    (res, circuit_metrics)
}

pub fn exp_by_neg_x(f: ark_bn254::Fq12) -> ark_bn254::Fq12 {
    conjugate(cyclotomic_exp(f))
}

pub fn exp_by_neg_x_evaluate(f: Wires) -> (Wires, CircuitMetrics) {
    let mut circuit_metrics = CircuitMetrics::zero();
    let (f2, gc) = cyclotomic_exp_fast_inverse_evaluate_fast(f);
    circuit_metrics += gc;
    let (f3, gc) = Fq12::conjugate_evaluate(f2);
    circuit_metrics += gc;
    (f3, circuit_metrics)
}

pub fn exp_by_neg_x_evaluate_montgomery(f: Wires) -> (Wires, CircuitMetrics) {
    let mut circuit_metrics = CircuitMetrics::zero();
    let (f2, gc) = cyclotomic_exp_fast_inverse_evaluate_montgomery_fast(f);
    circuit_metrics += gc;
    let (f3, gc) = Fq12::conjugate_evaluate(f2);
    circuit_metrics += gc;
    (f3, circuit_metrics)
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

pub fn final_exponentiation_evaluate_fast(f: Wires) -> (Wires, CircuitMetrics) {
    let mut circuit_metrics = CircuitMetrics::zero();
    let (f_inv, gc) = (
        Fq12::wires_set(Fq12::from_wires(f.clone()).inverse().unwrap()),
        CircuitMetrics::fq12_inverse(),
    );
    circuit_metrics += gc;
    let (f_conjugate, gc) = Fq12::conjugate_evaluate(f.clone());
    circuit_metrics += gc;
    let (u, gc) = (
        Fq12::wires_set(Fq12::from_wires(f_inv) * Fq12::from_wires(f_conjugate)),
        CircuitMetrics::fq12_mul(),
    ); // Fq12::mul_evaluate(f_inv, f_conjugate);
    circuit_metrics += gc;
    let (u_frobenius, gc) = Fq12::frobenius_evaluate(u.clone(), 2);
    circuit_metrics += gc;
    let (r, gc) = (
        Fq12::wires_set(Fq12::from_wires(u_frobenius) * Fq12::from_wires(u.clone())),
        CircuitMetrics::fq12_mul(),
    ); // Fq12::mul_evaluate(u_frobenius, u.clone());
    circuit_metrics += gc;
    let (y0, gc) = exp_by_neg_x_evaluate(r.clone());
    circuit_metrics += gc;
    let (y1, gc) = (
        Fq12::wires_set(Fq12::from_wires(y0).square()),
        CircuitMetrics::fq12_square(),
    ); // Fq12::square_evaluate(y0);
    circuit_metrics += gc;
    let (y2, gc) = (
        Fq12::wires_set(Fq12::from_wires(y1.clone()).square()),
        CircuitMetrics::fq12_square(),
    ); // Fq12::square_evaluate(y1.clone());
    circuit_metrics += gc;
    let (y3, gc) = (
        Fq12::wires_set(Fq12::from_wires(y1.clone()) * Fq12::from_wires(y2)),
        CircuitMetrics::fq12_mul(),
    ); // Fq12::mul_evaluate(y1.clone(), y2);
    circuit_metrics += gc;
    let (y4, gc) = exp_by_neg_x_evaluate(y3.clone());
    circuit_metrics += gc;
    let (y5, gc) = (
        Fq12::wires_set(Fq12::from_wires(y4.clone()).square()),
        CircuitMetrics::fq12_square(),
    ); // Fq12::square_evaluate(y4.clone());
    circuit_metrics += gc;
    let (y6, gc) = exp_by_neg_x_evaluate(y5);
    circuit_metrics += gc;
    let (y7, gc) = Fq12::conjugate_evaluate(y3);
    circuit_metrics += gc;
    let (y8, gc) = Fq12::conjugate_evaluate(y6);
    circuit_metrics += gc;
    let (y9, gc) = (
        Fq12::wires_set(Fq12::from_wires(y8) * Fq12::from_wires(y4.clone())),
        CircuitMetrics::fq12_mul(),
    ); // Fq12::mul_evaluate(y8, y4.clone());
    circuit_metrics += gc;
    let (y10, gc) = (
        Fq12::wires_set(Fq12::from_wires(y9) * Fq12::from_wires(y7)),
        CircuitMetrics::fq12_mul(),
    ); // Fq12::mul_evaluate(y9, y7);
    circuit_metrics += gc;
    let (y11, gc) = (
        Fq12::wires_set(Fq12::from_wires(y10.clone()) * Fq12::from_wires(y1)),
        CircuitMetrics::fq12_mul(),
    ); // Fq12::mul_evaluate(y10.clone(), y1);
    circuit_metrics += gc;
    let (y12, gc) = (
        Fq12::wires_set(Fq12::from_wires(y10.clone()) * Fq12::from_wires(y4)),
        CircuitMetrics::fq12_mul(),
    ); // Fq12::mul_evaluate(y10.clone(), y4);
    circuit_metrics += gc;
    let (y13, gc) = (
        Fq12::wires_set(Fq12::from_wires(y12) * Fq12::from_wires(r.clone())),
        CircuitMetrics::fq12_mul(),
    ); // Fq12::mul_evaluate(y12, r.clone());
    circuit_metrics += gc;
    let (y14, gc) = Fq12::frobenius_evaluate(y11.clone(), 1);
    circuit_metrics += gc;
    let (y15, gc) = (
        Fq12::wires_set(Fq12::from_wires(y14) * Fq12::from_wires(y13)),
        CircuitMetrics::fq12_mul(),
    ); // Fq12::mul_evaluate(y14, y13);
    circuit_metrics += gc;
    let (y16, gc) = Fq12::frobenius_evaluate(y10, 2);
    circuit_metrics += gc;
    let (y17, gc) = (
        Fq12::wires_set(Fq12::from_wires(y16) * Fq12::from_wires(y15)),
        CircuitMetrics::fq12_mul(),
    ); // Fq12::mul_evaluate(y16, y15);
    circuit_metrics += gc;
    let (r2, gc) = Fq12::conjugate_evaluate(r);
    circuit_metrics += gc;
    let (y18, gc) = (
        Fq12::wires_set(Fq12::from_wires(r2) * Fq12::from_wires(y11)),
        CircuitMetrics::fq12_mul(),
    ); // Fq12::mul_evaluate(r2, y11);
    circuit_metrics += gc;
    let (y19, gc) = Fq12::frobenius_evaluate(y18, 3);
    circuit_metrics += gc;
    let (y20, gc) = (
        Fq12::wires_set(Fq12::from_wires(y19) * Fq12::from_wires(y17)),
        CircuitMetrics::fq12_mul(),
    ); // Fq12::mul_evaluate(y19, y17);
    circuit_metrics += gc;
    (y20, circuit_metrics)
}

pub fn final_exponentiation_evaluate_montgomery_fast(f: Wires) -> (Wires, CircuitMetrics) {
    let mut circuit_metrics = CircuitMetrics::zero();
    let (f_inv, gc) = (
        Fq12::wires_set_montgomery(Fq12::from_montgomery_wires(f.clone()).inverse().unwrap()),
        CircuitMetrics::fq12_inverse_montgomery(),
    );
    circuit_metrics += gc;
    let (f_conjugate, gc) = Fq12::conjugate_evaluate(f.clone());
    circuit_metrics += gc;
    let (u, gc) = (
        Fq12::wires_set_montgomery(
            Fq12::from_montgomery_wires(f_inv) * Fq12::from_montgomery_wires(f_conjugate),
        ),
        CircuitMetrics::fq12_mul_montgomery(),
    ); // Fq12::mul_evaluate_montgomery(f_inv, f_conjugate);
    circuit_metrics += gc;
    let (u_frobenius, gc) = Fq12::frobenius_evaluate_montgomery(u.clone(), 2);
    circuit_metrics += gc;
    let (r, gc) = (
        Fq12::wires_set_montgomery(
            Fq12::from_montgomery_wires(u_frobenius) * Fq12::from_montgomery_wires(u.clone()),
        ),
        CircuitMetrics::fq12_mul_montgomery(),
    ); // Fq12::mul_evaluate_montgomery(u_frobenius, u.clone());
    circuit_metrics += gc;
    let (y0, gc) = exp_by_neg_x_evaluate_montgomery(r.clone());
    circuit_metrics += gc;
    let (y1, gc) = (
        Fq12::wires_set_montgomery(Fq12::from_montgomery_wires(y0).square()),
        CircuitMetrics::fq12_square_montgomery(),
    ); // Fq12::square_evaluate_montgomery(y0);
    circuit_metrics += gc;
    let (y2, gc) = (
        Fq12::wires_set_montgomery(Fq12::from_montgomery_wires(y1.clone()).square()),
        CircuitMetrics::fq12_square_montgomery(),
    ); // Fq12::square_evaluate_montgomery(y1.clone());
    circuit_metrics += gc;
    let (y3, gc) = (
        Fq12::wires_set_montgomery(
            Fq12::from_montgomery_wires(y1.clone()) * Fq12::from_montgomery_wires(y2),
        ),
        CircuitMetrics::fq12_mul_montgomery(),
    ); // Fq12::mul_evaluate_montgomery(y1.clone(), y2);
    circuit_metrics += gc;
    let (y4, gc) = exp_by_neg_x_evaluate_montgomery(y3.clone());
    circuit_metrics += gc;
    let (y5, gc) = (
        Fq12::wires_set_montgomery(Fq12::from_montgomery_wires(y4.clone()).square()),
        CircuitMetrics::fq12_square_montgomery(),
    ); // Fq12::square_evaluate_montgomery(y4.clone());
    circuit_metrics += gc;
    let (y6, gc) = exp_by_neg_x_evaluate_montgomery(y5);
    circuit_metrics += gc;
    let (y7, gc) = Fq12::conjugate_evaluate(y3);
    circuit_metrics += gc;
    let (y8, gc) = Fq12::conjugate_evaluate(y6);
    circuit_metrics += gc;
    let (y9, gc) = (
        Fq12::wires_set_montgomery(
            Fq12::from_montgomery_wires(y8) * Fq12::from_montgomery_wires(y4.clone()),
        ),
        CircuitMetrics::fq12_mul_montgomery(),
    ); // Fq12::mul_evaluate_montgomery(y8, y4.clone());
    circuit_metrics += gc;
    let (y10, gc) = (
        Fq12::wires_set_montgomery(
            Fq12::from_montgomery_wires(y9) * Fq12::from_montgomery_wires(y7),
        ),
        CircuitMetrics::fq12_mul_montgomery(),
    ); // Fq12::mul_evaluate_montgomery(y9, y7);
    circuit_metrics += gc;
    let (y11, gc) = (
        Fq12::wires_set_montgomery(
            Fq12::from_montgomery_wires(y10.clone()) * Fq12::from_montgomery_wires(y1),
        ),
        CircuitMetrics::fq12_mul_montgomery(),
    ); // Fq12::mul_evaluate_montgomery(y10.clone(), y1);
    circuit_metrics += gc;
    let (y12, gc) = (
        Fq12::wires_set_montgomery(
            Fq12::from_montgomery_wires(y10.clone()) * Fq12::from_montgomery_wires(y4),
        ),
        CircuitMetrics::fq12_mul_montgomery(),
    ); // Fq12::mul_evaluate_montgomery(y10.clone(), y4);
    circuit_metrics += gc;
    let (y13, gc) = (
        Fq12::wires_set_montgomery(
            Fq12::from_montgomery_wires(y12) * Fq12::from_montgomery_wires(r.clone()),
        ),
        CircuitMetrics::fq12_mul_montgomery(),
    ); // Fq12::mul_evaluate_montgomery(y12, r.clone());
    circuit_metrics += gc;
    let (y14, gc) = Fq12::frobenius_evaluate_montgomery(y11.clone(), 1);
    circuit_metrics += gc;
    let (y15, gc) = (
        Fq12::wires_set_montgomery(
            Fq12::from_montgomery_wires(y14) * Fq12::from_montgomery_wires(y13),
        ),
        CircuitMetrics::fq12_mul_montgomery(),
    ); // Fq12::mul_evaluate_montgomery(y14, y13);
    circuit_metrics += gc;
    let (y16, gc) = Fq12::frobenius_evaluate_montgomery(y10, 2);
    circuit_metrics += gc;
    let (y17, gc) = (
        Fq12::wires_set_montgomery(
            Fq12::from_montgomery_wires(y16) * Fq12::from_montgomery_wires(y15),
        ),
        CircuitMetrics::fq12_mul_montgomery(),
    ); // Fq12::mul_evaluate_montgomery(y16, y15);
    circuit_metrics += gc;
    let (r2, gc) = Fq12::conjugate_evaluate(r);
    circuit_metrics += gc;
    let (y18, gc) = (
        Fq12::wires_set_montgomery(
            Fq12::from_montgomery_wires(r2) * Fq12::from_montgomery_wires(y11),
        ),
        CircuitMetrics::fq12_mul_montgomery(),
    ); // Fq12::mul_evaluate_montgomery(r2, y11);
    circuit_metrics += gc;
    let (y19, gc) = Fq12::frobenius_evaluate_montgomery(y18, 3);
    circuit_metrics += gc;
    let (y20, gc) = (
        Fq12::wires_set_montgomery(
            Fq12::from_montgomery_wires(y19) * Fq12::from_montgomery_wires(y17),
        ),
        CircuitMetrics::fq12_mul_montgomery(),
    ); // Fq12::mul_evaluate_montgomery(y19, y17);
    circuit_metrics += gc;
    (y20, circuit_metrics)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::circuits::bn254::{
        finalexp::{
            cyclotomic_exp, cyclotomic_exp_evaluate_fast, cyclotomic_exp_evaluate_montgomery_fast,
            cyclotomic_exp_fast_inverse_evaluate_fast,
            cyclotomic_exp_fast_inverse_evaluate_montgomery_fast, cyclotomic_exp_fastinv,
            final_exponentiation, final_exponentiation_evaluate_fast,
            final_exponentiation_evaluate_montgomery_fast,
        },
        fp254impl::Fp254Impl,
        fq::Fq,
        fq12::Fq12,
    };
    use ark_ec::{
        bn::BnConfig,
        pairing::{MillerLoopOutput, Pairing},
    };
    use ark_ff::{CyclotomicMultSubgroup, Field, UniformRand};
    use ark_std::rand::SeedableRng;
    use num_bigint::BigUint;
    use rand_chacha::ChaCha20Rng;

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
    fn test_cyclotomic_exp_evaluate_fast() {
        let p = Fq::modulus_as_biguint();
        let u = (p.pow(6) - BigUint::from_str("1").unwrap())
            * (p.pow(2) + BigUint::from_str("1").unwrap());
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let cyclotomic_f = f.pow(u.to_u64_digits());
        let c = cyclotomic_f.cyclotomic_exp(ark_bn254::Config::X);
        let (d, circuit_metrics) = cyclotomic_exp_evaluate_fast(Fq12::wires_set(cyclotomic_f));
        circuit_metrics.print();
        assert_eq!(c, Fq12::from_wires(d));
    }

    #[test]
    fn test_cyclotomic_exp_evaluate_montgomery_fast() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);

        let c = cyclotomic_exp(f); // f.cyclotomic_exp(ark_bn254::Config::X);
        let (d, circuit_metrics) =
            cyclotomic_exp_evaluate_montgomery_fast(Fq12::wires_set_montgomery(f));
        circuit_metrics.print();
        assert_eq!(c, Fq12::from_montgomery_wires(d));
    }

    #[test]
    fn test_cyclotomic_exp_fast_inverse_evaluate_fast() {
        let p = Fq::modulus_as_biguint();
        let u = (p.pow(6) - BigUint::from_str("1").unwrap())
            * (p.pow(2) + BigUint::from_str("1").unwrap());
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let cyclotomic_f = f.pow(u.to_u64_digits());
        let c = cyclotomic_f.cyclotomic_exp(ark_bn254::Config::X);
        let (d, circuit_metrics) =
            cyclotomic_exp_fast_inverse_evaluate_fast(Fq12::wires_set(cyclotomic_f));
        circuit_metrics.print();
        assert_eq!(c, Fq12::from_wires(d));
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
        let (d, circuit_metrics) = cyclotomic_exp_fast_inverse_evaluate_montgomery_fast(
            Fq12::wires_set_montgomery(cyclotomic_f),
        );
        circuit_metrics.print();
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
    fn test_final_exponentiation_evaluate_fast() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);

        let c = ark_bn254::Bn254::final_exponentiation(MillerLoopOutput(f))
            .unwrap()
            .0;
        let (d, circuit_metrics) = final_exponentiation_evaluate_fast(Fq12::wires_set(f));
        circuit_metrics.print();

        assert_eq!(Fq12::from_wires(d), c);
    }

    #[test]
    fn test_final_exponentiation_evaluate_montgomery_fast() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);

        let c = ark_bn254::Bn254::final_exponentiation(MillerLoopOutput(f))
            .unwrap()
            .0;
        let (d, circuit_metrics) =
            final_exponentiation_evaluate_montgomery_fast(Fq12::wires_set_montgomery(f));
        circuit_metrics.print();

        assert_eq!(Fq12::from_montgomery_wires(d), c);
    }
}
