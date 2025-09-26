use std::ops::{Add, Mul};

use ark_ec::{PrimeGroup, scalar_mul::BatchMulPreprocessing};
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_ff::{Field, One, UniformRand, Zero};
use ark_secp256k1::{Fr, Projective};
use rand::Rng;
use serde::{Deserialize, Serialize};

pub struct Secp256k1 {
    pub generator: BatchMulPreprocessing<Projective>,
}

impl Default for Secp256k1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Secp256k1 {
    pub fn new() -> Self {
        // 181*176*3 is roughly the number of generator multiplications we do
        Self {
            generator: BatchMulPreprocessing::new(Projective::generator(), 181 * 176 * 3),
        }
    }

    // Replacement of BatchMulPreprocessing::batch_mul, which (1) uses rayon parallization
    // and (2) converts the result to an affine point instead of a projective point.
    fn generator_batch_mul(&self, scalars: &[Fr]) -> Vec<Projective> {
        scalars.iter().map(|e| self.windowed_mul(e)).collect()
    }

    // copied from ark-ec/src/scalar_mul/mod.rs because it's not public
    fn windowed_mul(&self, scalar: &Fr) -> Projective {
        let outerc = self
            .generator
            .max_scalar_size
            .div_ceil(self.generator.window);
        let modulus_size = Fr::MODULUS_BIT_SIZE as usize;
        let scalar_val = scalar.into_bigint().to_bits_le();

        let mut res = Projective::from(self.generator.table[0][0]);
        for outer in 0..outerc {
            let mut inner = 0usize;
            for i in 0..self.generator.window {
                if outer * self.generator.window + i < modulus_size
                    && scalar_val[outer * self.generator.window + i]
                {
                    inner |= 1 << i;
                }
            }
            res += &self.generator.table[outer][inner];
        }
        res
    }
}

// we use this for both polynomials over scalars and over projective points
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Polynomial<T>(Vec<T>);

impl<T> Polynomial<T>
where
    for<'a> T: Add<T, Output = T> + Mul<&'a Fr, Output = T> + Clone,
{
    // todo: max x an int
    fn eval_at(&self, x: Fr) -> T {
        // Horner's method
        let mut iter = self.0.iter().rev();
        let mut acc = iter
            .next()
            .expect("polynomial must have at least one coefficient")
            .clone();
        for coeff in iter {
            acc = coeff.clone() + acc * &x;
        }
        acc
    }
}

impl Polynomial<Fr> {
    pub fn rand(mut rand: impl Rng, degree: usize) -> Self {
        Self((0..degree + 1).map(|_| Fr::rand(&mut rand)).collect())
    }

    pub fn coefficient_commits(&self, secp: &Secp256k1) -> PolynomialCommits {
        PolynomialCommits(Polynomial(secp.generator_batch_mul(&self.0)))
    }

    // shares are return with 0-based index. However, we evaluate share i at
    // x = i+1, since the value at x=0 represents the secret
    pub fn shares(&self, num_shares: usize) -> Vec<(usize, Fr)> {
        (0..num_shares)
            .map(|i| (i, self.eval_at(Fr::from((i + 1) as u64))))
            .collect()
    }

    pub fn share_commits(&self, secp: &Secp256k1, num_shares: usize) -> ShareCommits {
        let shares = self
            .shares(num_shares)
            .into_iter()
            .map(|(_, share)| share)
            .collect::<Vec<_>>();
        let commits = secp.generator_batch_mul(&shares);
        ShareCommits(commits)
    }
}

#[derive(Clone, Debug)]
pub struct PolynomialCommits(Polynomial<Projective>);

#[derive(Clone, Debug)]
pub struct ShareCommits(pub Vec<Projective>);

impl ShareCommits {
    pub fn verify(&self, polynomial_commits: &PolynomialCommits) -> Result<(), String> {
        for (i, share_commit) in self.0.iter().enumerate() {
            let recomputed_share_commit = polynomial_commits.0.eval_at(Fr::from((i + 1) as u64));

            if share_commit != &recomputed_share_commit {
                return Err("Share commit verification failed".to_owned());
            }
        }
        Ok(())
    }

    pub fn verify_shares(&self, secp: &Secp256k1, shares: &[(usize, Fr)]) -> Result<(), String> {
        let mut indices = shares.iter().map(|(i, _)| *i).collect::<Vec<_>>();
        indices.sort_unstable();
        if indices.windows(2).any(|arr| arr[0] == arr[1]) {
            return Err("Duplicate share index found".to_owned());
        }

        let (indices, shares): (Vec<_>, Vec<_>) = shares.iter().copied().unzip();
        let recomputed_commits = secp.generator_batch_mul(&shares);
        for (index, recomputed_commit) in indices.iter().zip(recomputed_commits.into_iter()) {
            let share_commit = self
                .0
                .get(*index)
                .ok_or("Share index out of bounds".to_owned())?;

            if *share_commit != recomputed_commit {
                return Err("Share verification failed".to_owned());
            }
        }

        Ok(())
    }
}

// find the missing point by using the Lagrange interpolation, see https://en.wikipedia.org/wiki/Lagrange_polynomial
// Input is a vec of (index, value), where index is 0-based
pub fn lagrange_interpolate_at_index(points: &[(usize, Fr)], index: usize) -> Fr {
    lagrange_interpolate_at_x(points, Fr::from((index + 1) as u64))
}

// internal function that allows also queying g(0)
fn lagrange_interpolate_at_x(points: &[(usize, Fr)], x: Fr) -> Fr {
    let sc = |val: usize| Fr::from(val as u64);
    points
        .iter()
        .enumerate()
        .fold(Fr::zero(), |result, (i, (idx, y_i))| {
            let x_i = sc(*idx + 1); // share 0 corresponds to x=1
            // Compute L_i(x)
            let (num, denum) = points.iter().enumerate().filter(|(j, _)| *j != i).fold(
                (Fr::one(), Fr::one()),
                |(num, denum), (_, (idx, _))| {
                    let x_j = sc(*idx + 1); // share 0 corresponds to x=1

                    (num * (x - x_j), denum * (x_i - x_j))
                },
            );

            // calculate li = num / denum = num * denum^{-1}
            let denum_inv = denum.inverse().expect("x_i - x_j must be nonzero");
            let li = num * denum_inv;

            result + *y_i * li
        })
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use ark_ec::ScalarMul;

    use super::*;

    #[test]
    fn test_polynomial_eval() {
        let polynomial = Polynomial::<Fr>::rand(rand::thread_rng(), 2);

        match polynomial.0.as_slice() {
            &[a, b, c] => {
                let x = Fr::rand(&mut rand::thread_rng());
                assert_eq!(polynomial.eval_at(x), a + b * x + c * x * x);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_interpolation_from_coefficients() {
        let polynomial_degree = 3;
        let polynomial = Polynomial::rand(rand::thread_rng(), polynomial_degree);

        let num_shares = polynomial_degree + 1;
        let points = polynomial.shares(num_shares);

        let secret = lagrange_interpolate_at_x(&points, Fr::zero());

        assert_eq!(secret, polynomial.0[0]);
    }

    #[test]
    fn test_interpolate_missing_shares() {
        let polynomial_degree = 3;
        let polynomial = Polynomial::rand(rand::thread_rng(), polynomial_degree);
        let points = polynomial.shares(6);
        let selected_points = &points[..polynomial_degree + 1];
        let missing_points = &points[polynomial_degree + 1..];

        for (i, share) in missing_points.iter() {
            let reconstructed = lagrange_interpolate_at_index(selected_points, *i);
            assert_eq!(reconstructed, *share);
        }
    }

    #[test]
    fn test_commit_verification() {
        let polynomial_degree = 3;

        let secp = Secp256k1::new();

        let polynomial = Polynomial::rand(rand::thread_rng(), polynomial_degree);

        let num_shares = polynomial_degree + 1;
        let poly_commits = polynomial.coefficient_commits(&secp);
        let share_commits = polynomial.share_commits(&secp, num_shares);

        share_commits.verify(&poly_commits).unwrap();

        let shares = polynomial.shares(num_shares);
        share_commits.verify_shares(&secp, &shares).unwrap();
    }

    #[test]
    fn test_batch_mul() {
        let time_start = Instant::now();
        let secp = Secp256k1::new();
        println!(
            "secp256k1 precalculation time: {:?}",
            Instant::now() - time_start
        );

        let approx_size = secp.generator.table.iter().map(|x| x.len()).sum::<usize>()
            * std::mem::size_of::<<Projective as ScalarMul>::MulBase>();
        println!("approx_size: {:?}", approx_size);

        let coeffs = (0..174)
            .map(|_| Fr::rand(&mut rand::thread_rng()))
            .collect::<Vec<_>>();

        let time_start = Instant::now();
        let vals_batched = secp.generator_batch_mul(&coeffs);
        println!("batch_mul time: {:?}", Instant::now() - time_start);

        let generator = Projective::generator();
        let time_start = Instant::now();
        let vals_unbatched = coeffs.iter().map(|c| generator * c).collect::<Vec<_>>();
        println!("unbatched time: {:?}", Instant::now() - time_start);

        assert_eq!(vals_batched, vals_unbatched);
    }
}
