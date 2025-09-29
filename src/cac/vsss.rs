use std::ops::{Add, Mul};

use ark_ec::PrimeGroup;
use ark_ff::{Field, One, UniformRand, Zero};
use ark_secp256k1::{Fr, Projective};
use rand::Rng;
use serde::{Deserialize, Serialize};

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

    pub fn coefficient_commits(&self) -> PolynomialCommits {
        let generator = Projective::generator();
        PolynomialCommits(Polynomial(self.0.iter().map(|x| generator * x).collect()))
    }

    // shares are return with 0-based index. However, we evaluate share i at
    // x = i+1, since the value at x=0 represents the secret
    pub fn shares(&self, num_shares: usize) -> Vec<(usize, Fr)> {
        (0..num_shares)
            .map(|i| (i, self.eval_at(Fr::from((i + 1) as u64))))
            .collect()
    }

    pub fn share_commits(&self, num_shares: usize) -> ShareCommits {
        ShareCommits(
            self.shares(num_shares)
                .into_iter()
                .map(|(_, share)| Projective::generator() * share)
                .collect(),
        )
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

    pub fn verify_shares(&self, shares: &[(usize, Fr)]) -> Result<(), String> {
        let mut indices = shares.iter().map(|(i, _)| *i).collect::<Vec<_>>();
        indices.sort_unstable();
        if indices.windows(2).any(|arr| arr[0] == arr[1]) {
            return Err("Duplicate share index found".to_owned());
        }

        for (i, share) in shares.iter() {
            let share_commit = self
                .0
                .get(*i)
                .ok_or("Share index out of bounds".to_owned())?;

            if *share_commit != Projective::generator() * share {
                return Err("Share verification failed".to_owned());
            }
        }

        Ok(())
    }
}

/// Returns the values of the polynomial defined by known_points at missing_points, in the given order
/// Assumes that points in the two sets are disjoint and their union is set of natural numbers smaller than < n (including 0) for n = len(known_points) + len(missing_points)
/// Uses the fact that the number of missing points will be small compared to the known ones to evalute polynomials with factorials
/// so, assuming field inversion and multiplication complexity are I and M, total complexity is O(I + len(missing_points) * n * M)
pub fn lagrange_interpolate_whole_polynomial(
    known_points: &[(usize, Fr)],
    missing_points: &[usize],
) -> Vec<Fr> {
    assert!(!known_points.is_empty() || !missing_points.is_empty());

    let n = known_points.len() + missing_points.len();
    let factorial: Vec<Fr> = std::iter::once(Fr::one())
        .chain((1..n).scan(Fr::one(), |state, i| {
            *state *= Fr::from(i as u64);
            Some(*state)
        }))
        .collect();

    // inv_fact[i] = 1 / factorial[i]
    let inv_factorial: Vec<Fr> = (0..n)
        .rev()
        .scan(
            factorial[n - 1]
                .inverse()
                .expect("This is guaranteed to be non-zero"),
            |cur_state, i| {
                let ith_value = *cur_state;
                *cur_state *= Fr::from(i as u64);
                Some(ith_value)
            },
        )
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();

    let inv: Vec<Fr> = (0..n)
        .map(|i| {
            if i == 0 {
                Fr::zero() //This should never be used
            } else {
                inv_factorial[i] * factorial[i - 1]
            }
        })
        .collect();

    // For x, calculates the multiplication of (x - i) for all i in known_points (known_points = 0..n \ missing_points)
    // returns the inverse of the multiplication result, based on the parameter
    let get_coeff = |x: usize, is_inverse: bool| {
        // corner case checks for 0 and n - 1 are not needed since inv_factorial[0] = factorial[0] = 1
        let mut result: Fr = if is_inverse {
            inv_factorial[x] * inv_factorial[n - 1 - x]
        } else {
            factorial[x] * factorial[n - 1 - x]
        };
        if (n - x).is_multiple_of(2) {
            result *= -Fr::one();
        }
        for i in missing_points {
            if *i == x {
                continue;
            };
            result *= if is_inverse {
                Fr::from(x as i64 - *i as i64)
            } else if *i < x {
                inv[x - *i]
            } else {
                -inv[*i - x]
            }
        }
        result
    };

    let lagrange_basis_polynomial_coeffs: Vec<(usize, Fr)> = known_points
        .iter()
        .map(|(x, y)| (*x, get_coeff(*x, true) * y))
        .collect();

    missing_points
        .iter()
        .map(|x| {
            let all_differences = get_coeff(*x, false);
            lagrange_basis_polynomial_coeffs
                .iter()
                .fold(Fr::zero(), |result, (i, coeff_i)| {
                    let ith_diff_inv: Fr = if i < x { inv[x - i] } else { -inv[i - x] };
                    result + ith_diff_inv * all_differences * *coeff_i
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, seq::index::sample};
    use rand_chacha::ChaCha20Rng;
    use std::collections::HashSet;
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
    fn test_commit_verification() {
        let polynomial_degree = 3;
        let polynomial = Polynomial::rand(rand::thread_rng(), polynomial_degree);

        let num_shares = polynomial_degree + 1;
        let poly_commits = polynomial.coefficient_commits();
        let share_commits = polynomial.share_commits(num_shares);

        share_commits.verify(&poly_commits).unwrap();

        let shares = polynomial.shares(num_shares);
        share_commits.verify_shares(&shares).unwrap();
    }

    #[test]
    fn test_interpolation() {
        for (n_revealed, n_hidden) in vec![(5usize, 2usize), (100, 10), (175, 7)] {
            // Assumes one of the revealed ones is 0, as it will be in application, includes it in the n_revealed ones
            let n_total = n_revealed + n_hidden;
            let mut seed_rng = ChaCha20Rng::seed_from_u64(42);
            let hidden_points = sample(&mut seed_rng, n_total, n_hidden)
                .into_vec()
                .into_iter()
                .map(|x| x + 1)
                .collect::<Vec<_>>();
            let polynomial = Polynomial::rand(seed_rng, n_revealed - 1);
            let points = polynomial.shares(n_total); //points[i].0 = i

            let aux_set: HashSet<_> = hidden_points.iter().copied().collect();
            let known_points: Vec<(usize, Fr)> = points
                .clone()
                .into_iter()
                .filter(|(x, _)| !aux_set.contains(x))
                .collect();
            let answer = lagrange_interpolate_whole_polynomial(&known_points, &hidden_points);

            for (x, y) in hidden_points.into_iter().zip(answer.into_iter()) {
                assert_eq!(points[x].1, y);
            }
        }
    }
}
