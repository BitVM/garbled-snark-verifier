use k256::elliptic_curve::PrimeField;
use k256::{ProjectivePoint, Scalar};
use rand;
use std::ops::Add;
use std::ops::Mul;

// we use this for both polynomials over scalars and over projective points
pub struct Polynomial<T>(Vec<T>);

impl<T> Polynomial<T>
where
    T: Add<T, Output = T> + Mul<Scalar, Output = T> + Copy,
{
    // todo: max x an int
    fn eval_at(&self, x: Scalar) -> T {
        self.0
            .iter()
            .skip(1)
            .fold((self.0[0], Scalar::ONE), |(acc, prev_factor), &elem| {
                let new_factor = prev_factor * x;
                (acc + elem * new_factor, new_factor)
            })
            .0
    }
}

impl Polynomial<Scalar> {
    pub fn rand(degree: usize) -> Self {
        Self(
            (0..degree + 1)
                .map(|_| Scalar::generate_vartime(&mut rand::thread_rng()))
                .collect(),
        )
    }
    pub fn coefficient_commits(&self) -> PolynomialCommits {
        PolynomialCommits(Polynomial(
            self.0
                .iter()
                .map(|x| ProjectivePoint::GENERATOR * x)
                .collect(),
        ))
    }
    // shares are return with 0-based index. However, we evaluate share i at
    // x = i+1, since the value at x=0 represents the secret
    pub fn shares(&self, num_shares: usize) -> Vec<(usize, Scalar)> {
        (0..num_shares)
            .map(|i| (i, self.eval_at(Scalar::from_u128((i + 1) as u128))))
            .collect::<Vec<_>>()
    }
    pub fn share_commits(&self, num_shares: usize) -> ShareCommits {
        ShareCommits(
            self.shares(num_shares)
                .into_iter()
                .map(|(_, share)| ProjectivePoint::GENERATOR * share)
                .collect(),
        )
    }
}

pub struct PolynomialCommits(Polynomial<ProjectivePoint>);

pub struct ShareCommits(pub Vec<ProjectivePoint>);
impl ShareCommits {
    pub fn verify(&self, polynomial_commits: &PolynomialCommits) -> Result<(), String> {
        for (i, share_commit) in self.0.iter().enumerate() {
            let recomputed_share_commit = polynomial_commits
                .0
                .eval_at(Scalar::from_u128((i + 1) as u128));
            if share_commit != &recomputed_share_commit {
                return Err("Share commit verification failed".to_string());
            }
        }
        Ok(())
    }

    pub fn verify_shares(&self, shares: &[(usize, Scalar)]) -> Result<(), String> {
        let mut indices = shares.iter().map(|(i, _)| *i).collect::<Vec<_>>();
        indices.sort_unstable();
        if indices.windows(2).any(|arr| arr[0] == arr[1]) {
            return Err("Duplicate share index found".to_string());
        }

        for (i, share) in shares.iter() {
            let share_commit = self
                .0
                .get(*i)
                .ok_or("Share index out of bounds".to_string())?;

            if *share_commit != ProjectivePoint::GENERATOR * share {
                return Err("Share verification failed".to_string());
            }
        }
        Ok(())
    }
}

// find the missing point by using the Lagrange interpolation, see https://en.wikipedia.org/wiki/Lagrange_polynomial
// Input is a vec of (index, value), where index is 0-based
pub fn lagrange_interpolate_at_index(points: &[(usize, Scalar)], index: usize) -> Scalar {
    lagrange_interpolate_at_x(points, Scalar::from_u128((index + 1) as u128))
}

// internal function that allows also queying g(0)
fn lagrange_interpolate_at_x(points: &[(usize, Scalar)], x: Scalar) -> Scalar {
    let scalar = |val: usize| Scalar::from_u128(val as u128);
    points
        .iter()
        .enumerate()
        .fold(Scalar::ZERO, |result, (i, (idx, y_i))| {
            let x_i = scalar(*idx + 1); // share 0 corresponds to x=1
            // Compute L_i(x)
            let (num, denum) = points.iter().enumerate().filter(|(j, _)| *j != i).fold(
                (Scalar::ONE, Scalar::ONE),
                |(num, denum), (_, (idx, _))| {
                    let x_j = scalar(*idx + 1); // share 0 corresponds to x=1

                    (num * (x - x_j), denum * (x_i - x_j))
                },
            );

            // calculate li = num / denum = num * denum^{-1}
            let denum_inv = denum.invert().expect("x_i - x_j must be nonzero");
            let li = num * denum_inv;

            result + *y_i * li
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polynomial_eval() {
        let polynomial = Polynomial::<Scalar>::rand(2);
        match polynomial.0.as_slice() {
            &[a, b, c] => {
                let x = Scalar::generate_vartime(&mut rand::thread_rng());
                assert_eq!(polynomial.eval_at(x), a + b * x + c * x * x);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_interpolation_from_coefficients() {
        let polynomial_degree = 3;
        let polynomial = Polynomial::rand(polynomial_degree);

        let num_shares = polynomial_degree + 1;
        let points = polynomial.shares(num_shares);

        let secret = lagrange_interpolate_at_x(&points, Scalar::ZERO);

        assert_eq!(secret, polynomial.0[0]);
    }

    #[test]
    fn test_interpolate_missing_shares() {
        let polynomial_degree = 3;
        let polynomial = Polynomial::rand(polynomial_degree);
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
        let polynomial = Polynomial::rand(polynomial_degree);

        let num_shares = polynomial_degree + 1;

        let polynomial_commits = polynomial.coefficient_commits();
        let share_commits = polynomial.share_commits(num_shares);
        share_commits.verify(&polynomial_commits).unwrap();
    }
}
