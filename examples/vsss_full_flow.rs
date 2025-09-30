use ark_ff::PrimeField;
use ark_secp256k1::Fr;
use bitcoin::{TapSighash, hashes::Hash};
use garbled_snark_verifier::cut_and_choose::soldering::{
    adaptor_sigs::AdaptorInfo,
    vsss::{Polynomial, Secp256k1, lagrange_interpolate_whole_polynomial},
};
use k256::schnorr::{Signature as KSig, SigningKey, VerifyingKey};
use rand::{prelude::IteratorRandom, thread_rng};
use rayon::prelude::*;
use sha2::{Digest, Sha256};

const TOTAL_SHARES: usize = 181;
const DEGREE: usize = TOTAL_SHARES - 7;

fn main() {
    let num_polynomials = 1273;

    (0..num_polynomials)
        .into_par_iter()
        .map(run_full_flow)
        .try_for_each(|res| res)
        .expect("full flow should succeed for all polynomials");

    println!(
        "Completed full cut-and-choose flow for {num_polynomials} polynomial(s) of degree {DEGREE}."
    );
}

fn run_full_flow(polynomial_idx: usize) -> Result<(), String> {
    let secp = Secp256k1::new();

    // Garbler picks a random polynomial of degree 174 (181 - 7).
    let polynomial = Polynomial::rand(thread_rng(), DEGREE);

    // Commit to coefficients and shares.
    let coefficient_commits = polynomial.coefficient_commits(&secp);
    let share_commits = polynomial.share_commits(&secp, TOTAL_SHARES);
    share_commits.verify(&coefficient_commits).map_err(|err| {
        format!("[{polynomial_idx}] coefficient commit verification failed: {err}")
    })?;

    // Evaluator samples k indices from the share range.
    let selected_indices = (0..TOTAL_SHARES)
        .choose_multiple(&mut thread_rng(), DEGREE)
        .into_iter()
        .collect::<Vec<_>>();

    let all_shares = polynomial.shares(TOTAL_SHARES);
    let selected_shares = selected_indices
        .iter()
        .map(|i| all_shares[*i])
        .collect::<Vec<_>>();

    share_commits
        .verify_shares(&secp, &selected_shares)
        .map_err(|err| format!("[{polynomial_idx}] share verification failed: {err}"))?;

    // Pick one unopened share to use for the adaptor signature round-trip.
    let unused_share_commit = share_commits
        .0
        .iter()
        .enumerate()
        .find(|(i, _)| !selected_indices.contains(i))
        .ok_or_else(|| format!("[{polynomial_idx}] no unopened share found"))?;

    let unused_share_secret = all_shares
        .iter()
        .find(|(i, _)| i == &unused_share_commit.0)
        .map(|(_, share)| *share)
        .ok_or_else(|| format!("[{polynomial_idx}] missing unopened share secret"))?;

    let evaluator_privkey = SigningKey::random(&mut thread_rng());
    let mut sk_bytes = evaluator_privkey.to_bytes().to_vec();
    sk_bytes.reverse();

    let evaluator_secret_fr = Fr::from_le_bytes_mod_order(&sk_bytes);

    let sighash_source = Sha256::digest(format!("cac_polynomial:{polynomial_idx}").as_bytes());
    let sighash = TapSighash::from_byte_array(sighash_source.into()).to_byte_array();

    let adaptor = AdaptorInfo::new(
        &evaluator_secret_fr,
        *unused_share_commit.1,
        &sighash,
        &mut thread_rng(),
    );

    let garbler_sig = adaptor.garbler_signature(&unused_share_secret);
    let verifying_key: VerifyingKey = *evaluator_privkey.verifying_key();
    let ksig = KSig::try_from(garbler_sig.as_slice())
        .map_err(|_| format!("[{polynomial_idx}] invalid schnorr signature bytes"))?;
    verifying_key.verify_raw(&sighash, &ksig).map_err(|err| {
        format!("[{polynomial_idx}] adaptor signature verification failed: {err}")
    })?;

    let extracted = adaptor
        .extract_secret(&garbler_sig)
        .map_err(|err| format!("[{polynomial_idx}] failed to extract secret: {err}"))?;
    if extracted != unused_share_secret {
        return Err(format!("[{polynomial_idx}] adaptor extracted wrong secret"));
    }

    let mut combined_shares = selected_shares;
    combined_shares.push((unused_share_commit.0, unused_share_secret));

    let missing_points = (0..TOTAL_SHARES)
        .filter(|i| combined_shares.iter().all(|(j, _)| j != i))
        .collect::<Vec<_>>();

    let reconstructed = lagrange_interpolate_whole_polynomial(&combined_shares, &missing_points);

    for (missing_idx, value) in missing_points.into_iter().zip(reconstructed.into_iter()) {
        let (expected_idx, expected_value) = all_shares[missing_idx];
        debug_assert_eq!(missing_idx, expected_idx);
        if value != expected_value {
            return Err(format!(
                "[{polynomial_idx}] reconstructed share mismatch at index {missing_idx}"
            ));
        }
    }

    Ok(())
}
