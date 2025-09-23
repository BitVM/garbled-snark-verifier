pub mod adaptor_sigs;
pub mod vsss;

#[cfg(test)]
mod tests {
    use ark_ff::PrimeField;
    use ark_secp256k1::Fr;
    use bitcoin::{TapSighash, hashes::Hash};
    use k256::schnorr::{Signature as KSig, SigningKey, VerifyingKey};
    use rand::prelude::IteratorRandom;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::cac::{adaptor_sigs::AdaptorInfo, vsss::lagrange_interpolate_at_index};

    #[test]
    fn test_full_flow() {
        let n = 181;
        let k = 181 - 7;

        let mut rng = rand::thread_rng();

        // step 1: garbler generates secret:
        let polynomial = vsss::Polynomial::rand(&mut rng, k);

        // step 2: garbler send commitments to the polynomial coefficients to the evaluator
        let coefficient_commits = polynomial.coefficient_commits();

        // step 3: garbler shares commits, sends them to evaluator
        let share_commits = polynomial.share_commits(n);

        // step 4: evaluator verifies correctness of the share commits:
        share_commits
            .verify(&coefficient_commits)
            .expect("Share commit verification failed");

        // step 5: evaluator chooses k indices at random from range is 0..n
        let selected_indices = (0..n).choose_multiple(&mut rand::thread_rng(), k);

        // step 6: for each index i select, garbler sends share_i to the evaluator
        let all_shares = polynomial.shares(n);
        let selected_shares = selected_indices
            .iter()
            .map(|i| all_shares[*i])
            .collect::<Vec<_>>();

        // step 7: evaluator checks that the selected shares match the share commits
        share_commits
            .verify_shares(&selected_shares)
            .expect("Share verification failed");

        // step 8: (omitted) evaluator checks the garbled circuit validity

        // step 9: one of the unselected share commits is chosen. Any will do. We just use the first unused one.
        let unused_share_commit = share_commits
            .0
            .iter()
            .enumerate()
            .find(|(i, _)| !selected_indices.contains(i))
            .unwrap();
        let unused_share_secret = polynomial
            .shares(n)
            .iter()
            .find(|(i, _)| i == &unused_share_commit.0)
            .unwrap()
            .1;

        // step 10: evaluator sets up adaptor and sends to garbler
        let evaluator_privkey = SigningKey::random(&mut rand::thread_rng());

        let mut sk_bytes = evaluator_privkey.to_bytes().to_vec();
        sk_bytes.reverse();

        let evaluator_secret_fr = Fr::from_le_bytes_mod_order(&sk_bytes);
        let sighash =
            TapSighash::from_byte_array(Sha256::digest(b"some message").into()).to_byte_array();

        let mut rng = rand::thread_rng();

        let adaptor = AdaptorInfo::new(
            &evaluator_secret_fr,
            *unused_share_commit.1,
            &sighash,
            &mut rng,
        );

        // step 11: garbler signs the adaptor, submits on-chain
        let garbler_sig = adaptor.garbler_signature(&unused_share_secret);
        let verifying_key: VerifyingKey = *evaluator_privkey.verifying_key();
        let ksig = KSig::try_from(garbler_sig.as_slice()).expect("valid sig");
        verifying_key
            .verify_raw(&sighash, &ksig)
            .expect("signature should be valid");

        // step 12: evaluator monitors chain, extracts the garbler secret from the signature
        let secrets_share = adaptor.extract_secret(&garbler_sig);
        assert_eq!(secrets_share, Ok(unused_share_secret));

        // step 13: evaluator can now use the newly revealed share, together with the previously revealed ones,
        // to reconstruct any missing shares.
        let combined_shares = [
            &selected_shares[..],
            &[(unused_share_commit.0, unused_share_secret)],
        ]
        .concat();
        let missing_shares = (0..n)
            .filter(|&i| combined_shares.iter().all(|(j, _)| i != *j))
            .map(|i| (i, lagrange_interpolate_at_index(&combined_shares, i)))
            .collect::<Vec<_>>();

        for share in missing_shares {
            assert_eq!(share, all_shares[share.0]);
        }
    }
}
