use bitcoin::TapSighash;
use bitcoin::hashes::Hash;
use k256::FieldBytes;
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{
    ProjectivePoint, Scalar,
    schnorr::{Signature, SigningKey, VerifyingKey},
};
use rand;
use sha2::{Digest, Sha256};

pub struct AdaptorInfo {
    garbler_commit: ProjectivePoint,
    evaluator_nonce_commit: ProjectivePoint,
    evaluator_s: Scalar,
    evaluator_pubkey: VerifyingKey,
}

impl AdaptorInfo {
    pub fn new(
        evaluator_privkey: &SigningKey,
        garbler_commit: ProjectivePoint,
        message_hash: &TapSighash,
    ) -> Self {
        let verifying_key = evaluator_privkey.verifying_key();

        let mut nonce = Scalar::generate_vartime(&mut rand::thread_rng());
        let nonce_commit = ProjectivePoint::GENERATOR * nonce;

        let mut public_sum = garbler_commit + nonce_commit;

        // bip-340 requires the pubkey & nonce commit to be even, so we flip if needed.
        // Note that we also need to flip the corresponding private values, i.e. `nonce`
        // here, and the garbler will need to flip their secret value as well.
        if Into::<bool>::into(public_sum.to_affine().y_is_odd()) {
            public_sum = -public_sum;
            nonce = -nonce;
        }

        let public_sum_bytes = *public_sum.to_encoded_point(false).x().unwrap();

        let tag_hash = Sha256::digest(b"BIP0340/challenge");
        let h = Sha256::digest(
            [
                &tag_hash,
                &tag_hash,
                &public_sum_bytes,
                &verifying_key.to_bytes(),
                &message_hash.as_byte_array()[..],
            ]
            .concat(),
        );
        let e = Scalar::from_repr(h).expect("fixed size shouldn't fail");

        let x = evaluator_privkey.as_nonzero_scalar().as_ref();
        let s = nonce + e * x;

        AdaptorInfo {
            evaluator_nonce_commit: nonce_commit,
            garbler_commit,
            evaluator_s: s,
            evaluator_pubkey: *verifying_key,
        }
    }

    pub fn extract_secret(&self, garbler_sig: &Signature) -> Scalar {
        let commit_sum = self.evaluator_nonce_commit + self.garbler_commit;
        let is_odd: bool = commit_sum.to_affine().y_is_odd().into();
        let garbler_s =
            Scalar::from_repr(*FieldBytes::from_slice(&garbler_sig.to_bytes()[32..])).unwrap();
        let diff = garbler_s - self.evaluator_s;
        if is_odd {
            // see the `garbler_signature` function - we have:
            // garbler_s = self.evaluator_s - secret
            // so secret = -(garbler_s - self.evaluator_s)
            // = -diff
            -diff
        } else {
            diff
        }
    }

    pub fn garbler_signature(&self, secret: &Scalar) -> Signature {
        let commit_sum = self.evaluator_nonce_commit + self.garbler_commit;
        let is_odd: bool = commit_sum.to_affine().y_is_odd().into();

        let (r, s) = if is_odd {
            // During setup, we negated evaluator_nonce_commit and garbler_commit, and we need to
            // flip the corresponding private values as well. In the setup, the evaluator's private
            // nonce was already negated. Now we need to add the negation of our secret to make a
            // valid signature.
            (-commit_sum, self.evaluator_s - secret)
        } else {
            (commit_sum, self.evaluator_s + secret)
        };
        Signature::try_from([r.to_affine().x(), s.to_bytes()].concat().as_ref())
            .expect("valid signature")
    }

    pub fn verify_garbler_signature(
        &self,
        sighash: &TapSighash,
        garbler_sig: &Signature,
    ) -> Result<(), ()> {
        self.evaluator_pubkey
            .verify_raw(sighash.as_byte_array(), garbler_sig)
            .map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::{ProjectivePoint, Scalar, schnorr::SigningKey};
    use sha2::{Digest, Sha256};

    use crate::cac::adaptor_sigs::AdaptorInfo;

    #[test]
    fn test_high_level() {
        let evaluator_privkey = SigningKey::random(&mut rand::thread_rng());
        let garbler_secret = Scalar::generate_vartime(&mut rand::thread_rng());
        let garbler_commit = ProjectivePoint::GENERATOR * garbler_secret;

        let sighash = TapSighash::from_byte_array(Sha256::digest(b"some message").into());
        let adaptor = AdaptorInfo::new(&evaluator_privkey, garbler_commit, &sighash);

        let garbler_sig = adaptor.garbler_signature(&garbler_secret);
        adaptor
            .verify_garbler_signature(&sighash, &garbler_sig)
            .expect("signature should be valid");

        let secret = adaptor.extract_secret(&garbler_sig);
        assert_eq!(secret, garbler_secret);
    }
}

#[cfg(test)]
mod bitvm_tests {
    use super::*;

    use bitcoin::{
        Address, Amount, Network, ScriptBuf, TapSighashType, Transaction, TxIn, TxOut, Witness,
        XOnlyPublicKey,
        absolute::LockTime,
        key::{Secp256k1, UntweakedPublicKey},
        sighash::{Prevouts, ScriptPath, SighashCache},
        taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo},
        transaction::Version,
    };
    use bitcoin_script::script;
    use std::str::FromStr;

    pub(crate) fn unspendable_pubkey() -> UntweakedPublicKey {
        XOnlyPublicKey::from_str("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
            .unwrap()
    }

    pub fn spend_info_from_script(script: ScriptBuf) -> TaprootSpendInfo {
        let secp = Secp256k1::new();

        TaprootBuilder::with_huffman_tree(vec![(1, script)])
            .unwrap()
            .finalize(&secp, unspendable_pubkey())
            .unwrap()
    }

    pub fn address_from_spend_info(spend_info: &TaprootSpendInfo, network: Network) -> Address {
        let secp = Secp256k1::new();
        Address::p2tr(
            &secp,
            spend_info.internal_key(),
            spend_info.merkle_root(),
            network,
        )
    }

    #[test]
    fn test_tx() {
        let evaluator_privkey = SigningKey::random(&mut rand::thread_rng());
        let garbler_secret = Scalar::generate_vartime(&mut rand::thread_rng());
        let garbler_commit = ProjectivePoint::GENERATOR * garbler_secret;

        let evaluator_pubkey = evaluator_privkey.verifying_key().as_affine().x().to_vec();

        let script = script! {
            { evaluator_pubkey }
            OP_CHECKSIG
        }
        .compile();

        let spend_info = spend_info_from_script(script.clone());
        let address = address_from_spend_info(&spend_info, Network::Bitcoin);

        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![],
        };

        let mut sighash_cache = SighashCache::new(&tx);
        let prevouts = [TxOut {
            script_pubkey: address.script_pubkey(),
            value: Amount::from_sat(1000000),
        }];

        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&prevouts),
                ScriptPath::with_defaults(script.as_script()),
                TapSighashType::Default,
            )
            .unwrap();

        let adaptor = AdaptorInfo::new(&evaluator_privkey, garbler_commit, &sighash);

        let garbler_sig = adaptor.garbler_signature(&garbler_secret);
        adaptor
            .verify_garbler_signature(&sighash, &garbler_sig)
            .expect("signature should be valid");

        let secret = adaptor.extract_secret(&garbler_sig);
        assert_eq!(secret, garbler_secret);

        let control_block = spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .unwrap()
            .serialize();

        let witness: Witness = vec![
            garbler_sig.to_bytes().to_vec(),
            script.to_bytes(),
            control_block,
        ]
        .into();

        tx.input[0].witness = witness;

        let res = bitvm::dry_run_taproot_input(&tx, 0, &prevouts[..]);
        assert!(res.success);
    }
}
