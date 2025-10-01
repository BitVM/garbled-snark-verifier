use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_secp256k1::{Fq, Fr, Projective};
use sha2::{Digest, Sha256};

fn fq_to_be32(x: &Fq) -> [u8; 32] {
    // `Fq` modulus is 256 bits, so its big-endian encoding always fits in 32 bytes.
    x.into_bigint()
        .to_bytes_be()
        .try_into()
        .expect("Fq encodes to exactly 32 bytes")
}

fn fr_to_be32(x: &Fr) -> [u8; 32] {
    // `Fr` modulus is 256 bits, so its big-endian encoding always fits in 32 bytes.
    x.into_bigint()
        .to_bytes_be()
        .try_into()
        .expect("Fr encodes to exactly 32 bytes")
}

fn fr_from_be_bytes_mod_order(bytes: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

fn is_odd(y: &Fq) -> bool {
    y.into_bigint().is_odd()
}

#[derive(Clone, Debug)]
pub struct AdaptorInfo {
    garbler_commit: Projective,
    evaluator_nonce_commit: Projective,
    evaluator_s: Fr,
}

pub type SignatureBytes = [u8; 64];

impl AdaptorInfo {
    pub fn new<R: rand::Rng + ?Sized>(
        evaluator_secret: &Fr,
        garbler_commit: Projective,
        message_hash: &[u8],
        rng: &mut R,
    ) -> Self {
        let mut nonce = Fr::rand(rng);
        let nonce_commit = Projective::generator() * nonce;

        // Compute evaluator public key (x-only) for the challenge hash
        let eval_pub = (Projective::generator() * evaluator_secret).into_affine();
        let eval_pub_x = fq_to_be32(&eval_pub.x);

        let mut public_sum = garbler_commit + nonce_commit;
        // BIP-340 requires even Y; if odd, negate both commit and nonce
        if is_odd(&public_sum.into_affine().y) {
            public_sum = -public_sum;
            nonce = -nonce;
        }
        let public_sum_bytes = fq_to_be32(&public_sum.into_affine().x);

        let tag_hash = Sha256::digest(b"BIP0340/challenge");
        let mut hasher = Sha256::new();
        hasher.update(tag_hash);
        hasher.update(tag_hash);
        hasher.update(public_sum_bytes);
        hasher.update(eval_pub_x);
        hasher.update(message_hash);
        let h = hasher.finalize();
        let e = fr_from_be_bytes_mod_order(h.as_slice());

        let s = nonce + e * evaluator_secret;

        AdaptorInfo {
            evaluator_nonce_commit: nonce_commit,
            garbler_commit,
            evaluator_s: s,
        }
    }

    pub fn extract_secret(&self, garbler_sig: &[u8]) -> Result<Fr, String> {
        if garbler_sig.len() != 64 {
            return Err("invalid signature length".to_owned());
        }
        let commit_sum = self.evaluator_nonce_commit + self.garbler_commit;
        let is_odd = is_odd(&commit_sum.into_affine().y);
        let garbler_s = fr_from_be_bytes_mod_order(&garbler_sig[32..]);
        let diff = garbler_s - self.evaluator_s;
        Ok(if is_odd { -diff } else { diff })
    }

    pub fn garbler_signature(&self, secret: &Fr) -> SignatureBytes {
        let commit_sum = self.evaluator_nonce_commit + self.garbler_commit;
        let is_odd = is_odd(&commit_sum.into_affine().y);

        let (r, s) = if is_odd {
            (-commit_sum, self.evaluator_s - secret)
        } else {
            (commit_sum, self.evaluator_s + secret)
        };
        let r_x = fq_to_be32(&r.into_affine().x);
        let s_bytes = fr_to_be32(&s);
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&r_x);
        out[32..].copy_from_slice(&s_bytes);
        out
    }
}

#[cfg(test)]
mod tests {
    use k256::schnorr::{Signature as KSig, SigningKey, VerifyingKey};
    use sha2::{Digest, Sha256};

    use super::*;

    fn fr_from_sk(sk: &SigningKey) -> Fr {
        let bytes = sk.to_bytes();
        fr_from_be_bytes_mod_order(bytes.as_slice())
    }

    #[test]
    fn test_high_level() {
        let mut rng = rand::thread_rng();
        let evaluator_privkey = SigningKey::random(&mut rng);
        let evaluator_secret_fr = fr_from_sk(&evaluator_privkey);
        let garbler_secret_fr = Fr::rand(&mut rng);
        let garbler_commit = Projective::generator() * garbler_secret_fr;

        let sighash = Sha256::digest(b"some message").to_vec();
        let adaptor = AdaptorInfo::new(
            &evaluator_secret_fr,
            garbler_commit,
            sighash.as_slice(),
            &mut rng,
        );

        let garbler_sig_bytes = adaptor.garbler_signature(&garbler_secret_fr);
        // Verify using k256 in test only
        let verifying_key: VerifyingKey = *evaluator_privkey.verifying_key();
        let ksig = KSig::try_from(garbler_sig_bytes.as_slice()).expect("valid sig");
        verifying_key
            .verify_raw(sighash.as_slice(), &ksig)
            .expect("signature should be valid");

        let secret = adaptor
            .extract_secret(&garbler_sig_bytes)
            .expect("secret should be extracted");
        assert_eq!(secret, garbler_secret_fr);
    }
}

#[cfg(test)]
mod bitvm_tests {
    use std::str::FromStr;

    use bitcoin::{
        Address, Amount, Network, ScriptBuf, TapSighashType, Transaction, TxIn, TxOut, Witness,
        XOnlyPublicKey,
        absolute::LockTime,
        hashes::Hash,
        key::{Secp256k1, UntweakedPublicKey},
        sighash::{Prevouts, ScriptPath, SighashCache},
        taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo},
        transaction::Version,
    };
    use bitcoin_script::script;
    use k256::{
        elliptic_curve::point::AffineCoordinates,
        schnorr::{Signature as KSig, SigningKey, VerifyingKey},
    };

    use super::*;

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
        let evaluator_pubkey = evaluator_privkey.verifying_key().as_affine().x().to_vec();
        let mut rng = rand::thread_rng();
        let evaluator_secret_fr = {
            let b = evaluator_privkey.to_bytes();
            fr_from_be_bytes_mod_order(b.as_slice())
        };
        let garbler_secret_fr = Fr::rand(&mut rng);
        let garbler_commit = Projective::generator() * garbler_secret_fr;

        let script = script! {
            { evaluator_pubkey }
            OP_CHECKSIG
        }
        .compile();

        let spend_info = spend_info_from_script(script.clone());
        let address = address_from_spend_info(&spend_info, Network::Testnet);
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                value: Amount::from_sat(2000),
                script_pubkey: address.script_pubkey(),
            }],
        };

        // Provide a concrete prevout matching the spend script to compute taproot sighash
        let prevouts = vec![TxOut {
            value: Amount::from_sat(2000),
            script_pubkey: address.script_pubkey(),
        }];
        let mut sighash_cache = SighashCache::new(&tx);

        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&prevouts),
                ScriptPath::with_defaults(script.as_script()),
                TapSighashType::Default,
            )
            .unwrap()
            .to_byte_array()
            .to_vec();

        let adaptor = AdaptorInfo::new(
            &evaluator_secret_fr,
            garbler_commit,
            sighash.as_slice(),
            &mut rng,
        );

        let garbler_sig_bytes = adaptor.garbler_signature(&garbler_secret_fr);
        // Verify using k256 in test only
        let verifying_key: VerifyingKey = *evaluator_privkey.verifying_key();
        let ksig = KSig::try_from(garbler_sig_bytes.as_slice()).expect("valid sig");
        verifying_key
            .verify_raw(sighash.as_slice(), &ksig)
            .expect("signature should be valid");

        let secret = adaptor
            .extract_secret(&garbler_sig_bytes)
            .expect("secret should be extracted");
        assert_eq!(secret, garbler_secret_fr);

        let control_block = spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .unwrap()
            .serialize();

        let witness: Witness =
            vec![garbler_sig_bytes.to_vec(), script.to_bytes(), control_block].into();

        tx.input[0].witness = witness;

        let res = bitvm::dry_run_taproot_input(&tx, 0, &prevouts[..]);
        assert!(res.success);
    }
}
