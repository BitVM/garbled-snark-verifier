//! Native reference fixture only. No Nova verification happens in a GC yet.
use ff::PrimeField;
use num_bigint::BigUint;
use garbled_snark_verifier::nova::PastaField;
use nova_snark::{
    frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError},
    nova::{CompressedSNARK, PublicParams, RecursiveSNARK},
    provider::{ipa_pc, PallasEngine, VestaEngine},
    spartan::snark::RelaxedR1CSSNARK,
    traits::{circuit::StepCircuit, snark::RelaxedR1CSSNARKTrait, Engine},
};
use sha2::{Digest, Sha256};
use std::{error::Error, path::PathBuf, time::Instant};

type E1 = PallasEngine;
type E2 = VestaEngine;
type F = <E1 as Engine>::Scalar;
type S1 = RelaxedR1CSSNARK<E1, ipa_pc::EvaluationEngine<E1>>;
type S2 = RelaxedR1CSSNARK<E2, ipa_pc::EvaluationEngine<E2>>;
type Proof = CompressedSNARK<E1, E2, SquarePlusFive, S1, S2>;
#[derive(Clone, Debug)]
struct SquarePlusFive;
impl StepCircuit<F> for SquarePlusFive {
    fn arity(&self) -> usize { 1 }
    fn synthesize<CS: ConstraintSystem<F>>(&self, cs: &mut CS, z: &[AllocatedNum<F>]) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let sq = z[0].square(cs.namespace(|| "square"))?;
        let out = AllocatedNum::alloc(cs.namespace(|| "plus_five"), || {
            Ok(sq.get_value().ok_or(SynthesisError::AssignmentMissing)? + F::from(5))
        })?;
        cs.enforce(|| "bind_output", |lc| lc + sq.get_variable() + (F::from(5), CS::one()),
            |lc| lc + CS::one(), |lc| lc + out.get_variable());
        Ok(vec![out])
    }
}
fn sha(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
fn main() -> Result<(), Box<dyn Error>> {
    let out = PathBuf::from(std::env::args().nth(1).unwrap_or_else(|| "results/nova-reference".into()));
    std::fs::create_dir_all(&out)?;
    let start = Instant::now();
    // Cross-check the field-role mapping against the actual Nova dependency.
    for (field, native) in [(PastaField::VestaBase, F::MODULUS),
        (PastaField::PallasBase, <<E2 as Engine>::Scalar as PrimeField>::MODULUS)] {
        let bytes: Vec<u8> = field.modulus_le().iter().flat_map(|v| v.to_le_bytes()).collect();
        let actual = BigUint::parse_bytes(native.trim_start_matches("0x").as_bytes(), 16).expect("field modulus");
        assert_eq!(BigUint::from_bytes_le(&bytes), actual);
    }
    let c = SquarePlusFive;
    let pp = PublicParams::<E1, E2, SquarePlusFive>::setup(&c, &*S1::ck_floor(), &*S2::ck_floor())?;
    let z0 = vec![F::from(2)];
    let steps = 2;
    let expected = vec![F::from(86)]; // 2 -> 9 -> 86, independently specified.
    let mut recursive = RecursiveSNARK::<E1, E2, SquarePlusFive>::new(&pp, &c, &z0)?;
    for _ in 0..steps { recursive.prove_step(&pp, &c)?; }
    assert_eq!(recursive.verify(&pp, steps, &z0)?, expected);
    let (pk, vk) = Proof::setup(&pp)?;
    let proof = Proof::prove(&pp, &pk, &recursive)?;
    assert_eq!(proof.verify(&vk, steps, &z0)?, expected);
    assert!(proof.verify(&vk, steps + 1, &z0).is_err());
    assert!(proof.verify(&vk, steps, &[F::from(3)]).is_err());
    assert_ne!(proof.verify(&vk, steps, &z0)?, vec![F::from(87)]);
    let bytes = bincode::serialize(&proof)?;
    let vk_bytes = bincode::serialize(&vk)?;
    let decoded: Proof = bincode::deserialize(&bytes)?;
    assert_eq!(decoded.verify(&vk, steps, &z0)?, expected);
    std::fs::write(out.join("proof.bin"), &bytes)?;
    std::fs::write(out.join("vk.bin"), &vk_bytes)?;
    let report = serde_json::json!({
        "scope": "native_reference_only", "nova_version": "0.76.0",
        "curve_cycle": "Pallas/Vesta", "compression": "Spartan/IPA",
        "trusted_setup": false, "garbled_nova_verification": false,
        "statement": "square_plus_five_v1", "steps": steps, "z0_decimal": ["2"],
        "expected_zn_decimal": ["86"], "proof_bytes": bytes.len(),
        "proof_sha256": sha(&bytes), "vk_sha256": sha(&vk_bytes),
        "rejects_wrong_steps": true, "rejects_wrong_initial_state": true,
        "checks_expected_final_state": true, "roundtrip_verified": true,
        "primary_constraints": pp.num_constraints().0, "secondary_constraints": pp.num_constraints().1,
        "elapsed_seconds": start.elapsed().as_secs_f64()
    });
    let json = serde_json::to_string_pretty(&report)?;
    std::fs::write(out.join("receipt.json"), &json)?;
    println!("{json}");
    Ok(())
}
