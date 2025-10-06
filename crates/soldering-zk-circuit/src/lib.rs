use std::{convert::TryInto, sync::OnceLock};

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::{
    crh::{
        CRHSchemeGadget,
        poseidon::constraints::{CRHGadget, CRHParametersVar},
    },
    sponge::poseidon::{PoseidonConfig, traits::find_poseidon_ark_and_mds},
};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, Proof as GrothProof, VerifyingKey};
use ark_r1cs_std::{
    alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::fp::FpVar, prelude::ToBitsGadget,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};
use thiserror::Error;

pub type Proof = Vec<u8>;
pub type Label = [u8; 16];
pub type Hash = [u8; 32];

const LABEL_BYTES: usize = 16;
const LABEL_BITS: usize = LABEL_BYTES * 8;

type PoseidonCrhGadget = CRHGadget<Fr>;
type PoseidonCrhParamsVar = CRHParametersVar<Fr>;

#[derive(Debug, Error)]
pub enum ZkError {
    #[error("circuit synthesis failed: {0}")]
    Synthesis(#[from] SynthesisError),
    #[error("serialization failed: {0}")]
    Serialization(#[from] ark_serialize::SerializationError),
    #[error("malformed proof: {0}")]
    ProofFormat(String),
    #[error("proof decoding consumed only {consumed} of {total} bytes")]
    TrailingProofBytes { consumed: usize, total: usize },
}

#[derive(Clone)]
struct SolderingCircuit<const I: usize, const L: usize> {
    commits: Box<[[[Hash; 2]; L]; I]>,
    deltas0: Box<[[Label; L]; I]>,
    deltas1: Box<[[Label; L]; I]>,
    labels0: Box<[[Label; L]; I]>,
    labels1: Box<[[Label; L]; I]>,
}

impl<const I: usize, const L: usize> SolderingCircuit<I, L> {
    fn new(
        commits: &[[[Hash; 2]; L]; I],
        deltas0: &[[Label; L]; I],
        deltas1: &[[Label; L]; I],
        labels0: &[[Label; L]; I],
        labels1: &[[Label; L]; I],
    ) -> Self {
        Self {
            commits: Box::new(*commits),
            deltas0: Box::new(*deltas0),
            deltas1: Box::new(*deltas1),
            labels0: Box::new(*labels0),
            labels1: Box::new(*labels1),
        }
    }

    fn public_inputs(&self) -> Vec<Fr> {
        collect_public_inputs(&self.commits, &self.deltas0, &self.deltas1)
    }
}

impl<const I: usize, const L: usize> ConstraintSynthesizer<Fr> for SolderingCircuit<I, L> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let params_var = PoseidonCrhParamsVar::new_constant(cs.clone(), poseidon_config().clone())?;
        let mut base_label0_bits: Vec<Vec<Boolean<Fr>>> = Vec::with_capacity(L);
        let mut base_label1_bits: Vec<Vec<Boolean<Fr>>> = Vec::with_capacity(L);

        // Collect all elements that will be aggregated
        let mut elements_to_aggregate = Vec::with_capacity(I * L * 4);

        for row in 0..I {
            for wire in 0..L {
                // Compute and verify commits
                let label0_field = label_to_field(&self.labels0[row][wire]);
                let label0_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(label0_field))?;
                let hash0_var = PoseidonCrhGadget::evaluate(&params_var, &[label0_var.clone()])?;

                let label1_field = label_to_field(&self.labels1[row][wire]);
                let label1_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(label1_field))?;
                let hash1_var = PoseidonCrhGadget::evaluate(&params_var, &[label1_var.clone()])?;

                // Add computed hashes to aggregation list
                elements_to_aggregate.push(hash0_var.clone());
                elements_to_aggregate.push(hash1_var.clone());

                // Store base instance labels when row == 0
                if row == 0 {
                    // Only decompose to bits if we're the base instance
                    let label0_bits = label0_var
                        .to_bits_le()?
                        .into_iter()
                        .take(LABEL_BITS)
                        .collect::<Vec<_>>();
                    let label1_bits = label1_var
                        .to_bits_le()?
                        .into_iter()
                        .take(LABEL_BITS)
                        .collect::<Vec<_>>();

                    base_label0_bits.push(label0_bits);
                    base_label1_bits.push(label1_bits);
                } else {
                    // For non-base instances, decompose and verify XOR
                    let label0_bits = label0_var
                        .to_bits_le()?
                        .into_iter()
                        .take(LABEL_BITS)
                        .collect::<Vec<_>>();
                    let label1_bits = label1_var
                        .to_bits_le()?
                        .into_iter()
                        .take(LABEL_BITS)
                        .collect::<Vec<_>>();

                    // Read deltas and decompose
                    let delta0_field = label_to_field(&self.deltas0[row][wire]);
                    let delta0_var = FpVar::<Fr>::new_constant(cs.clone(), delta0_field)?;
                    let delta0_bits = delta0_var
                        .to_bits_le()?
                        .into_iter()
                        .take(LABEL_BITS)
                        .collect::<Vec<_>>();

                    let delta1_field = label_to_field(&self.deltas1[row][wire]);
                    let delta1_var = FpVar::<Fr>::new_constant(cs.clone(), delta1_field)?;
                    let delta1_bits = delta1_var
                        .to_bits_le()?
                        .into_iter()
                        .take(LABEL_BITS)
                        .collect::<Vec<_>>();

                    // Add deltas to aggregation
                    elements_to_aggregate.push(delta0_var);
                    elements_to_aggregate.push(delta1_var);

                    // Verify XOR for non-base instances
                    let base0_bits = &base_label0_bits[wire];
                    let base1_bits = &base_label1_bits[wire];
                    enforce_xor_bits(base0_bits, &label0_bits, &delta0_bits)?;
                    enforce_xor_bits(base1_bits, &label1_bits, &delta1_bits)?;
                }

                // Add deltas to aggregation for base instance (they're zero but needed for consistency)
                if row == 0 {
                    let delta0_field = label_to_field(&self.deltas0[row][wire]);
                    let delta0_var = FpVar::<Fr>::new_constant(cs.clone(), delta0_field)?;
                    let delta1_field = label_to_field(&self.deltas1[row][wire]);
                    let delta1_var = FpVar::<Fr>::new_constant(cs.clone(), delta1_field)?;
                    elements_to_aggregate.push(delta0_var);
                    elements_to_aggregate.push(delta1_var);
                }
            }
        }

        // Aggregate all elements into a single hash (mirroring tree structure from collect_public_inputs)
        let aggregated_var = aggregate_elements_gadget(&params_var, &elements_to_aggregate)?;

        // The single aggregated hash is our only public input
        let expected_aggregate =
            FpVar::<Fr>::new_input(cs.clone(), || Ok(self.public_inputs()[0]))?;

        aggregated_var.enforce_equal(&expected_aggregate)?;

        Ok(())
    }
}

fn aggregate_elements_gadget(
    params_var: &PoseidonCrhParamsVar,
    elements: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    // Hash elements in chunks to build a tree-like structure (same as aggregate_elements)
    let mut current = elements.to_vec();

    while current.len() > 1 {
        let mut next_level = Vec::new();

        // Process in chunks of 2 (binary tree)
        for chunk in current.chunks(2) {
            let hash = if chunk.len() == 2 {
                PoseidonCrhGadget::evaluate(params_var, &[chunk[0].clone(), chunk[1].clone()])?
            } else {
                // Odd element, just pass through
                chunk[0].clone()
            };
            next_level.push(hash);
        }

        current = next_level;
    }

    Ok(current[0].clone())
}

pub fn prove_soldering<const I: usize, const L: usize, R: RngCore + CryptoRng>(
    commits: &[[[Hash; 2]; L]; I],
    deltas0: &[[Label; L]; I],
    deltas1: &[[Label; L]; I],
    labels0: &[[Label; L]; I],
    labels1: &[[Label; L]; I],
    rng: &mut R,
) -> Result<Proof, ZkError> {
    let circuit = SolderingCircuit::new(commits, deltas0, deltas1, labels0, labels1);
    let public_inputs = circuit.public_inputs();

    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng)?;
    let proof = Groth16::<Bn254>::prove(&pk, circuit, rng)?;

    encode_proof(&vk, &public_inputs, &proof)
}

pub fn verify_soldering<const I: usize, const L: usize>(
    commits: &[[[Hash; 2]; L]; I],
    deltas0: &[[Label; L]; I],
    deltas1: &[[Label; L]; I],
    proof_bytes: &Proof,
) -> Result<bool, ZkError> {
    let public_inputs = collect_public_inputs(commits, deltas0, deltas1);
    let (vk, encoded_inputs, proof) = decode_proof(proof_bytes)?;
    let prepared = Groth16::<Bn254>::process_vk(&vk)?;

    if encoded_inputs != public_inputs {
        return Ok(false);
    }

    Ok(Groth16::<Bn254>::verify_with_processed_vk(
        &prepared,
        &encoded_inputs,
        &proof,
    )?)
}

fn encode_proof(
    vk: &VerifyingKey<Bn254>,
    public_inputs: &[Fr],
    proof: &GrothProof<Bn254>,
) -> Result<Proof, ZkError> {
    let mut bytes = Vec::new();

    vk.serialize_compressed(&mut bytes)?;
    proof.serialize_compressed(&mut bytes)?;

    let inputs_len: u32 = public_inputs
        .len()
        .try_into()
        .expect("public input vector too large");
    bytes.extend_from_slice(&inputs_len.to_le_bytes());

    for fr in public_inputs {
        fr.serialize_compressed(&mut bytes)?;
    }

    Ok(bytes)
}

fn decode_proof(
    bytes: &[u8],
) -> Result<(VerifyingKey<Bn254>, Vec<Fr>, GrothProof<Bn254>), ZkError> {
    let mut cursor = bytes;

    let vk = VerifyingKey::<Bn254>::deserialize_compressed(&mut cursor)?;
    let proof = GrothProof::<Bn254>::deserialize_compressed(&mut cursor)?;
    if cursor.len() < core::mem::size_of::<u32>() {
        return Err(ZkError::ProofFormat("missing public input length".into()));
    }
    let (len_bytes, rest) = cursor.split_at(core::mem::size_of::<u32>());
    let inputs_len = u32::from_le_bytes(len_bytes.try_into().expect("length slice")) as usize;
    cursor = rest;

    let mut public_inputs = Vec::with_capacity(inputs_len);
    for _ in 0..inputs_len {
        public_inputs.push(Fr::deserialize_compressed(&mut cursor)?);
    }

    if cursor.is_empty() {
        Ok((vk, public_inputs, proof))
    } else {
        let consumed = bytes.len() - cursor.len();
        Err(ZkError::TrailingProofBytes {
            consumed,
            total: bytes.len(),
        })
    }
}

fn collect_public_inputs<const I: usize, const L: usize>(
    commits: &[[[Hash; 2]; L]; I],
    deltas0: &[[Label; L]; I],
    deltas1: &[[Label; L]; I],
) -> Vec<Fr> {
    let mut elements = Vec::with_capacity(I * L * 4);

    // Collect all elements in canonical order
    for row in 0..I {
        for wire in 0..L {
            elements.push(hash_to_field(&commits[row][wire][0]));
            elements.push(hash_to_field(&commits[row][wire][1]));
            elements.push(label_to_field(&deltas0[row][wire]));
            elements.push(label_to_field(&deltas1[row][wire]));
        }
    }

    // Aggregate all elements into a single hash using Poseidon sponge
    let aggregated = aggregate_elements(&elements);

    vec![aggregated]
}

fn aggregate_elements(elements: &[Fr]) -> Fr {
    use ark_crypto_primitives::crh::{CRHScheme, poseidon::CRH};

    // Hash elements in chunks to build a tree-like structure
    let mut current = elements.to_vec();

    while current.len() > 1 {
        let mut next_level = Vec::new();

        // Process in chunks of 2 (binary tree)
        for chunk in current.chunks(2) {
            let hash = if chunk.len() == 2 {
                CRH::<Fr>::evaluate(poseidon_config(), [chunk[0], chunk[1]])
                    .expect("Poseidon evaluation should succeed")
            } else {
                // Odd element, just pass through
                chunk[0]
            };
            next_level.push(hash);
        }

        current = next_level;
    }

    current[0]
}

fn enforce_xor_bits(
    base_bits: &[Boolean<Fr>],
    other_bits: &[Boolean<Fr>],
    delta_bits: &[Boolean<Fr>],
) -> Result<(), SynthesisError> {
    debug_assert_eq!(base_bits.len(), LABEL_BITS);
    debug_assert_eq!(other_bits.len(), LABEL_BITS);
    debug_assert_eq!(delta_bits.len(), LABEL_BITS);

    for ((base_bit, other_bit), delta_bit) in base_bits.iter().zip(other_bits).zip(delta_bits) {
        let expected = base_bit.clone() ^ other_bit.clone();
        expected.enforce_equal(delta_bit)?;
    }

    Ok(())
}

fn hash_to_field(hash: &Hash) -> Fr {
    Fr::from_le_bytes_mod_order(hash)
}

fn label_to_field(label: &Label) -> Fr {
    Fr::from_le_bytes_mod_order(label)
}

fn poseidon_config() -> &'static PoseidonConfig<Fr> {
    static CONFIG: OnceLock<PoseidonConfig<Fr>> = OnceLock::new();
    CONFIG.get_or_init(|| {
        const RATE: usize = 2;
        const FULL_ROUNDS: usize = 8;
        const PARTIAL_ROUNDS: usize = 57;
        const ALPHA: u64 = 5;
        const CAPACITY: usize = 1;

        let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
            Fr::MODULUS_BIT_SIZE as u64,
            RATE,
            FULL_ROUNDS as u64,
            PARTIAL_ROUNDS as u64,
            0,
        );

        PoseidonConfig::new(FULL_ROUNDS, PARTIAL_ROUNDS, ALPHA, mds, ark, RATE, CAPACITY)
    })
}

#[cfg(test)]
mod tests {
    use ark_crypto_primitives::crh::{CRHScheme, poseidon::CRH};
    use ark_ff::BigInteger;
    use ark_std::rand::{Rng, RngCore, SeedableRng, rngs::StdRng};

    use super::*;

    type PoseidonCrh = CRH<Fr>;

    #[cfg(test)]
    fn compute_label_commit(label: &Label) -> Hash {
        let label_field = label_to_field(label);
        let input = [label_field];
        let hash = PoseidonCrh::evaluate(poseidon_config(), input)
            .expect("Poseidon evaluation should succeed");
        field_to_hash(&hash)
    }

    #[cfg(test)]
    fn field_to_hash(value: &Fr) -> Hash {
        let mut bytes = [0u8; 32];
        let bigint = (*value).into_bigint();
        let repr = bigint.to_bytes_le();
        bytes[..repr.len()].copy_from_slice(&repr);
        bytes
    }

    #[test]
    fn circuit_succeeds_on_consistent_inputs() {
        const I: usize = 2;
        const L: usize = 3;

        let mut rng = StdRng::seed_from_u64(42);

        let mut commits = [[[Hash::default(); 2]; L]; I];
        let mut deltas0 = [[Label::default(); L]; I];
        let mut deltas1 = [[Label::default(); L]; I];
        let labels0 = random_label_matrix::<I, L>(&mut rng);
        let labels1 = random_label_matrix::<I, L>(&mut rng);

        derive_commits_from_labels(&mut commits, &labels0, &labels1);
        derive_deltas_from_labels(&mut deltas0, &mut deltas1, &labels0, &labels1);

        let proof =
            prove_soldering::<I, L, _>(&commits, &deltas0, &deltas1, &labels0, &labels1, &mut rng)
                .expect("proving should succeed");

        assert!(
            verify_soldering::<I, L>(&commits, &deltas0, &deltas1, &proof)
                .expect("verification should succeed"),
            "verification must succeed on matching inputs"
        );
    }

    #[test]
    fn circuit_rejects_commit_mismatch() {
        const I: usize = 1;
        const L: usize = 1;
        let mut rng = StdRng::seed_from_u64(7);

        let mut commits = [[[Hash::default(); 2]; L]; I];
        let mut deltas0 = [[Label::default(); L]; I];
        let mut deltas1 = [[Label::default(); L]; I];
        let labels0 = random_label_matrix::<I, L>(&mut rng);
        let labels1 = random_label_matrix::<I, L>(&mut rng);
        derive_commits_from_labels(&mut commits, &labels0, &labels1);
        derive_deltas_from_labels(&mut deltas0, &mut deltas1, &labels0, &labels1);

        let proof =
            prove_soldering::<I, L, _>(&commits, &deltas0, &deltas1, &labels0, &labels1, &mut rng)
                .expect("proving should succeed");

        let i = rng.gen_range(0..I);
        let l = rng.gen_range(0..L);
        let label_i = rng.gen_range(0..2);
        let bit = rng.gen_range(0..16);

        commits[i][l][label_i][bit] ^= 0xFF;

        assert!(
            !verify_soldering::<I, L>(&commits, &deltas0, &deltas1, &proof)
                .expect("verification should run"),
            "verification must fail when public inputs differ"
        );
    }

    #[test]
    fn verification_rejects_tampered_delta() {
        const I: usize = 2;
        const L: usize = 2;
        let mut rng = StdRng::seed_from_u64(99);

        let mut commits = [[[Hash::default(); 2]; L]; I];
        let mut deltas0 = [[Label::default(); L]; I];
        let mut deltas1 = [[Label::default(); L]; I];
        let labels0 = random_label_matrix::<I, L>(&mut rng);
        let labels1 = random_label_matrix::<I, L>(&mut rng);

        derive_commits_from_labels(&mut commits, &labels0, &labels1);
        derive_deltas_from_labels(&mut deltas0, &mut deltas1, &labels0, &labels1);

        let proof =
            prove_soldering::<I, L, _>(&commits, &deltas0, &deltas1, &labels0, &labels1, &mut rng)
                .expect("proving should succeed");

        deltas0[1][0][0] ^= 0xFF;

        assert!(
            !verify_soldering::<I, L>(&commits, &deltas0, &deltas1, &proof)
                .expect("verification should run"),
            "verification must fail when deltas are tampered after proving"
        );
    }

    #[test]
    fn test_medium_scale() {
        use std::time::Instant;

        const I: usize = 7; // 7 instances
        const L: usize = 100; // 100 labels per instance

        println!(
            "\n=== Medium Scale Test: {} instances × {} labels ===",
            I, L
        );
        println!("Total labels: {}", I * L * 2);
        println!("Total XOR checks: {}", (I - 1) * L * 2);
        println!("Public inputs: 1 (aggregated hash)");

        let mut rng = StdRng::seed_from_u64(42);

        // Generate test data
        let labels0 = random_label_matrix::<I, L>(&mut rng);
        let labels1 = random_label_matrix::<I, L>(&mut rng);

        let mut commits = [[[Hash::default(); 2]; L]; I];
        derive_commits_from_labels(&mut commits, &labels0, &labels1);

        let mut deltas0 = [[Label::default(); L]; I];
        let mut deltas1 = [[Label::default(); L]; I];
        derive_deltas_from_labels(&mut deltas0, &mut deltas1, &labels0, &labels1);

        // Prove
        let start = Instant::now();
        let proof =
            prove_soldering::<I, L, _>(&commits, &deltas0, &deltas1, &labels0, &labels1, &mut rng)
                .expect("proving should succeed");
        let proving_time = start.elapsed();

        // Verify
        let start = Instant::now();
        let verified = verify_soldering::<I, L>(&commits, &deltas0, &deltas1, &proof)
            .expect("verification should succeed");
        let verification_time = start.elapsed();

        assert!(verified, "Proof must verify");

        println!("\n✅ Test passed!");
        println!("Proving time: {:?}", proving_time);
        println!("Verification time: {:?}", verification_time);
        println!("Proof size: {} bytes", proof.len());
    }

    #[test]
    #[ignore] // Run with --ignored flag for full scale test
    fn test_full_scale_benchmark() {
        use std::time::Instant;

        const I: usize = 7; // 7 instances
        const L: usize = 1019; // 1019 labels per instance

        println!(
            "\n=== Full Scale Benchmark: {} instances × {} labels ===",
            I, L
        );
        println!("Total labels: {}", I * L * 2);
        println!("Total XOR checks: {}\n", (I - 1) * L * 2);

        let mut rng = StdRng::seed_from_u64(42);

        // Generate random labels
        let start = Instant::now();
        let labels0 = random_label_matrix::<I, L>(&mut rng);
        let labels1 = random_label_matrix::<I, L>(&mut rng);
        println!("Label generation: {:?}", start.elapsed());

        // Compute commitments
        let start = Instant::now();
        let mut commits = [[[Hash::default(); 2]; L]; I];
        derive_commits_from_labels(&mut commits, &labels0, &labels1);
        println!("Commitment computation: {:?}", start.elapsed());

        // Compute deltas
        let start = Instant::now();
        let mut deltas0 = [[Label::default(); L]; I];
        let mut deltas1 = [[Label::default(); L]; I];
        derive_deltas_from_labels(&mut deltas0, &mut deltas1, &labels0, &labels1);
        println!("Delta computation: {:?}", start.elapsed());

        // Prove
        let start = Instant::now();
        let proof =
            prove_soldering::<I, L, _>(&commits, &deltas0, &deltas1, &labels0, &labels1, &mut rng)
                .expect("proving should succeed");
        let proving_time = start.elapsed();
        println!("\n🔨 Proving time: {:?}", proving_time);
        println!("Proof size: {} bytes", proof.len());

        // Verify
        let start = Instant::now();
        let verified = verify_soldering::<I, L>(&commits, &deltas0, &deltas1, &proof)
            .expect("verification should succeed");
        let verification_time = start.elapsed();
        println!("✅ Verification time: {:?}", verification_time);

        assert!(verified, "Proof must verify");

        println!("\n=== Summary ===");
        println!("Proving: {:?}", proving_time);
        println!("Verification: {:?}", verification_time);
        println!("Proof size: {} bytes", proof.len());
    }

    #[test]
    fn circuit_unsatisfied_on_inconsistent_labels() {
        const I: usize = 2;
        const L: usize = 2;
        let mut rng = StdRng::seed_from_u64(1234);

        let mut commits = [[[Hash::default(); 2]; L]; I];
        let mut deltas0 = [[Label::default(); L]; I];
        let mut deltas1 = [[Label::default(); L]; I];
        let mut labels0 = random_label_matrix::<I, L>(&mut rng);
        let labels1 = random_label_matrix::<I, L>(&mut rng);

        derive_commits_from_labels(&mut commits, &labels0, &labels1);
        derive_deltas_from_labels(&mut deltas0, &mut deltas1, &labels0, &labels1);

        labels0[0][0][0] ^= 0x01;

        let circuit = SolderingCircuit::new(&commits, &deltas0, &deltas1, &labels0, &labels1);
        let cs = ark_relations::r1cs::ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("constraint generation must succeed");
        assert!(
            !cs.is_satisfied().expect("constraint evaluation"),
            "circuit must be unsatisfied when labels mismatch commitments"
        );
    }

    fn derive_commits_from_labels<const I: usize, const L: usize>(
        commits: &mut [[[Hash; 2]; L]; I],
        labels0: &[[Label; L]; I],
        labels1: &[[Label; L]; I],
    ) {
        for row in 0..I {
            for wire in 0..L {
                commits[row][wire][0] = compute_label_commit(&labels0[row][wire]);
                commits[row][wire][1] = compute_label_commit(&labels1[row][wire]);
            }
        }
    }

    fn derive_deltas_from_labels<const I: usize, const L: usize>(
        deltas0: &mut [[Label; L]; I],
        deltas1: &mut [[Label; L]; I],
        labels0: &[[Label; L]; I],
        labels1: &[[Label; L]; I],
    ) {
        for wire in 0..L {
            deltas0[0][wire] = [0u8; LABEL_BYTES];
            deltas1[0][wire] = [0u8; LABEL_BYTES];
        }

        for row in 1..I {
            for wire in 0..L {
                deltas0[row][wire] = xor_labels(&labels0[0][wire], &labels0[row][wire]);
                deltas1[row][wire] = xor_labels(&labels1[0][wire], &labels1[row][wire]);
            }
        }
    }

    fn xor_labels(a: &Label, b: &Label) -> Label {
        let mut out = [0u8; LABEL_BYTES];
        for (dst, (lhs, rhs)) in out.iter_mut().zip(a.iter().zip(b.iter())) {
            *dst = lhs ^ rhs;
        }
        out
    }

    fn random_label_matrix<const I: usize, const L: usize>(rng: &mut StdRng) -> [[Label; L]; I] {
        use std::array;

        array::from_fn(|_| array::from_fn(|_| random_label(rng)))
    }

    fn random_label(rng: &mut StdRng) -> Label {
        let mut label = [0u8; 16];
        rng.fill_bytes(&mut label);
        label
    }
}
