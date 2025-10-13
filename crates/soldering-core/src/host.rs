use sp1_sdk::{
    ExecutionReport, Prover, ProverClient, SP1ProofWithPublicValues, SP1PublicValues, SP1Stdin,
    SP1VerifyingKey,
};

pub use crate::{
    guest,
    types::{ArchivedSolderedLabelsData, SolderedLabelsData, WiresInput},
};

/// Result of executing the soldering guest without producing a proof.
#[derive(Debug)]
pub struct ExecuteReport {
    pub public_values: SP1PublicValues,
    pub report: ExecutionReport,
}

fn cpu_prover() -> sp1_sdk::CpuProver {
    ProverClient::builder().cpu().build()
}

fn build_stdin(input: &WiresInput) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    let input_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(input).unwrap();

    stdin.write(&input_bytes.as_slice());

    stdin
}

pub fn execute(private_input: &WiresInput) -> ExecuteReport {
    let prover = cpu_prover();
    let stdin = build_stdin(private_input);

    prover
        .execute(guest::elf(), &stdin)
        .run()
        .map(|(public_values, report)| ExecuteReport {
            public_values,
            report,
        })
        .unwrap()
}

pub struct ProvenSolderedLabelsData {
    proof: SP1ProofWithPublicValues,
    vk: SP1VerifyingKey,
}

pub fn prove(private_input: &WiresInput) -> ProvenSolderedLabelsData {
    let prover = cpu_prover();
    let stdin = build_stdin(private_input);

    tracing::info!("start setup");
    let (pk, vk) = prover.setup(guest::elf());
    tracing::info!("start prove");
    let proof = prover.prove(&pk, &stdin).core().run().unwrap();

    ProvenSolderedLabelsData { proof, vk }
}

pub fn verify(data: ProvenSolderedLabelsData) -> SolderedLabelsData {
    cpu_prover().verify(&data.proof, &data.vk).unwrap();

    let archived = unsafe {
        rkyv::access_unchecked::<ArchivedSolderedLabelsData>(data.proof.public_values.as_slice())
    };

    rkyv::deserialize::<SolderedLabelsData, rkyv::rancor::Error>(archived).unwrap()
}

#[cfg(test)]
mod test {
    use std::{iter, ops::BitXor, time::Instant};

    use rand::{rng, Rng};
    use sha2::Digest;
    use test_log::test;

    use crate::types::{ArchivedSolderedLabelsData, SolderedLabelsData, WiresInput};

    fn precalculate_soldered_labels_data(archived: &WiresInput) -> SolderedLabelsData {
        let instances_count = archived.instances_wires.len();

        // Split first instance as base, keep rest as iterator
        let (base_instance, remaining) = archived.instances_wires.split_first().unwrap();
        let wires_count = base_instance.len();
        let soldered_instances_count = instances_count - 1;

        let mut base_commitment = Vec::with_capacity(wires_count);
        let mut commitments: Vec<Vec<([u8; 32], [u8; 32])>> =
            vec![Vec::with_capacity(wires_count); soldered_instances_count];
        let mut deltas = vec![Vec::with_capacity(wires_count); soldered_instances_count];

        // Use multizip to lazily iterate through corresponding positions
        // This transposes the iteration: instead of iterating instances then wires,
        // we iterate wires then instances (all at the same position)
        let all_instances = std::iter::once(base_instance).chain(remaining.iter());

        // Create iterators for each instance
        let mut iters: Vec<_> = all_instances.map(|instance| instance.iter()).collect();

        // Process wire by wire across all instances
        for _wire_id in 0..wires_count {
            // Get next wire from base instance
            let base_wire = iters[0].next().unwrap();

            base_commitment.push((
                sha2::Sha256::digest(base_wire.0.to_be_bytes()).into(),
                sha2::Sha256::digest(base_wire.1.to_be_bytes()).into(),
            ));

            // Get corresponding wire from each remaining instance
            for (idx, iter) in iters[1..].iter_mut().enumerate() {
                let instance_wire = iter.next().unwrap();

                // Hash each label individually like base instance
                commitments[idx].push((
                    sha2::Sha256::digest(instance_wire.0.to_be_bytes()).into(),
                    sha2::Sha256::digest(instance_wire.1.to_be_bytes()).into(),
                ));

                let delta0 = base_wire.0.bitxor(instance_wire.0);
                let delta1 = base_wire.1.bitxor(instance_wire.1);
                deltas[idx].push((delta0, delta1));
            }
        }

        // Compute nonce commitments
        let nonce = archived.nonce;
        let base_nonce_commitment = base_instance
            .iter()
            .map(|wire| {
                let label0_with_nonce = wire.0.bitxor(nonce);
                let label1_with_nonce = wire.1.bitxor(nonce);
                (
                    sha2::Sha256::digest(label0_with_nonce.to_be_bytes()).into(),
                    sha2::Sha256::digest(label1_with_nonce.to_be_bytes()).into(),
                )
            })
            .collect();

        SolderedLabelsData {
            deltas,
            base_commitment,
            base_nonce_commitment,
            commitments,
            nonce: archived.nonce,
        }
    }

    fn rnd_input() -> WiresInput {
        let mut rng = rng();

        WiresInput {
            instances_wires: iter::repeat_with(|| {
                iter::repeat_with(|| rng.random()).take(1019).collect()
            })
            .take(7)
            .collect(),
            nonce: rng.random(),
        }
    }

    #[test]
    #[ignore = "slow zkSNARK generation"]
    fn execute() {
        let input = rnd_input();
        let report = super::execute(&input);
        let bytes = report.public_values.as_slice();

        let archived = unsafe { rkyv::access_unchecked::<ArchivedSolderedLabelsData>(bytes) };

        let on_circuit =
            rkyv::deserialize::<SolderedLabelsData, rkyv::rancor::Error>(archived).unwrap();

        let off_circuit = precalculate_soldered_labels_data(&input);

        assert_eq!(on_circuit, off_circuit);
        println!("{}", report.report);
    }

    #[test]
    #[ignore = "slow zkSNARK generation"]
    fn prove_verify_e2e_with_nonce() {
        let input = rnd_input();

        let timer = Instant::now();
        let data = super::prove(&input);
        tracing::info!("prove time is {}", timer.elapsed().as_secs());

        let result = super::verify(data);
        tracing::info!("verify time is {}", timer.elapsed().as_secs());

        // Verify that nonce commitments are present
        assert_eq!(
            result.base_nonce_commitment.len(),
            result.base_commitment.len()
        );
    }

    #[test]
    #[ignore = "slow zkSNARK generation"]
    fn prove_verify_e2e() {
        let input = rnd_input();
        let timer = Instant::now();
        let data = super::prove(&input);
        tracing::info!("prove time is {}", timer.elapsed().as_secs());

        super::verify(data);
        tracing::info!("verify time is {}", timer.elapsed().as_secs());
    }
}
