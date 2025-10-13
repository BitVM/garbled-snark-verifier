#![allow(clippy::needless_range_loop)]

use garbled_snark_verifier::{
    Delta, GarbledWire, S, init_tracing,
    soldering::{prove_soldering, verify_soldering},
};
use sha2::Digest;

fn main() {
    init_tracing();
    // Configure a small demo; increase for heavier checks
    let wires = std::env::var("WIRES")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1019);
    let instances = std::env::var("INSTANCES")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(7);

    tracing::info!(wires, instances, "soldering_e2e: start");

    // Generate a consistent Free-XOR delta and random wires for base and instances
    let mut rng = rand::thread_rng();
    let delta = Delta::generate(&mut rng);
    let nonce = S::random(&mut rng);

    let base: Vec<GarbledWire> = (0..wires)
        .map(|_| GarbledWire::random(&mut rng, &delta))
        .collect();
    let additional: Vec<Vec<GarbledWire>> = (0..instances)
        .map(|_| {
            (0..wires)
                .map(|_| GarbledWire::random(&mut rng, &delta))
                .collect()
        })
        .collect();

    // Prove and verify with SP1; requires `--features sp1-soldering` and SP1 artifacts
    let proof = prove_soldering(&base, &additional, nonce).expect("prove");
    let out = verify_soldering(proof);
    tracing::info!("soldering_e2e: proof verified");

    assert_eq!(out.deltas.len(), instances, "delta instances mismatch");
    assert_eq!(out.base_commitment.len(), wires, "base commitment mismatch");
    assert_eq!(
        out.commitments.len(),
        instances,
        "instance commitments mismatch"
    );

    // Helper to select a bit label from a GarbledWire
    let pick = |gw: &GarbledWire, bit: bool| -> S { if bit { gw.label1 } else { gw.label0 } };

    // For each wire and each bit, check reconstructability from any known label
    for w in 0..wires {
        // Closure to fetch the delta for (instance, wire, bit)
        let delta_for = |inst_idx: usize, bit: bool| -> S {
            let (d0, d1) = out.deltas[inst_idx][w];
            if bit { d1 } else { d0 }
        };

        for bit in [false, true] {
            // Base → all instances
            let base_label = pick(&base[w], bit);
            for j in 0..instances {
                let expected = pick(&additional[j][w], bit);
                let got = base_label ^ &delta_for(j, bit);
                assert_eq!(
                    got, expected,
                    "wire {w}, bit {bit}: reconstruct inst {j} from base"
                );
            }

            // Check base commitment: SHA256(label_bit)
            let digest = sha2::Sha256::digest(base_label.to_u128().to_be_bytes());
            let commit: [u8; 32] = digest.into();
            let idx = usize::from(bit);
            assert_eq!(
                out.base_commitment[w][idx], commit,
                "wire {w}, bit {bit}: base commitment"
            );

            // From each instance k → recover base → recreate all instances
            for k in 0..instances {
                let known = pick(&additional[k][w], bit);
                let base_rec = known ^ &delta_for(k, bit);
                let base_expected = base_label;
                assert_eq!(
                    base_rec, base_expected,
                    "wire {w}, bit {bit}: recover base from inst {k}"
                );

                for j in 0..instances {
                    let got = base_rec ^ &delta_for(j, bit);
                    let expected = pick(&additional[j][w], bit);
                    assert_eq!(
                        got, expected,
                        "wire {w}, bit {bit}: reconstruct inst {j} from inst {k}"
                    );
                }
            }
        }
    }

    tracing::info!("soldering_e2e: all reconstruction checks passed");
}
