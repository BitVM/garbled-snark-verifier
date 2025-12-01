use ark_ff::{BigInteger, PrimeField};
use ark_secp256k1::Fr;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::{EvaluatedWire, GarbledWire, S};

const TAG_LEN: usize = 16;

#[derive(Serialize, Deserialize, Hash, Debug, Clone)]
pub struct GarbledWideLabelTable(Vec<Vec<u8>>);

impl GarbledWideLabelTable {
    pub fn build_all(byte_labels: &[Fr], bit_labels: &[GarbledWire]) -> Vec<Self> {
        byte_labels
            .chunks(256)
            .zip(bit_labels.chunks(8))
            .map(|(byte_labels, bit_labels)| GarbledWideLabelTable::new(byte_labels, bit_labels))
            .collect()
    }

    fn new(byte_labels: &[Fr], bit_labels: &[GarbledWire]) -> Self {
        assert_ne!(bit_labels.len(), 0);
        assert_ne!(byte_labels.len(), 0);
        assert_eq!(byte_labels.len(), 2usize.pow(bit_labels.len() as u32));

        let table = byte_labels
            .iter()
            .enumerate()
            .map(|(i, byte_label)| {
                let bit_labels: Vec<u8> = (0..bit_labels.len())
                    .map(|bit| {
                        if ((i >> (bit_labels.len() - bit - 1)) & 1) == 0 {
                            bit_labels[bit].label0
                        } else {
                            bit_labels[bit].label1
                        }
                    })
                    .flat_map(|label| label.to_bytes())
                    .chain(std::iter::repeat_n(0u8, TAG_LEN))
                    .collect();

                let mut blake_hash = blake3::Hasher::new();
                let mut mask = (0..bit_labels.len()).map(|_| 0u8).collect_vec();
                blake_hash.update(&byte_label.into_bigint().to_bytes_le());
                blake_hash.finalize_xof().fill(&mut mask);

                bit_labels
                    .iter()
                    .zip(mask.iter())
                    .map(|(c, m)| c ^ m)
                    .collect_vec()
            })
            .collect();
        GarbledWideLabelTable(table)
    }

    pub fn aggregate_hash(tables: &[Self]) -> [u8; 32] {
        // calculate a hash over all the wide label lookup tables
        let mut hasher = blake3::Hasher::new();
        for table in tables.iter() {
            let bytes = table.0.iter().flatten().copied().collect_vec();
            hasher.update(&bytes);
        }
        let hash = hasher.finalize();
        *hash.as_bytes()
    }

    pub fn lookup(&self, wide_label: &Fr) -> Vec<S> {
        self.lookup_evaluated_wires(wide_label)
            .iter()
            .map(|evaluated_wire| evaluated_wire.active_label)
            .collect_vec()
    }

    pub fn lookup_index(&self, wide_label: &Fr) -> usize {
        self.lookup_evaluated_wires_and_index(wide_label).0
    }

    pub fn lookup_evaluated_wires(&self, wide_label: &Fr) -> Vec<EvaluatedWire> {
        self.lookup_evaluated_wires_and_index(wide_label).1
    }

    pub fn lookup_evaluated_wires_and_index(&self, wide_label: &Fr) -> (usize, Vec<EvaluatedWire>) {
        self.0
            .iter()
            .enumerate()
            .find_map(|(wide_label_idx, ciphertext)| {
                let label_count = self.0.len().ilog2();
                assert_eq!(ciphertext.len(), label_count as usize * 16 + TAG_LEN);

                let mut mask = vec![0u8; ciphertext.len()];
                let mut blake_hash = blake3::Hasher::new();
                blake_hash.update(&wide_label.into_bigint().to_bytes_le());
                blake_hash.finalize_xof().fill(&mut mask[..]);

                let decrypted = ciphertext
                    .iter()
                    .zip(mask.iter())
                    .map(|(c, m)| c ^ m)
                    .collect_vec();

                let (labels, tag) = decrypted.split_at(decrypted.len() - TAG_LEN);

                let successful_decryption = tag.iter().all(|x| *x == 0);

                successful_decryption.then_some((
                    wide_label_idx,
                    labels
                        .chunks(16)
                        .enumerate()
                        .map(|(bit_idx, chunk)| {
                            let label = S::from_bytes(
                                chunk.try_into().expect("should be exactly 16 items"),
                            );
                            let bit_value =
                                ((wide_label_idx >> (label_count as usize - bit_idx - 1)) & 1) == 1;
                            EvaluatedWire::new(label, bit_value)
                        })
                        .collect_vec(),
                ))
            })
            .expect("Failed to decrypt wide label lookup table with the given key")
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::UniformRand;
    use rand::thread_rng;

    use super::*;
    use crate::Delta;

    #[test]
    fn test_garbled_wide_label_table_lookup() {
        let mut rng = thread_rng();

        let delta = Delta::generate(&mut rng);

        for num_bits in [2, 8] {
            let num_labels = 2u32.pow(num_bits as u32);
            let bit_labels = (0..num_bits)
                .map(|_| GarbledWire::random(&mut rng, &delta))
                .collect_vec();
            let byte_labels = (0..num_labels).map(|_| Fr::rand(&mut rng)).collect_vec();

            let table = GarbledWideLabelTable::new(&byte_labels, &bit_labels);

            let expected_vals = (0..num_labels)
                .map(|i| {
                    (0..num_bits)
                        .map(|bit| {
                            if ((i >> (num_bits - bit - 1)) & 1) == 0 {
                                EvaluatedWire::new(bit_labels[bit].label0, false)
                            } else {
                                EvaluatedWire::new(bit_labels[bit].label1, true)
                            }
                        })
                        .collect_vec()
                })
                .collect_vec();

            for (byte_label, expected_vals) in byte_labels.iter().zip(expected_vals.iter()) {
                let recovered_bit_labels = table.lookup_evaluated_wires(byte_label);
                assert_eq!(&recovered_bit_labels[..], &expected_vals[..]);
            }

            println!("table size: {}", table.0.iter().flatten().count());
        }
    }
}
