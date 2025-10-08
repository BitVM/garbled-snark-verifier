use serde::{ser::SerializeSeq, *};

// Serde helpers for Box<[T; N]> arrays of any size.
mod boxed_array {
    use super::*;

    pub fn serialize<S, T, const N: usize>(
        arr: &Box<[T; N]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: Serialize,
    {
        let mut seq = serializer.serialize_seq(Some(N))?;
        for item in arr.iter() {
            seq.serialize_element(item)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D, T, const N: usize>(deserializer: D) -> Result<Box<[T; N]>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        let v: Vec<T> = Vec::deserialize(deserializer)?;
        if v.len() != N {
            return Err(serde::de::Error::custom(format!(
                "expected array of length {}, got {}",
                N,
                v.len()
            )));
        }
        // SAFETY: length is checked to be exactly N above.
        let boxed_slice: Box<[T]> = v.into_boxed_slice();
        let boxed_array = boxed_slice.try_into().map_err(|boxed: Box<[T]>| {
            serde::de::Error::custom(format!(
                "failed to convert boxed slice of length {} to boxed array of length {}",
                boxed.len(),
                N
            ))
        })?;
        Ok(boxed_array)
    }
}

pub const INPUT_WIRE_COUNT: usize = 1093;
pub const INSTANCE_COUNT: usize = 7;

pub type Label = [u8; 16];
pub type Commit = [u8; 32];
pub type ShaDigest = [u8; 32];

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Wire {
    pub label0: Label,
    pub label1: Label,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct InstanceWires {
    #[serde(with = "boxed_array")]
    pub labels: Box<[Wire; INPUT_WIRE_COUNT]>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PrivateParams {
    pub input_labels: Box<[InstanceWires; INSTANCE_COUNT]>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Input {
    pub public_param: PublicParams,
    pub private_param: PrivateParams,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum InstanceCommitment {
    /// For the first instance, we store sha256 on each input wire
    Core {
        #[serde(with = "boxed_array")]
        sha256_commit: Box<[[ShaDigest; 2]; INPUT_WIRE_COUNT]>,
    },
    /// For all instances except the first we store poseidon on aggregate commit over labels
    Additional { poseidon_commit: Commit },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicParams {
    pub commitments: Box<[InstanceCommitment; INSTANCE_COUNT]>,
    #[serde(with = "boxed_array")]
    pub deltas0: Box<[WireLabels; INSTANCE_COUNT]>,
    #[serde(with = "boxed_array")]
    pub deltas1: Box<[WireLabels; INSTANCE_COUNT]>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct WireLabels(#[serde(with = "boxed_array")] pub Box<[Label; INPUT_WIRE_COUNT]>);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_roundtrip_input_bincode() {
        let zero_label: Label = [0u8; 16];
        let zero_commit: Commit = [0u8; 32];
        let zero_sha: ShaDigest = [0u8; 32];

        let wire_zero = Wire {
            label0: zero_label,
            label1: zero_label,
        };
        let wires_for_instance: [Wire; INPUT_WIRE_COUNT] =
            std::array::from_fn(|_| wire_zero.clone());
        let instances: [InstanceWires; INSTANCE_COUNT] = std::array::from_fn(|_| InstanceWires {
            labels: Box::new(wires_for_instance.clone()),
        });

        let commitments: [InstanceCommitment; INSTANCE_COUNT] =
            std::array::from_fn(|instance_index| {
                if instance_index == 0 {
                    InstanceCommitment::Core {
                        sha256_commit: Box::new(std::array::from_fn(|_| [zero_sha; 2])),
                    }
                } else {
                    InstanceCommitment::Additional {
                        poseidon_commit: zero_commit,
                    }
                }
            });
        let zero_wire_labels = WireLabels(Box::new(std::array::from_fn(|_| zero_label)));

        let public_param = PublicParams {
            commitments: Box::new(commitments),
            deltas0: Box::new(std::array::from_fn(|_| zero_wire_labels.clone())),
            deltas1: Box::new(std::array::from_fn(|_| zero_wire_labels.clone())),
        };

        let private_param = PrivateParams {
            input_labels: Box::new(instances),
        };

        let input = Input {
            public_param,
            private_param,
        };

        let bytes = bincode::serialize(&input).expect("serialize to bincode");
        let de: Input = bincode::deserialize(&bytes).expect("deserialize from bincode");
        assert_eq!(input, de);
    }

    #[test]
    fn serde_rejects_wrong_length_bincode() {
        // Build valid parts
        let zero_label: Label = [0u8; 16];
        let wire_zero = Wire {
            label0: zero_label,
            label1: zero_label,
        };
        let wires_for_instance: [Wire; INPUT_WIRE_COUNT] =
            std::array::from_fn(|_| wire_zero.clone());
        let instances: [InstanceWires; INSTANCE_COUNT] = std::array::from_fn(|_| InstanceWires {
            labels: Box::new(wires_for_instance.clone()),
        });
        let zero_commit: Commit = [0u8; 32];
        let zero_sha: ShaDigest = [0u8; 32];
        let zero_wire_labels = WireLabels(Box::new(std::array::from_fn(|_| zero_label)));
        let deltas0 = std::array::from_fn(|_| zero_wire_labels.clone());
        let deltas1 = std::array::from_fn(|_| zero_wire_labels.clone());

        // Define a version with sha256_commit one element short to produce mismatched length on decode
        #[derive(Serialize)]
        struct PublicParamsWrong {
            commitments: Box<[InstanceCommitmentWrong; INSTANCE_COUNT]>,
            #[serde(with = "boxed_array")]
            deltas0: Box<[WireLabels; INSTANCE_COUNT]>,
            #[serde(with = "boxed_array")]
            deltas1: Box<[WireLabels; INSTANCE_COUNT]>,
        }

        #[derive(Serialize)]
        enum InstanceCommitmentWrong {
            Core {
                #[serde(with = "boxed_array")]
                sha256_commit: Box<[[ShaDigest; 2]; INPUT_WIRE_COUNT - 1]>,
            },
            Additional {
                poseidon_commit: Commit,
            },
        }

        #[derive(Serialize)]
        struct InputWrong {
            public_param: PublicParamsWrong,
            private_param: PrivateParams,
        }

        let commitments_wrong: [InstanceCommitmentWrong; INSTANCE_COUNT] =
            std::array::from_fn(|instance_index| {
                if instance_index == 0 {
                    InstanceCommitmentWrong::Core {
                        sha256_commit: Box::new(std::array::from_fn(|_| [zero_sha; 2])),
                    }
                } else {
                    InstanceCommitmentWrong::Additional {
                        poseidon_commit: zero_commit,
                    }
                }
            });
        let public_param_wrong = PublicParamsWrong {
            commitments: Box::new(commitments_wrong),
            deltas0: Box::new(deltas0),
            deltas1: Box::new(deltas1),
        };

        let private_param = PrivateParams {
            input_labels: Box::new(instances),
        };
        let input_wrong = InputWrong {
            public_param: public_param_wrong,
            private_param,
        };

        let bytes = bincode::serialize(&input_wrong).expect("serialize to bincode");
        let res: Result<Input, _> = bincode::deserialize(&bytes);
        assert!(res.is_err(), "expected error on wrong-length boxed array");
    }
}
