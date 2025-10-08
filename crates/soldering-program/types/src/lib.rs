use serde::*;
use serde::ser::SerializeSeq;

// Serde helpers for Box<[T; N]> arrays of any size.
mod boxed_array {
    use super::*;

    pub fn serialize<S, T, const N: usize>(arr: &Box<[T; N]>, serializer: S) -> Result<S::Ok, S::Error>
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
    pub labels: Box<[InstanceWires; INSTANCE_COUNT]>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Input {
    pub public_param: PublicParams,
    pub private_param: PrivateParams,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicParams {
    pub selection: Box<[bool; INSTANCE_COUNT]>,
    pub commitments: Box<[Commit; INSTANCE_COUNT]>,
    #[serde(with = "boxed_array")]
    pub sha0: Box<[ShaDigest; INPUT_WIRE_COUNT]>,
    #[serde(with = "boxed_array")]
    pub sha1: Box<[ShaDigest; INPUT_WIRE_COUNT]>,
    #[serde(with = "boxed_array")]
    pub deltas0: Box<[WireLabels; INSTANCE_COUNT]>,
    #[serde(with = "boxed_array")]
    pub deltas1: Box<[WireLabels; INSTANCE_COUNT]>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct WireLabels(
    #[serde(with = "boxed_array")] pub Box<[Label; INPUT_WIRE_COUNT]>
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_roundtrip_input_bincode() {
        let zero_label: Label = [0u8; 16];
        let zero_commit: Commit = [0u8; 32];
        let zero_sha: ShaDigest = [0u8; 32];

        let wire_zero = Wire { label0: zero_label, label1: zero_label };
        let wires_for_instance: [Wire; INPUT_WIRE_COUNT] =
            std::array::from_fn(|_| wire_zero.clone());
        let instances: [InstanceWires; INSTANCE_COUNT] = std::array::from_fn(|_| InstanceWires {
            labels: Box::new(wires_for_instance.clone()),
        });

        let selection: [bool; INSTANCE_COUNT] = [false; INSTANCE_COUNT];
        let commitments: [Commit; INSTANCE_COUNT] = std::array::from_fn(|_| zero_commit);
        let sha0: [ShaDigest; INPUT_WIRE_COUNT] = std::array::from_fn(|_| zero_sha);
        let sha1: [ShaDigest; INPUT_WIRE_COUNT] = std::array::from_fn(|_| zero_sha);
        let zero_wire_labels = WireLabels(Box::new(std::array::from_fn(|_| zero_label)));

        let public_param = PublicParams {
            selection: Box::new(selection),
            commitments: Box::new(commitments),
            sha0: Box::new(sha0),
            sha1: Box::new(sha1),
            deltas0: Box::new(std::array::from_fn(|_| zero_wire_labels.clone())),
            deltas1: Box::new(std::array::from_fn(|_| zero_wire_labels.clone())),
        };

        let private_param = PrivateParams {
            labels: Box::new(instances),
        };

        let input = Input { public_param, private_param };

        let bytes = bincode::serialize(&input).expect("serialize to bincode");
        let de: Input = bincode::deserialize(&bytes).expect("deserialize from bincode");
        assert_eq!(input, de);
    }

    #[test]
    fn serde_rejects_wrong_length_bincode() {
        // Build valid parts
        let zero_label: Label = [0u8; 16];
        let wire_zero = Wire { label0: zero_label, label1: zero_label };
        let wires_for_instance: [Wire; INPUT_WIRE_COUNT] =
            std::array::from_fn(|_| wire_zero.clone());
        let instances: [InstanceWires; INSTANCE_COUNT] = std::array::from_fn(|_| InstanceWires {
            labels: Box::new(wires_for_instance.clone()),
        });
        let selection: [bool; INSTANCE_COUNT] = [false; INSTANCE_COUNT];
        let zero_commit: Commit = [0u8; 32];
        let commitments: [Commit; INSTANCE_COUNT] = std::array::from_fn(|_| zero_commit);
        let zero_sha: ShaDigest = [0u8; 32];
        let sha1: [ShaDigest; INPUT_WIRE_COUNT] = std::array::from_fn(|_| zero_sha);
        let zero_wire_labels = WireLabels(Box::new(std::array::from_fn(|_| zero_label)));
        let deltas0 = std::array::from_fn(|_| zero_wire_labels.clone());
        let deltas1 = std::array::from_fn(|_| zero_wire_labels.clone());

        // Define a version with sha0 one element short to produce mismatched length on decode
        #[derive(Serialize)]
        struct PublicParamsWrong {
            selection: Box<[bool; INSTANCE_COUNT]>,
            commitments: Box<[Commit; INSTANCE_COUNT]>,
            #[serde(with = "boxed_array")]
            sha0: Box<[ShaDigest; INPUT_WIRE_COUNT - 1]>,
            #[serde(with = "boxed_array")]
            sha1: Box<[ShaDigest; INPUT_WIRE_COUNT]>,
            #[serde(with = "boxed_array")]
            deltas0: Box<[WireLabels; INSTANCE_COUNT]>,
            #[serde(with = "boxed_array")]
            deltas1: Box<[WireLabels; INSTANCE_COUNT]>,
        }

        #[derive(Serialize)]
        struct InputWrong {
            public_param: PublicParamsWrong,
            private_param: PrivateParams,
        }

        let sha0_short: [ShaDigest; INPUT_WIRE_COUNT - 1] = std::array::from_fn(|_| zero_sha);
        let public_param_wrong = PublicParamsWrong {
            selection: Box::new(selection),
            commitments: Box::new(commitments),
            sha0: Box::new(sha0_short),
            sha1: Box::new(sha1),
            deltas0: Box::new(deltas0),
            deltas1: Box::new(deltas1),
        };

        let private_param = PrivateParams { labels: Box::new(instances) };
        let input_wrong = InputWrong { public_param: public_param_wrong, private_param };

        let bytes = bincode::serialize(&input_wrong).expect("serialize to bincode");
        let res: Result<Input, _> = bincode::deserialize(&bytes);
        assert!(res.is_err(), "expected error on wrong-length boxed array");
    }
}
