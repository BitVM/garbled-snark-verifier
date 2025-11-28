use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Wrapper to serialize/deserialize Ark types using compressed canonical form.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
pub struct Canonical<T: CanonicalDeserialize + CanonicalSerialize>(pub T);

impl<T: CanonicalSerialize + CanonicalDeserialize> Serialize for Canonical<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = Vec::new();
        self.0
            .serialize_compressed(&mut bytes)
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de, T: CanonicalSerialize + CanonicalDeserialize> Deserialize<'de> for Canonical<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;

        Ok(Self(
            T::deserialize_compressed(&bytes[..]).map_err(serde::de::Error::custom)?,
        ))
    }
}

pub fn transpose<T: Clone>(m: &[Vec<T>]) -> Vec<Vec<T>> {
    (0..m[0].len())
        .map(|i| m.iter().map(|row| row[i].clone()).collect())
        .collect()
}
