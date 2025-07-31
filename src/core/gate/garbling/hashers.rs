use super::super::{GateId};
use crate::{S, core::s::S_SIZE};

pub trait GateHasher: Clone + Send + Sync {
    fn hash_for_garbling(selected_label: &S, other_label: &S, gate_id: GateId) -> (S, S);
    fn hash_for_degarbling(label: &S, gate_id: GateId) -> S;
}

#[derive(Clone, Debug, Default)]
pub struct Blake3Hasher;

impl GateHasher for Blake3Hasher {
    fn hash_for_garbling(selected_label: &S, other_label: &S, gate_id: GateId) -> (S, S) {
        let h_selected = Self::hash_for_degarbling(selected_label, gate_id);
        let h_other = Self::hash_for_degarbling(other_label, gate_id);
        (h_selected, h_other)
    }

    fn hash_for_degarbling(label: &S, gate_id: GateId) -> S {
        let mut result = [0u8; S_SIZE];
        let mut hasher = blake3::Hasher::new();
        hasher.update(&label.0);
        hasher.update(&gate_id.to_le_bytes());
        let hash = hasher.finalize();
        result.copy_from_slice(&hash.as_bytes()[0..S_SIZE]);
        S(result)
    }
}