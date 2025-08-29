use super::{GateId, GateType};
use crate::{Delta, EvaluatedWire, GarbledWire};

pub mod aes_ni;
pub mod hashers;
pub use hashers::{AesNiHasher, Blake3Hasher, GateHasher};

pub fn garble<H: GateHasher>(
    gate_id: GateId,
    gate_type: GateType,
    a: &GarbledWire,
    b: &GarbledWire,
    delta: &Delta,
) -> (crate::S, crate::S) {
    let (alpha_a, alpha_b, alpha_c) = gate_type.alphas();

    let selected_label = a.select(alpha_a);
    let other_label = a.select(!alpha_a);
    let (h_a0, h_a1) = H::hash_for_garbling(&selected_label, &other_label, gate_id);

    let ct = h_a0 ^ &h_a1 ^ &b.select(alpha_b);

    let w = if alpha_c { h_a0 ^ delta } else { h_a0 };

    (ct, w)
}

pub fn degarble<H: GateHasher>(
    gate_id: GateId,
    gate_type: GateType,
    ciphertext: &crate::S,
    a: &EvaluatedWire,
    b: &EvaluatedWire,
) -> crate::S {
    let h_a = H::hash_for_degarbling(&a.active_label, gate_id);

    let (alpha_a, _alpha_b, _alpha_c) = gate_type.alphas();

    if a.value() != alpha_a {
        ciphertext ^ &h_a ^ &b.active_label
    } else {
        h_a
    }
}

#[cfg(test)]
mod aes_ni_test;
#[cfg(test)]
mod tests;
