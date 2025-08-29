use crate::EvaluatedWire;

/// Simple commit, to be replaced in the future
pub type Commit = Vec<u8>;

/// Simple commit, to be replaced in the future
pub fn commit(wires: impl Iterator<Item = EvaluatedWire>) -> Commit {
    let mut hasher = blake3::Hasher::default();

    wires.for_each(|evaluated| {
        let b = evaluated.active_label.to_bytes();
        hasher.update(&b);
        hasher.update(&[evaluated.value() as u8]);
    });

    hasher.finalize().as_bytes().to_vec()
}
