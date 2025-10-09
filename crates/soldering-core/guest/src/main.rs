#![no_main]
sp1_zkvm::entrypoint!(main);

#[path = "../../src/types.rs"]
mod types;

#[path = "../../src/common.rs"]
mod common;

use common::compute_public_params;
use types::{Input, INPUT_WIRE_COUNT, SOLDERED_INSTANCE};

pub fn main() {
    let input = sp1_zkvm::io::read::<Input<INPUT_WIRE_COUNT, SOLDERED_INSTANCE>>();

    let expected_public = compute_public_params(&input.private_param);

    assert_eq!(
        expected_public, input.public_param,
        "public params mismatch between computed values and provided input"
    );

    sp1_zkvm::io::commit(&input.public_param);
}
