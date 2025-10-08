#![no_main]
sp1_zkvm::entrypoint!(main);

use sha2::Digest;
use soldering_types::Input;

pub fn main() {
    let input = sp1_zkvm::io::read::<Input>();
    let _ = sha2::Sha256::digest(input.private_param.labels[0].labels[0].label0);
    sp1_zkvm::io::commit(&input.public_param);
}
