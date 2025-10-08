#![no_main]
sp1_zkvm::entrypoint!(main);

use soldering_types::Input;

pub fn main() {
    let input = sp1_zkvm::io::read::<Input>();
    sp1_zkvm::io::commit(&input.public_param);
}
