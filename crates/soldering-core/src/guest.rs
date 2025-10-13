use sp1_sdk::include_elf;

/// Returns the compiled soldering guest ELF bytes.
pub fn elf() -> &'static [u8] {
    include_elf!("soldering-guest")
}
