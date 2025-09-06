// Small runtime helpers related to AES acceleration availability.

#[inline]
pub fn hardware_aes_available() -> bool {
    // x86/x86_64: check AES-NI
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        is_x86_feature_detected!("aes")
    }

    // aarch64: check ARMv8 AES
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("aes")
    }

    // Other architectures: conservatively assume no hardware AES
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}

#[inline]
pub fn warn_if_software_aes() {
    if !hardware_aes_available() {
        eprintln!(
            "Warning: AES hardware acceleration not detected; using software AES (not constant-time)."
        );
    }
}
