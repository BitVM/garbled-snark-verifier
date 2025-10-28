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
    let cpu_has_aes = hardware_aes_available();
    
    // Check if compiled with x86 AES-NI support
    let compiled_with_x86_aesni = cfg!(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "aes",
        target_feature = "sse2"
    ));
    
    // Check if compiled with ARM AES support
    let compiled_with_arm_aes = cfg!(all(
        target_arch = "aarch64",
        target_feature = "aes"
    ));
    
    let compiled_with_aes = compiled_with_x86_aesni || compiled_with_arm_aes;

    if !cpu_has_aes || !compiled_with_aes {
        eprintln!("Warning: AES hardware acceleration not used; falling back to software AES.");
    }
}
