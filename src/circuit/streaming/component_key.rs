use std::hash::{DefaultHasher, Hasher};

pub type ComponentKey = [u8; 8];

/// Generate a 16-byte key from component name and optional parameters
///
/// This function creates a deterministic key based on:
/// - The component's full name (typically module_path + function name)
/// - Optional parameter values (typically the "ignored" parameters from the macro)
///
/// The key is used for component identification and caching.
///
/// # Arguments
/// * `name` - The component name
/// * `params` - Optional iterator of parameter (name, bytes) pairs
pub fn generate_component_key<'a>(
    name: &str,
    params: impl IntoIterator<Item = (&'a str, &'a [u8])>,
    output_arity: usize,
    input_wires_len: usize,
) -> ComponentKey {
    let mut hasher = DefaultHasher::default();

    // Hash the component name
    hasher.write(name.as_bytes());
    hasher.write(&output_arity.to_le_bytes());
    hasher.write(&input_wires_len.to_le_bytes());

    // Hash each parameter name and value
    for (param_name, param_bytes) in params {
        hasher.write(b"|"); // separator to avoid collisions
        hasher.write(param_name.as_bytes());
        hasher.write(b"=");
        hasher.write(param_bytes);
    }

    // Extract first 8 bytes as the key
    hasher.finish().to_le_bytes()
}

/// Helper function to hash a single parameter value
/// Convenience wrapper for common case of single parameter
pub fn hash_param(
    name: &str,
    param_name: &str,
    param_bytes: &[u8],
    output_arity: usize,
    input_wires_len: usize,
) -> ComponentKey {
    generate_component_key(
        name,
        [(param_name, param_bytes)],
        output_arity,
        input_wires_len,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation_deterministic() {
        let key1 = generate_component_key("test::component", [], 0, 0);
        let key2 = generate_component_key("test::component", [], 0, 0);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_key_generation_with_params() {
        let param_bytes = 10usize.to_le_bytes();
        let key1 = generate_component_key("test::component", [("w", &param_bytes[..])], 100, 50);
        let key2 = generate_component_key("test::component", [("w", &param_bytes[..])], 100, 50);
        let param_bytes2 = 11usize.to_le_bytes();
        let key3 = generate_component_key("test::component", [("w", &param_bytes2[..])], 100, 50);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_different_names_different_keys() {
        let key1 = generate_component_key("test::component1", [] as [(&str, &[u8]); 0], 0, 0);
        let key2 = generate_component_key("test::component2", [] as [(&str, &[u8]); 0], 0, 0);
        assert_ne!(key1, key2);
    }
}
