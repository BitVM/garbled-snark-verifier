/// Arity verification utilities for circuit components
///
/// These utilities help ensure that the arity declared in component macros
/// matches the actual number of output wires at runtime.
use crate::WireId;

/// Macro to verify arity in debug builds
///
/// Usage in component implementations:
/// ```
/// use garbled_snark_verifier::verify_component_arity;
/// let output = vec![1, 2, 3];
/// let input = vec![1, 2];
/// verify_component_arity!("add_generic", output, input.len() + 1);
/// ```
#[macro_export]
macro_rules! verify_component_arity {
    ($name:expr, $output:expr, $expected:expr) => {
        #[cfg(debug_assertions)]
        {
            let actual = $output.len();
            let expected = $expected;
            if actual != expected {
                panic!(
                    "ARITY VERIFICATION FAILED in '{}': expected {} wires, got {}",
                    $name, expected, actual
                );
            }
        }
    };
}

/// Trait for types that can report their wire count
pub trait WireCount {
    fn wire_count(&self) -> usize;
}

impl WireCount for WireId {
    fn wire_count(&self) -> usize {
        1
    }
}

impl WireCount for Vec<WireId> {
    fn wire_count(&self) -> usize {
        self.len()
    }
}

/// Function to verify arity at runtime (always enabled)
pub fn verify_arity(component_name: &str, expected: usize, actual: usize) -> Result<(), String> {
    if expected != actual {
        Err(format!(
            "Arity mismatch in '{}': expected {} wires, got {}",
            component_name, expected, actual
        ))
    } else {
        Ok(())
    }
}

/// Builder pattern for arity verification
pub struct ArityChecker {
    component_name: String,
    expected: Option<usize>,
    actual: Option<usize>,
}

impl ArityChecker {
    pub fn new(component_name: impl Into<String>) -> Self {
        Self {
            component_name: component_name.into(),
            expected: None,
            actual: None,
        }
    }

    pub fn expected(mut self, count: usize) -> Self {
        self.expected = Some(count);
        self
    }

    pub fn actual(mut self, count: usize) -> Self {
        self.actual = Some(count);
        self
    }

    pub fn verify(self) -> Result<(), String> {
        match (self.expected, self.actual) {
            (Some(exp), Some(act)) => verify_arity(&self.component_name, exp, act),
            _ => Err(format!(
                "ArityChecker for '{}': missing expected or actual value",
                self.component_name
            )),
        }
    }

    /// Verify and panic on mismatch (for use in tests)
    pub fn assert(self) {
        if let Err(msg) = self.verify() {
            panic!("{}", msg);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arity_checker() {
        // This should pass
        ArityChecker::new("test_component")
            .expected(10)
            .actual(10)
            .assert();
    }

    #[test]
    #[should_panic(expected = "Arity mismatch")]
    fn test_arity_checker_mismatch() {
        ArityChecker::new("test_component")
            .expected(10)
            .actual(11)
            .assert();
    }

    #[test]
    fn test_verify_arity_function() {
        assert!(verify_arity("test", 5, 5).is_ok());
        assert!(verify_arity("test", 5, 6).is_err());
    }
}
