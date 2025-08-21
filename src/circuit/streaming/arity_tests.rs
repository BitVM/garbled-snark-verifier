// TODO GARBLE: Re-enable arity tests after Execute mode is replaced
// This entire module is commented out because it depends on Execute mode which is being removed

/*
#[cfg(test)]
mod arity_consistency_tests {
    use crate::{
        WireId,
        circuit::streaming::{CircuitMode, Execute},
    };

    /// Wrapper for Execute mode that verifies arity matches actual output
    pub struct ExecuteWithArityCheck {
        inner: Execute,
        expected_arity: Option<usize>,
    }

    impl ExecuteWithArityCheck {
        pub fn new() -> Self {
            Self {
                inner: Execute::default(),
                expected_arity: None,
            }
        }

        pub fn expect_arity(mut self, arity: usize) -> Self {
            self.expected_arity = Some(arity);
            self
        }
    }

    impl CircuitMode for ExecuteWithArityCheck {
        type WireValue = bool;

        fn lookup_wire(&self, wire: WireId) -> Option<&bool> {
            self.inner.lookup_wire(wire)
        }

        fn feed_wire(&mut self, wire: WireId, value: bool) {
            self.inner.feed_wire(wire, value)
        }

        fn total_size(&self) -> usize {
            self.inner.total_size()
        }

        fn current_size(&self) -> usize {
            self.inner.current_size()
        }

        fn push_frame(&mut self, name: &'static str, inputs: &[WireId]) {
            self.inner.push_frame(name, inputs)
        }

        fn pop_frame(&mut self, outputs: &[WireId]) -> Vec<(WireId, bool)> {
            self.inner.pop_frame(outputs)
        }

        fn evaluate_gate(&mut self, gate: &crate::Gate) -> Option<()> {
            self.inner.evaluate_gate(gate)
        }
    }

    #[test]
    fn test_bigint_add_arity() {
        // Test will be re-enabled when Execute mode is replaced
    }
}
*/
