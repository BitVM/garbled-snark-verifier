use std::cell::RefCell;

use log::{debug, error, trace};

use crate::{
    CircuitContext, Gate, WireId,
    circuit::streaming::{
        CircuitMode, FALSE_WIRE, TRUE_WIRE, WiresObject, component_meta::ComponentMeta,
    },
    storage::{Credits, Storage},
};

#[derive(Clone, Copy, Debug, Default)]
pub enum OptionalBoolean {
    #[default]
    None,
    True,
    False,
}

/// Prototype mode: single global storage keyed by `WireId` with credit-based lifetimes.
///
/// Notes:
/// - For now there is no prepass integration here; callers can `feed_wire` to seed inputs
///   and we consume credits on reads during gate evaluation.
/// - Constants are stored outside of `WireStorage` and don't consume credits.
#[derive(Debug)]
pub enum ExecuteWithCredits {
    MetadataPass(ComponentMeta),
    ExecutePass {
        storage: RefCell<Storage<WireId, OptionalBoolean>>,
        stack: Vec<ComponentMeta>,
    },
}

impl ExecuteWithCredits {
    pub fn new(capacity: usize) -> Self {
        debug!("ExecuteWithCredits::new capacity={}", capacity);
        Self::ExecutePass {
            storage: RefCell::new(Storage::new(capacity)),
            stack: vec![],
        }
    }

    pub fn to_execute_pass(self, capacity: usize) -> Self {
        if let Self::MetadataPass(meta) = self {
            debug!(
                "ExecuteWithCredits::to_execute_pass: start execute with stack depth=1 capacity={}",
                capacity
            );
            Self::ExecutePass {
                storage: RefCell::new(Storage::new(capacity)),
                stack: vec![meta],
            }
        } else {
            panic!()
        }
    }

    pub fn issue_wire_with_credit(&mut self) -> (WireId, Credits) {
        match self {
            Self::MetadataPass(meta) => (meta.issue_wire(), 0),
            Self::ExecutePass { storage, stack } => {
                let meta = stack.last_mut().unwrap();

                // Check if this issue position has a substitution
                if let Some((wire_id, credits)) = meta.check_substitution() {
                    debug!(
                        "issue_wire_with_credit: substitution hit wire_id={} credits={} stack_depth={}",
                        wire_id.0,
                        credits,
                        stack.len()
                    );
                    return (wire_id, credits);
                }

                // Normal allocation path
                if let Some(credit) = meta.next_credit() {
                    let wire_id = storage.borrow_mut().allocate(OptionalBoolean::None, credit);
                    debug!(
                        "issue_wire_with_credit: allocated wire_id={} credits={} stack_depth={}",
                        wire_id.0,
                        credit,
                        stack.len()
                    );
                    (wire_id, credit)
                } else {
                    unreachable!("{self:?}")
                }
            }
        }
    }
}

impl CircuitMode for ExecuteWithCredits {
    type WireValue = bool;

    fn lookup_wire(&self, wire: WireId) -> Option<&bool> {
        use crate::WireId as CoreWireId;

        match wire {
            TRUE_WIRE => Some(&true),
            FALSE_WIRE => Some(&false),
            // Unreachable wires don't have values
            wire if wire == CoreWireId::UNREACHABLE => None,
            wire => match self {
                Self::MetadataPass(_) => None,
                Self::ExecutePass { storage, .. } => {
                    trace!("lookup_wire: wire_id={} -> get()", wire.0);
                    match storage.borrow_mut().get(wire).as_deref() {
                        Ok(&OptionalBoolean::True) => {
                            trace!("lookup_wire: wire_id={} = True", wire.0);
                            Some(&true)
                        }
                        Ok(&OptionalBoolean::False) => {
                            trace!("lookup_wire: wire_id={} = False", wire.0);
                            Some(&false)
                        }
                        Ok(&OptionalBoolean::None) => {
                            error!("lookup_wire: wire_id={} has no value yet", wire.0);
                            panic!("value not writed: {wire:?}")
                        }
                        Err(err) => {
                            error!(
                                "lookup_wire: storage error for wire_id={} err={:?}",
                                wire.0, err
                            );
                            panic!("Error: {err:?}")
                        }
                    }
                }
            },
        }
    }

    fn feed_wire(&mut self, wire: WireId, value: Self::WireValue) {
        if matches!(wire, TRUE_WIRE | FALSE_WIRE) {
            return;
        }

        // Skip unreachable wires (those with 0 credits that are never read)
        if wire == WireId::UNREACHABLE {
            return;
        }

        if let Self::ExecutePass { storage, .. } = self {
            trace!("feed_wire: wire_id={} value={}", wire.0, value);
            storage
                .borrow_mut()
                .set(wire, |data| {
                    *data = if value {
                        OptionalBoolean::True
                    } else {
                        OptionalBoolean::False
                    };
                })
                .unwrap();
        }
    }

    fn total_size(&self) -> usize {
        if let Self::ExecutePass { storage, .. } = self {
            storage.borrow().len()
        } else {
            0
        }
    }

    fn current_size(&self) -> usize {
        if let Self::ExecutePass { storage, .. } = self {
            storage.borrow().len()
        } else {
            0
        }
    }

    fn push_frame(&mut self, _name: &'static str, _inputs: &[WireId]) {
        // Not used in this prototype mode
    }

    fn pop_frame(&mut self, _outputs: &[WireId]) -> Vec<(WireId, Self::WireValue)> {
        // Not used in this prototype mode
        vec![]
    }

    fn evaluate_gate(&mut self, gate: &Gate) -> Option<()> {
        trace!(
            "evaluate_gate: kind={:?} a={} b={} -> c={}",
            gate.gate_type, gate.wire_a.0, gate.wire_b.0, gate.wire_c.0
        );
        let a = self.lookup_wire(gate.wire_a)?;
        let b = self.lookup_wire(gate.wire_b)?;

        let c = gate.execute(*a, *b);
        self.feed_wire(gate.wire_c, c);

        Some(())
    }
}

impl CircuitContext for ExecuteWithCredits {
    type Mode = Self;

    fn issue_wire(&mut self) -> WireId {
        self.issue_wire_with_credit().0
    }

    fn add_gate(&mut self, gate: Gate) {
        if let Self::MetadataPass(meta) = self {
            meta.add_gate(gate);
            return;
        }

        self.evaluate_gate(&gate);
    }

    fn with_named_child<O: WiresObject>(
        &mut self,
        _name: &'static str,
        input_wires: Vec<WireId>,
        f: impl Fn(&mut Self) -> O,
        output_arity: impl FnOnce() -> usize,
    ) -> O {
        let arity = output_arity();
        debug!("with_named_child: enter name={} arity={}", _name, arity);

        if let Self::MetadataPass(meta) = self {
            meta.increment_credits(&input_wires);

            let mock_output = std::iter::repeat_with(|| meta.issue_wire())
                .take(arity)
                .collect::<Vec<_>>();

            // So that these wires are not deleted before time and can be substituted inside the
            // child, we save them in advance
            //
            // WIP ERROR Now these credits are not deducted after calling the child for quick
            // debugging purposes
            meta.increment_credits(&mock_output);
            debug!(
                "with_named_child[meta]: inputs={:?} mock_outputs={:?}",
                input_wires.iter().map(|w| w.0).collect::<Vec<_>>(),
                mock_output.iter().map(|w| w.0).collect::<Vec<_>>()
            );

            return O::from_wires(&mock_output).unwrap();
        }

        // Phase 1: Run child with metadata to discover output wire positions
        let mut child_meta = Self::MetadataPass(ComponentMeta::new(&input_wires, &[]));
        let meta_wires_output = f(&mut child_meta).to_wires_vec();

        let mut child_meta = match child_meta {
            Self::MetadataPass(meta) => meta,
            _ => unreachable!(),
        };

        // Get which child internal wires will be outputs (by their issue position)
        let output_indices = child_meta.get_issue_indices(&meta_wires_output);
        debug!(
            "with_named_child[exec]: output_indices={:?}",
            output_indices
        );

        // Propagate child's measured input usage back to the parent's wires
        if let Self::ExecutePass { storage, .. } = self {
            let input_counts = child_meta.external_input_counts(input_wires.len());
            debug!(
                "with_named_child[exec]: child_input_counts={:?} inputs={:?}",
                input_counts,
                input_wires.iter().map(|w| w.0).collect::<Vec<_>>()
            );
            for (wire, count) in input_wires.iter().copied().zip(input_counts.into_iter()) {
                // Adjust for the parent's metadata pass that counted a +1 "pass" credit.
                // Execution does not consume a read at call time, so we only need (count - 1)
                // extra credits to match the child's real reads.
                let extra = count.saturating_sub(1);
                debug!(
                    "with_named_child[exec]: child_reads={} -> add extra credits wire_id={} +{}",
                    count, wire.0, extra
                );
                if extra > 0 {
                    // Ignore errors for constants/unreachable; those should not appear here
                    let _ = storage.borrow_mut().add_credits(wire, extra);
                }
            }
        }
        // Phase 2: Pre-allocate parent output wires with credits
        let child_preallocated_outputs: Vec<_> =
            (0..arity).map(|_| self.issue_wire_with_credit()).collect();
        debug!(
            "with_named_child[exec]: prealloc_outputs={:?}",
            child_preallocated_outputs
                .iter()
                .map(|(w, c)| (w.0, *c))
                .collect::<Vec<_>>()
        );

        // Phase 3: Setup substitutions in child metadata
        child_meta.setup_substitutions(&output_indices, &child_preallocated_outputs);

        // Phase 4: Execute child with substitutions active
        if let Self::ExecutePass { stack, .. } = self {
            trace!(
                "with_named_child[exec]: push child meta; stack_depth={}",
                stack.len() + 1
            );
            stack.push(child_meta);
        }

        let output = f(self);

        if let Self::ExecutePass { stack, .. } = self {
            trace!(
                "with_named_child[exec]: pop child meta; stack_depth={}",
                stack.len() - 1
            );
            stack.pop();
        }

        debug!(
            "with_named_child: exit name={} outputs={:?}",
            _name,
            output
                .to_wires_vec()
                .iter()
                .map(|w| w.0)
                .collect::<Vec<_>>()
        );
        output
    }
}
