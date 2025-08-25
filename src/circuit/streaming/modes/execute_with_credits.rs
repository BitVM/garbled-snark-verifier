use std::{cell::RefCell, iter, time::Instant};

use log::{debug, error};

use crate::{
    CircuitContext, Gate, WireId,
    circuit::streaming::{
        CircuitMode, FALSE_WIRE, TRUE_WIRE, WiresObject, component_meta::ComponentMeta,
    },
    core::gate_type::GateCount,
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
        gate_count: GateCount,
    },
}

impl ExecuteWithCredits {
    pub fn new(capacity: usize) -> Self {
        Self::ExecutePass {
            storage: RefCell::new(Storage::new(capacity)),
            stack: vec![],
            gate_count: GateCount::default(),
        }
    }

    pub fn to_execute_pass(self, capacity: usize) -> Self {
        if let Self::MetadataPass(meta) = self {
            Self::ExecutePass {
                storage: RefCell::new(Storage::new(capacity)),
                stack: vec![meta],
                gate_count: GateCount::default(),
            }
        } else {
            panic!()
        }
    }

    pub fn issue_wire_with_credit(&mut self) -> (WireId, Credits) {
        match self {
            Self::MetadataPass(meta) => (meta.issue_wire(), 0),
            Self::ExecutePass { storage, stack, .. } => {
                let meta = stack.last_mut().unwrap();

                // Normal allocation path
                if let Some(credit) = meta.next_credit() {
                    let wire_id = storage.borrow_mut().allocate(OptionalBoolean::None, credit);
                    (wire_id, credit)
                } else {
                    unreachable!("{self:?}")
                }
            }
        }
    }

    #[cfg(test)]
    fn storage_contains(&self, wire: WireId) -> bool {
        match self {
            Self::ExecutePass { storage, .. } => storage.borrow().contains(wire),
            _ => false,
        }
    }
}

impl CircuitMode for ExecuteWithCredits {
    type WireValue = bool;

    fn lookup_wire(&self, wire: WireId) -> Option<&bool> {
        match wire {
            TRUE_WIRE => Some(&true),
            FALSE_WIRE => Some(&false),
            // Unreachable wires don't have values
            WireId::UNREACHABLE => None,
            wire => match self {
                Self::MetadataPass(_) => None,
                Self::ExecutePass { storage, .. } => {
                    match storage.borrow_mut().get(wire).as_deref() {
                        Ok(&OptionalBoolean::True) => Some(&true),
                        Ok(&OptionalBoolean::False) => Some(&false),
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
        if matches!(wire, TRUE_WIRE | FALSE_WIRE | WireId::UNREACHABLE) {
            return;
        }

        if let Self::ExecutePass { storage, .. } = self {
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
        assert_ne!(gate.wire_a, WireId::UNREACHABLE);
        assert_ne!(gate.wire_b, WireId::UNREACHABLE);

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
        key: &[u8; 16],
        input_wires: Vec<WireId>,
        f: impl Fn(&mut Self) -> O,
        output_arity: impl FnOnce() -> usize,
    ) -> O {
        let arity = output_arity();

        if let Self::MetadataPass(meta) = self {
            debug!("with_named_child: metapass enter name={key:?} arity={arity}");
            meta.increment_credits(&input_wires);

            // We just pre-alloc all outputs for handle credits
            let mock_output = iter::repeat_with(|| meta.issue_wire())
                .take(arity)
                .collect::<Vec<_>>();

            return O::from_wires(&mock_output).unwrap();
        }

        let instance = Instant::now();
        debug!("with_named_child: enter name={key:?} arity={arity}");

        let pre_alloc_output_credits = {
            if let Self::ExecutePass { stack, .. } = self {
                let stack = stack.last_mut().unwrap();

                iter::repeat_with(|| stack.next_credit().unwrap())
                    .take(arity)
                    .collect::<Vec<_>>()
            } else {
                unreachable!()
            }
        };

        let mut child_component_meta =
            Self::MetadataPass(ComponentMeta::new(&input_wires, &pre_alloc_output_credits));

        let meta_wires_output = f(&mut child_component_meta).to_wires_vec();

        let child_component_meta = match child_component_meta {
            Self::MetadataPass(meta) => meta.finalize(&meta_wires_output),
            _ => unreachable!(),
        };

        // Propagate child's measured input usage back to the parent's wires
        if let Self::ExecutePass { stack, storage, .. } = self {
            let mut storage = storage.borrow_mut();
            child_component_meta.for_each_input_extra_credits(|wire_id, extra| {
                if wire_id == TRUE_WIRE || wire_id == FALSE_WIRE {
                    return;
                }

                match extra {
                    0 => {
                        // Just remove one input-pin credit
                        _ = storage.get(wire_id).unwrap();
                    }
                    1 => (),
                    n => {
                        storage.add_credits(wire_id, n - 1).unwrap();
                    }
                }
            });

            stack.push(child_component_meta);
        } else {
            unreachable!()
        };

        let output = f(self);

        if let Self::ExecutePass { stack, .. } = self {
            let used_child_meta = stack.pop();
            assert!(used_child_meta.unwrap().credits_stack.is_empty());
        }

        debug!(
            "with_named_child: exit name={:?} outputs={:?}, duration = {:?} ms",
            key,
            output
                .to_wires_vec()
                .iter()
                .map(|w| w.0)
                .collect::<Vec<_>>(),
            instance.elapsed()
        );
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::gate_type::GateType;

    fn and(a: WireId, b: WireId, c: WireId) -> Gate {
        Gate {
            gate_type: GateType::And,
            wire_a: a,
            wire_b: b,
            wire_c: c,
        }
    }

    #[test]
    fn no_zombie_parent_wire_after_child_reads() {
        // Metadata phase: prepare a single parent internal wire
        let mut meta = ExecuteWithCredits::MetadataPass(ComponentMeta::new(&[], &[]));
        let parent_wire = match &mut meta {
            ExecuteWithCredits::MetadataPass(m) => {
                let w = m.issue_wire();
                // Mimic the parent pass credit for "being passed to child"
                m.increment_credits(&[w]);
                w
            }
            _ => unreachable!(),
        };

        // Switch to execute pass
        let mut ctx = meta.to_execute_pass(8);
        ctx.feed_wire(parent_wire, true);

        // Child uses the parent wire twice; after child returns, parent wire must be fully consumed
        let _out = ctx.with_child(
            vec![parent_wire],
            |child| {
                let out = child.issue_wire();
                child.add_gate(and(parent_wire, parent_wire, out));
                vec![out]
            },
            || 1,
        );

        assert!(
            !ctx.storage_contains(parent_wire),
            "parent wire should be removed from storage (no zombie)"
        );
    }
}
