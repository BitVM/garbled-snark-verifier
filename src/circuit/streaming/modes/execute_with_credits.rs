use std::{cell::RefCell, iter};

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
    FirstPass(ComponentMeta),
    SecondPass {
        storage: RefCell<Storage<WireId, OptionalBoolean>>,
        stack: Vec<ComponentMeta>,
    },
}

impl ExecuteWithCredits {
    pub fn new(capacity: usize) -> Self {
        Self::SecondPass {
            storage: RefCell::new(Storage::new(capacity)),
            stack: vec![],
        }
    }

    pub fn to_second_pass(self, capacity: usize) -> Self {
        if let Self::FirstPass(meta) = self {
            Self::SecondPass {
                storage: RefCell::new(Storage::new(capacity)),
                stack: vec![meta],
            }
        } else {
            panic!()
        }
    }

    pub fn issue_wire_with_credit(&mut self) -> (WireId, Credits) {
        match self {
            Self::FirstPass(meta) => (meta.issue_wire(), 0),
            Self::SecondPass { storage, stack } => {
                if let Some(credit) = stack.last_mut().unwrap().next_credit() {
                    let wire_id = storage.borrow_mut().allocate(OptionalBoolean::None, credit);
                    dbg!(format!("Issue new wire {wire_id} with credits: {credit}"));

                    (wire_id, credit)
                } else {
                    // This Wire will not be used further, can be any Wire
                    (WireId::UNREACHABLE, 0)
                }
            }
        }
    }
}

impl CircuitMode for ExecuteWithCredits {
    type WireValue = bool;

    fn lookup_wire(&self, wire: WireId) -> Option<&bool> {
        match wire {
            TRUE_WIRE => Some(&true),
            FALSE_WIRE => Some(&false),
            wire => match self {
                Self::FirstPass(_) => None,
                Self::SecondPass { storage, .. } => {
                    dbg!(format!("lookup for {wire:?}"));

                    match storage.borrow_mut().get(wire).as_deref() {
                        Ok(&OptionalBoolean::True) => Some(&true),
                        Ok(&OptionalBoolean::False) => Some(&false),
                        Ok(&OptionalBoolean::None) => panic!("value not writed: {wire:?}"),
                        Err(err) => panic!("Error: {err:?}"),
                    }
                }
            },
        }
    }

    fn feed_wire(&mut self, wire: WireId, value: Self::WireValue) {
        if matches!(wire, TRUE_WIRE | FALSE_WIRE) {
            return;
        }

        if let Self::SecondPass { storage, .. } = self {
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
        if let Self::SecondPass { storage, .. } = self {
            storage.borrow().len()
        } else {
            0
        }
    }

    fn current_size(&self) -> usize {
        if let Self::SecondPass { storage, .. } = self {
            storage.borrow().len()
        } else {
            0
        }
    }

    fn push_frame(&mut self, _name: &'static str, _inputs: &[WireId]) {
        todo!("check")
    }

    fn pop_frame(&mut self, _outputs: &[WireId]) -> Vec<(WireId, Self::WireValue)> {
        todo!("check")
    }

    fn evaluate_gate(&mut self, gate: &Gate) -> Option<()> {
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
        if let Self::FirstPass(meta) = self {
            return meta.issue_wire();
        }

        self.issue_wire_with_credit().0
    }

    fn add_gate(&mut self, gate: Gate) {
        if let Self::FirstPass(meta) = self {
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
        dbg!("start child handler");
        let arity = output_arity();

        if let Self::FirstPass(meta) = self {
            meta.increment_credits(&input_wires);

            let mock_output = std::iter::repeat_with(|| self.issue_wire())
                .take(arity)
                .collect::<Vec<_>>();

            return O::from_wires(&mock_output).unwrap();
        }

        let output = iter::repeat_with(|| self.issue_wire_with_credit())
            .take(arity)
            .collect::<Vec<_>>();

        let mut meta = Self::FirstPass(ComponentMeta::new(&input_wires, &output));

        f(&mut meta);

        let meta = match meta {
            Self::FirstPass(meta) => meta,
            _ => unreachable!(),
        };
        if let Self::SecondPass { stack, .. } = self {
            stack.push(meta);
        }

        let output = f(self);

        if let Self::SecondPass { stack, .. } = self {
            stack.pop();
        }

        output
    }
}
