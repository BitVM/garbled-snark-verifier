use slotmap::{SlotMap, new_key_type};

use crate::{Gate, WireId};

new_key_type! { pub struct ComponentId; }

#[derive(Clone, Debug)]
pub enum Action {
    Gate(Gate),
    Call { id: ComponentId },
}

#[derive(Clone, Debug)]
pub struct Component {
    pub name: &'static str,
    pub internal_wire_offset: usize,
    pub num_wire: usize,
    pub input_wires: Vec<WireId>,
    pub output_wires: Vec<WireId>,
    pub actions: Vec<Action>,
}

impl Component {
    pub fn empty_root() -> Self {
        Self {
            name: "root",
            internal_wire_offset: 0,
            num_wire: 2,
            input_wires: Vec::new(),
            output_wires: Vec::new(),
            actions: Vec::new(),
        }
    }
}

pub struct ComponentPool(pub(super) SlotMap<ComponentId, Component>);

impl ComponentPool {
    pub(super) fn new() -> Self {
        ComponentPool(SlotMap::with_key())
    }

    pub(super) fn insert(&mut self, c: Component) -> ComponentId {
        self.0.insert(c)
    }

    pub(super) fn remove(&mut self, id: ComponentId) -> Component {
        self.0.remove(id).unwrap()
    }

    pub(super) fn get(&self, id: ComponentId) -> &Component {
        &self.0[id]
    }

    pub(super) fn get_mut(&mut self, id: ComponentId) -> &mut Component {
        &mut self.0[id]
    }

    pub(super) fn take(&mut self, id: ComponentId) -> Component {
        self.0.remove(id).unwrap()
    }
}
