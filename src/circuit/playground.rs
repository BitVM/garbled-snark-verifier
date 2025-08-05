#![allow(dead_code)]

use std::collections::HashMap;

use slotmap::{new_key_type, SlotMap};

use crate::{Gate, WireId};

pub trait IntoWires {
    fn get_wires_vec(&self) -> Vec<WireId>;
}
impl IntoWires for WireId {
    fn get_wires_vec(&self) -> Vec<WireId> {
        vec![*self]
    }
}
impl IntoWires for Vec<WireId> {
    fn get_wires_vec(&self) -> Vec<WireId> {
        self.clone()
    }
}

/// Simplified CircuitContext trait for hierarchical circuit building
/// Focuses on core operations without flat circuit input/output designation
pub trait CircuitContext {
    /// Allocates a new wire and returns its identifier
    fn issue_wire(&mut self) -> WireId;

    /// Adds a gate to the current component
    fn add_gate(&mut self, gate: Gate);

    fn with_child<O: IntoWires>(
        &mut self,
        input_wires: &[WireId],
        f: impl FnOnce(&mut ComponentHandle) -> O,
    ) -> O;
}

// Constants available to all context users
pub const FALSE_WIRE: WireId = WireId(0);
pub const TRUE_WIRE: WireId = WireId(1);

new_key_type! { pub struct ComponentId; }

#[derive(Clone, Debug)]
pub enum Action {
    Gate(Gate),
    Call { id: ComponentId },
}

#[derive(Clone, Debug)]
pub struct Component {
    pub internal_wire_offset: usize,
    pub num_wire: usize,
    pub input_wires: Vec<WireId>,
    pub output_wires: Vec<WireId>,
    pub actions: Vec<Action>,
}

impl Component {
    pub fn empty_root() -> Self {
        Self {
            internal_wire_offset: 0,
            num_wire: 2,
            input_wires: Vec::new(),
            output_wires: Vec::new(),
            actions: Vec::new(),
        }
    }
}

pub struct ComponentPool(SlotMap<ComponentId, Component>);

impl ComponentPool {
    fn insert(&mut self, c: Component) -> ComponentId {
        self.0.insert(c)
    }

    fn remove(&mut self, id: ComponentId) {
        self.0.remove(id);
    }

    fn get(&self, id: ComponentId) -> &Component {
        &self.0[id]
    }

    fn get_mut(&mut self, id: ComponentId) -> &mut Component {
        &mut self.0[id]
    }

    fn take(&mut self, id: ComponentId) -> Component {
        self.0.remove(id).unwrap()
    }
}

#[derive(Default, Clone)]
struct WireCache {
    values: HashMap<WireId, bool>,
}

impl WireCache {
    fn lookup_wire(&self, wire: WireId) -> Option<bool> {
        match wire {
            FALSE_WIRE => Some(false),
            TRUE_WIRE => Some(true),
            wire => self.values.get(&wire).copied(),
        }
    }

    fn feed_wire(&mut self, wire: WireId, value: bool) {
        self.values.insert(wire, value);
    }

    fn size(&self) -> usize {
        self.values.len()
    }

    fn clean_session(&mut self, keep_wires: &[WireId]) {
        self.values
            .retain(|wire_id, _| keep_wires.contains(wire_id));
    }
}

fn evaluate_component(
    component_id: ComponentId,
    pool: &mut ComponentPool,
    parent_cache: &mut WireCache,
) -> Result<Vec<(WireId, bool)>, &'static str> {
    let component = pool.get(component_id).clone();

    let mut local_cache = WireCache::default();

    for &wire_id in &component.input_wires {
        let value = parent_cache
            .lookup_wire(wire_id)
            .ok_or("Missing input wire value")?;

        local_cache.feed_wire(wire_id, value);
    }

    // Process actions
    for action in &component.actions {
        match action {
            Action::Gate(gate) => {
                let a = local_cache
                    .lookup_wire(gate.wire_a)
                    .ok_or("Wire A not evaluated")?;
                let b = local_cache
                    .lookup_wire(gate.wire_b)
                    .ok_or("Wire B not evaluated")?;

                let c = (gate.gate_type.f())(a, b);
                local_cache.feed_wire(gate.wire_c, c);
            }
            Action::Call { id } => {
                let child_outputs = evaluate_component(*id, pool, &mut local_cache)?;

                println!(
                    "  Successfully evaluated child component {:?} with {} outputs",
                    id,
                    child_outputs.len()
                );

                // Feed child outputs into our local cache
                for (wire_id, value) in child_outputs {
                    local_cache.feed_wire(wire_id, value);
                }
            }
        }
    }

    // Collect output wires from local cache
    let outputs: Vec<(WireId, bool)> = component
        .output_wires
        .iter()
        .map(|&wire_id| {
            let value = local_cache
                .lookup_wire(wire_id)
                .ok_or("Output wire not evaluated")?;
            Ok((wire_id, value))
        })
        .collect::<Result<Vec<_>, &'static str>>()?;

    for (wire_id, value) in &outputs {
        parent_cache.feed_wire(*wire_id, *value);
    }

    Ok(outputs)
}

// ――― Helper functions ―――
fn is_true_leaf(component: &Component) -> bool {
    component
        .actions
        .iter()
        .all(|action| matches!(action, Action::Gate(_)))
}

pub struct ComponentHandle<'a> {
    id: ComponentId,
    builder: &'a mut CircuitBuilder,
}

impl<'a> ComponentHandle<'a> {
    /// Direct access to the underlying component (for metadata operations)
    pub fn get_component(&mut self) -> &mut Component {
        self.builder.pool.get_mut(self.id)
    }
}

// Implement the CircuitContext trait for ComponentHandle
impl<'a> CircuitContext for ComponentHandle<'a> {
    fn issue_wire(&mut self) -> WireId {
        self.builder.allocate_wire()
    }

    fn add_gate(&mut self, gate: Gate) {
        self.builder
            .pool
            .get_mut(self.id)
            .actions
            .push(Action::Gate(gate));
    }

    /// Creates a child component with the given input wires
    /// Returns the output wires produced by the child
    fn with_child<O: IntoWires>(
        &mut self,
        input_wires: &[WireId],
        f: impl FnOnce(&mut ComponentHandle) -> O,
    ) -> O {
        // Create child component
        let mut child = Component::empty_root();
        child.input_wires = input_wires.to_vec();
        // Set internal wire tracking for streaming garbling
        child.internal_wire_offset = self.builder.next_wire_id;

        // Insert child into pool
        let child_id = self.builder.pool.insert(child);

        // Push to stack
        self.builder.stack.push(child_id);

        let mut child_handle = ComponentHandle {
            id: child_id,
            builder: self.builder,
        };

        // Execute closure to build child and get output wires
        let output_wires = f(&mut child_handle);

        // Update child's output wires and wire count for truncation
        let child_component = self.builder.pool.get_mut(child_id);
        child_component.output_wires = output_wires.get_wires_vec();
        child_component.num_wire = self.builder.next_wire_id - child_component.internal_wire_offset;

        // Pop from stack and handle exit logic
        self.builder.exit_component();

        // Add call action to parent
        self.builder
            .pool
            .get_mut(self.id)
            .actions
            .push(Action::Call { id: child_id });

        output_wires
    }
}

pub struct CircuitBuilder {
    pool: ComponentPool,
    stack: Vec<ComponentId>,
    counting_mode: bool,
    depth_count: usize,
    max_depth: usize,
    wire_cache: WireCache,
    next_wire_id: usize,
}

impl CircuitBuilder {
    pub fn new(max_depth: usize, root: impl FnOnce(ComponentHandle) -> Vec<WireId>) -> Self {
        let mut builder = Self {
            pool: ComponentPool(SlotMap::with_key()),
            stack: vec![],
            counting_mode: false,
            depth_count: 0,
            max_depth,
            wire_cache: WireCache::default(),
            next_wire_id: 2,
        };

        let handler = builder.enter_component(Component::empty_root());

        root(handler);

        builder
    }

    pub fn global_input(&self) -> &[WireId] {
        let root = self.stack.first().unwrap();
        &self.pool.get(*root).input_wires
    }

    pub fn current_component(&mut self) -> ComponentHandle {
        let current_id = *self.stack.last().unwrap();
        ComponentHandle {
            id: current_id,
            builder: self,
        }
    }

    pub fn allocate_wire(&mut self) -> WireId {
        let wire = WireId(self.next_wire_id);
        self.next_wire_id += 1;
        wire
    }

    pub fn enter_component(&mut self, c: Component) -> ComponentHandle {
        let id = self.pool.insert(c);

        if let Some(&parent) = self.stack.last() {
            let parent = self.pool.get_mut(parent);
            parent.actions.push(Action::Call { id });
        }

        self.stack.push(id);
        ComponentHandle { id, builder: self }
    }

    pub fn exit_component(&mut self) {
        let id = self.stack.pop().expect("unbalanced exit_component");

        // Always evaluate when we exit the root component (stack becomes empty)
        if self.stack.is_empty() {
            println!("Exiting root component {id:?}, evaluating entire graph");
            self.evaluate_subgraph(id);
            return;
        }

        // Streaming evaluation logic for non-root components
        if !self.counting_mode && is_true_leaf(&self.pool.0[id]) {
            self.counting_mode = true;
            self.depth_count = 1;
            println!("Started counting from leaf component {id:?}");
        } else if self.counting_mode {
            self.depth_count += 1;
            println!("Counting depth: {}/{}", self.depth_count, self.max_depth);

            if self.depth_count == self.max_depth {
                println!("Reached max depth, evaluating buffered components");
                self.evaluate_subgraph(id);
                self.counting_mode = false;
                self.depth_count = 0;
            }
        }
    }

    pub fn add_gate(&mut self, gate: Gate) {
        let &current = self.stack.last().expect("no open component");
        self.pool.get_mut(current).actions.push(Action::Gate(gate));
    }

    pub fn evaluate_subgraph(&mut self, id: ComponentId) {
        // Feed component inputs from existing wire cache
        for wire_id in self.pool.get(id).input_wires.iter().copied() {
            if self.wire_cache.lookup_wire(wire_id).is_none() {
                println!("Warning: Input wire {wire_id:?} not in cache");
            }
        }

        println!("Cache size before evaluation: {}", self.wire_cache.size());

        let outputs = evaluate_component(id, &mut self.pool, &mut self.wire_cache).unwrap();

        println!(
            "Evaluated component {:?}, got {} outputs",
            id,
            outputs.len()
        );

        let mut keep_wires = vec![];
        let output_wires: Vec<WireId> = outputs.iter().map(|(wire_id, _)| *wire_id).collect();

        keep_wires.extend(self.pool.get(id).input_wires.clone());
        keep_wires.extend(output_wires);
        keep_wires.extend(self.global_input());

        for (wire_id, value) in outputs {
            println!("  Output wire {wire_id:?} = {value}");
        }

        // Clean cache after session, keeping constants, inputs and outputs for next session
        self.wire_cache.clean_session(&keep_wires);

        println!(
            "Cache size after session cleanup: {}",
            self.wire_cache.size()
        );
    }
}

#[cfg(test)]
mod eval_test {
    use super::*;

    #[test]
    fn simple() {
        CircuitBuilder::new(2, |mut root| {
            let a = root.issue_wire();
            let b = root.issue_wire();

            let c = root.with_child(&[a, b], |component| {
                let c = component.issue_wire();

                component.add_gate(Gate::and(a, b, c));

                c
            });

            let d = root.with_child(&[a, b], |component| {
                let c = component.issue_wire();

                component.add_gate(Gate::and(a, b, c));

                c
            });

            let e = root.issue_wire();
            root.add_gate(Gate::and(c, d, e));

            vec![e]
        });
    }
}
