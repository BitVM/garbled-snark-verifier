use crate::{
    Gate, WireId,
    circuit::playground::{CircuitBuilder, CircuitContext},
    component,
};

#[component]
fn and_gate(ctx: &mut impl CircuitContext, a: WireId, b: WireId) -> WireId {
    let c = ctx.issue_wire();
    ctx.add_gate(Gate::and(a, b, c));
    c
}

#[component]
fn triple_and(ctx: &mut impl CircuitContext, a: WireId, b: WireId, c: WireId) -> WireId {
    let ab = and_gate(ctx, a, b);
    and_gate(ctx, ab, c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_component_macro_basic() {
        CircuitBuilder::new(2, |mut root| {
            let a = root.issue_wire();
            let b = root.issue_wire();

            let c = and_gate(&mut root, a, b);

            vec![c]
        });
    }

    #[test]
    fn test_component_macro_nested() {
        CircuitBuilder::new(2, |mut root| {
            let a = root.issue_wire();
            let b = root.issue_wire();
            let c = root.issue_wire();

            let result = triple_and(&mut root, a, b, c);

            vec![result]
        });
    }
}
