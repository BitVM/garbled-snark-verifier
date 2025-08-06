use crate::{
    circuit::playground::{CircuitBuilder, CircuitContext, SimpleInputs, TripleInputs},
    component, Gate, WireId,
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
    use crate::circuit::playground::{Evaluate, TripleInputsWire};

    #[test]
    fn test_component_macro_basic() {
        let inputs = SimpleInputs { a: true, b: false };

        CircuitBuilder::<Evaluate>::streaming_process(2, inputs, |root, inputs_wire| {
            let a = inputs_wire.a;
            let b = inputs_wire.b;

            let c = and_gate(root, a, b);

            vec![c]
        });
    }

    #[test]
    fn test_component_macro_nested() {
        let inputs = TripleInputs {
            a: true,
            b: true,
            c: false,
        };

        CircuitBuilder::<Evaluate>::streaming_process(2, inputs, |root, inputs_wire| {
            let TripleInputsWire { a, b, c } = inputs_wire;

            let result = triple_and(root, a, b, c);

            vec![result]
        });
    }
}
