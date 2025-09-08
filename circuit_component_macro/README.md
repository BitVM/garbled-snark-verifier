# Circuit Component Macro

Attribute macros for ergonomic circuit composition in the garbled SNARK verifier.

## Overview

The `#[component]` and `#[bn_component]` macros transform regular Rust functions into reusable circuit gadgets. They take care of wiring inputs, deriving stable component keys, and creating nested component frames, so you can write straight-line Rust over a `CircuitContext`.

## Features

- Automatic input wiring via `WiresObject` for parameters and returns
- Preserves original function signature and return type
- Pass-by-reference and slice parameters supported (auto-cloned for wiring)
- Up to 16 input parameters (excluding the context and any ignored ones)
- Stable component key derivation with optional off-circuit params
- Clear compile-time errors for invalid signatures

## Basic Usage

```rust
use garbled_snark_verifier::{component, CircuitContext, Gate, WireId};

#[component]
fn and_gate(ctx: &mut impl CircuitContext, a: WireId, b: WireId) -> WireId {
    let c = ctx.issue_wire();
    ctx.add_gate(Gate::and(a, b, c));
    c
}

#[component]
fn or_gate(ctx: &mut impl CircuitContext, a: WireId, b: WireId) -> WireId {
    let c = ctx.issue_wire();
    ctx.add_gate(Gate::or(a, b, c));
    c
}

fn build_circuit(root: &mut impl CircuitContext) {
    let a = root.issue_wire();
    let b = root.issue_wire();
    let c = root.issue_wire();

    let ab = and_gate(root, a, b);
    let _result = or_gate(root, ab, c);
}
```

## Advanced Examples

### Multiple Parameter Types

Parameters and return types can be any type implementing `WiresObject`:

```rust
use garbled_snark_verifier::{component, CircuitContext, WireId};

#[component]
fn complex(
    ctx: &mut impl CircuitContext,
    single: WireId,
    tuple: (WireId, WireId),
    vector: Vec<WireId>,
    slice_ref: &[WireId],      // refs are allowed
) -> (WireId, Vec<WireId>) {
    let out0 = ctx.issue_wire();
    let out1 = vector;         // any WiresObject
    (out0, out1)
}
```

References are cloned into owned wire objects for the child component; inside the body they are re-bound to references when needed (slices become `&[WireId]`).

### Nested Components

Components compose naturally:

```rust
#[component]
fn half_adder(ctx: &mut impl CircuitContext, a: WireId, b: WireId) -> (WireId, WireId) {
    let sum = xor_gate(ctx, a, b);
    let carry = and_gate(ctx, a, b);
    (sum, carry)
}

#[component]
fn full_adder(ctx: &mut impl CircuitContext, a: WireId, b: WireId, cin: WireId) -> (WireId, WireId) {
    let (s1, c1) = half_adder(ctx, a, b);
    let (sum, c2) = half_adder(ctx, s1, cin);
    let carry = or_gate(ctx, c1, c2);
    (sum, carry)
}
```

### Maximum Arity

Up to 16 input parameters are supported (excluding the context and any ignored ones):

```rust
#[component]
fn big_and(
    ctx: &mut impl CircuitContext,
    a1: WireId, a2: WireId, a3: WireId, a4: WireId,
    a5: WireId, a6: WireId, a7: WireId, a8: WireId,
    a9: WireId, a10: WireId, a11: WireId, a12: WireId,
    a13: WireId, a14: WireId, a15: WireId, a16: WireId,
) -> WireId {
    let result = ctx.issue_wire();
    // ... combine all inputs
    result
}
```

## Attribute Options

- `#[component(offcircuit_args = "a,b")]`
  - Excludes named parameters from the input wiring list and uses them only to derive the component key. Useful for mode-independent parameters like window sizes or constants.
- `#[bn_component(arity = "EXPR", offcircuit_args = "...")]`
  - Same as `component`, but lets you specify a runtime arity expression `EXPR` (parsed from a string and evaluated in the wrapper). Ideal for types like big integers where the number of wires depends on inputs.

Examples:

```rust
use circuit_component_macro::bn_component;

#[bn_component(arity = "a.len() + 1")]
fn add_generic(ctx: &mut impl CircuitContext, a: &BigIntWires, b: &BigIntWires) -> BigIntWires {
    // ...
}

#[bn_component(arity = "power", offcircuit_args = "power")]
fn mul_by_const_pow2(
    ctx: &mut impl CircuitContext,
    a: &BigIntWires,
    c: &BigUint,
    power: usize,
) -> BigIntWires {
    // ...
}
```

## Requirements

1. First parameter must be `&mut impl CircuitContext` (or any mutable reference to a type implementing `CircuitContext`).
2. All subsequent parameters must implement `WiresObject` (e.g., `WireId`, tuples, `Vec<WireId>`, BN254 wire types, etc.).
3. The return type must implement `WiresObject`.
4. No more than 16 input parameters (excluding the context and any `offcircuit_args`).
5. Parameters must be simple identifiers (no patterns).

## Implementation Details

The wrapper it generates roughly does the following:

1. Collects the non-ignored parameters into a `WiresObject` (cloning references as needed).
2. Derives a stable component key via `generate_component_key` using the module path, function name, arity, input length, and any `offcircuit_args`.
3. Calls `ctx.with_named_child(key, inputs, |comp, inputs| { ... }, arity)`.
4. Renames your context parameter to `comp` inside the body and returns your original return type.

Example (simplified):

```rust
fn and_gate(ctx: &mut impl CircuitContext, a: WireId, b: WireId) -> WireId {
    let input_wires = (a, b);
    ctx.with_named_child(
        crate::circuit::streaming::generate_component_key(
            concat!(module_path!(), "::", "and_gate"),
            [] as [(&str, &[u8]); 0],
            1, // arity inferred for fixed-size returns
            crate::circuit::streaming::WiresObject::to_wires_vec(&input_wires).len(),
        ),
        input_wires,
        |comp, inputs| {
            let (a, b) = inputs;
            let c = comp.issue_wire();
            comp.add_gate(Gate::and(a, b, c));
            c
        },
        1,
    )
}
```

## Errors and Limitations

- No context parameter: "Component function must have at least one parameter (&mut impl CircuitContext)".
- `self` not allowed: "Component functions cannot have 'self' parameter".
- Too many parameters: "...cannot have more than 16 input parameters (excluding context and ignored)".
- First parameter must be a simple identifier.

## Integration

- `#[component]` is re-exported by the main crate:

```rust
use garbled_snark_verifier::component;
```

- `#[bn_component]` is available from this crate:

```rust
use circuit_component_macro::bn_component;
```

## Testing

The crate includes trybuild tests to ensure:

- Valid signatures compile successfully.
- Invalid signatures produce clear errors.
- Generated code is syntactically correct and integrates with `CircuitContext`.
