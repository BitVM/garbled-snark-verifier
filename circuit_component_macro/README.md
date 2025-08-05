# Circuit Component Macro

A procedural attribute macro for simplifying circuit component functions in the garbled circuit verifier.

## Overview

The `#[component]` macro transforms regular Rust functions into circuit component gadgets, automatically handling wire management and component creation. It provides a clean, functional interface for building complex circuits from simple building blocks.

## Features

- **Automatic Wire Management**: Converts function parameters to input wire lists automatically
- **Type Safety**: Preserves original function signatures and return types
- **Tuple Support**: Handles up to 16 input parameters with support for nested tuples
- **Context Transformation**: Automatically renames the context parameter for cleaner code
- **Compile-time Validation**: Provides clear error messages for invalid signatures

## Basic Usage

```rust
use garbled_snark_verifier::{component, circuit::playground::CircuitContext, Gate, WireId};

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

// Use the components
fn build_circuit(root: &mut impl CircuitContext) {
    let a = root.issue_wire();
    let b = root.issue_wire();
    let c = root.issue_wire();
    
    let ab = and_gate(root, a, b);
    let result = or_gate(root, ab, c);
}
```

## Advanced Examples

### Multiple Input Types

The macro supports various input parameter types through the `IntoWireList` trait:

```rust
#[component]
fn complex_gate(
    ctx: &mut impl CircuitContext,
    single: WireId,
    tuple: (WireId, WireId),
    vector: Vec<WireId>
) -> WireId {
    // All parameters are automatically converted to wire lists
    let output = ctx.issue_wire();
    // ... implementation
    output
}
```

### Nested Components

Components can call other components seamlessly:

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

The macro supports up to 16 input parameters (excluding the context parameter):

```rust
#[component]
fn big_and_gate(
    ctx: &mut impl CircuitContext,
    a1: WireId, a2: WireId, a3: WireId, a4: WireId,
    a5: WireId, a6: WireId, a7: WireId, a8: WireId,
    a9: WireId, a10: WireId, a11: WireId, a12: WireId,
    a13: WireId, a14: WireId, a15: WireId, a16: WireId
) -> WireId {
    // Implementation with up to 16 inputs
    let result = ctx.issue_wire();
    // ... combine all inputs
    result
}
```

## Requirements

1. **First Parameter**: Must be `&mut impl CircuitContext` (or similar mutable reference to a type implementing `CircuitContext`)
2. **Input Parameters**: All subsequent parameters must implement `IntoWireList`
3. **Return Type**: Can be any type that implements `IntoWireList` (e.g., `WireId`, `(WireId, WireId)`, `Vec<WireId>`)
4. **Maximum Arity**: No more than 16 input parameters (17 including context)

## Implementation Details

### Code Generation

The macro generates a wrapper function that:

1. Collects all input parameters (except the first) into a `Vec<WireId>` using `IntoWireList::into_wire_list`
2. Calls `context.with_child(input_wires, |comp, _inputs| { ... })` 
3. Transforms the function body by renaming the context parameter to `comp`
4. Returns the result with the original return type

### Example Transformation

This source code:

```rust
#[component]
fn and_gate(ctx: &mut impl CircuitContext, a: WireId, b: WireId) -> WireId {
    let c = ctx.issue_wire();
    ctx.add_gate(Gate::and(a, b, c));
    c
}
```

Is transformed to approximately:

```rust
fn and_gate(ctx: &mut impl CircuitContext, a: WireId, b: WireId) -> WireId {
    let input_wires = {
        let mut input_wires = Vec::new();
        input_wires.extend(IntoWireList::into_wire_list(a));
        input_wires.extend(IntoWireList::into_wire_list(b));
        input_wires
    };
    
    ctx.with_child(input_wires, |comp, _inputs| {
        let c = comp.issue_wire();
        comp.add_gate(Gate::and(a, b, c));
        c
    })
}
```

## Error Messages

The macro provides clear compile-time error messages for common mistakes:

- **No context parameter**: "Component function must have at least one parameter (&mut impl CircuitContext)"
- **Self parameter**: "Component functions cannot have 'self' parameter" 
- **Too many parameters**: "Component functions cannot have more than 16 input parameters (excluding context)"
- **Invalid first parameter**: "First parameter must be a simple identifier"

## Limitations

1. **Arity Limit**: Maximum 16 input parameters (excluding context)
2. **Context Parameter**: Must be the first parameter and a mutable reference
3. **Parameter Names**: All parameters must be simple identifiers (no patterns)
4. **Context Renaming**: The first parameter is always renamed to `comp` in the function body

## Integration

The macro is automatically available when using the main crate:

```rust
use garbled_snark_verifier::component;
```

Or can be used directly from the macro crate:

```rust
use circuit_component_macro::component;
```

## Testing

The macro includes comprehensive compile-time tests using trybuild to ensure:

- Valid signatures compile successfully
- Invalid signatures produce appropriate error messages
- Generated code is syntactically correct
- Integration with the type system works properly