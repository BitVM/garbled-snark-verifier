use proc_macro::TokenStream;
use syn::{ItemFn, Meta, Token, parse_macro_input, punctuated::Punctuated};

mod gen_wrapper;
mod parse_sig;

use gen_wrapper::generate_wrapper;
use parse_sig::ComponentSignature;

/// Procedural attribute macro for circuit component functions
///
/// This macro transforms a regular Rust function into a circuit component gadget.
/// The first parameter must be `&mut impl CircuitContext`, and all subsequent
/// parameters are automatically converted to input wires using the `IntoWireList` trait.
///
/// # Requirements
///
/// - First parameter must be `&mut impl CircuitContext`
/// - Maximum 16 input parameters (excluding context)
/// - All input parameters must implement `IntoWireList`
/// - Return type must implement `IntoWireList`
///
/// # Example
///
/// ```ignore
/// use garbled_snark_verifier::{component, circuit::playground::CircuitContext, Gate, WireId};
///
/// #[component]
/// fn and_gate(ctx: &mut impl CircuitContext, a: WireId, b: WireId) -> WireId {
///     let c = ctx.issue_wire();
///     ctx.add_gate(Gate::and(a, b, c));
///     c
/// }
///
/// #[component]
/// fn full_adder(ctx: &mut impl CircuitContext, a: WireId, b: WireId, cin: WireId) -> (WireId, WireId) {
///     let sum1 = xor_gate(ctx, a, b);
///     let carry1 = and_gate(ctx, a, b);
///     let sum = xor_gate(ctx, sum1, cin);
///     let carry2 = and_gate(ctx, sum1, cin);
///     let carry = or_gate(ctx, carry1, carry2);
///     (sum, carry)
/// }
/// ```
///
/// # Generated Code
///
/// The macro generates a wrapper that:
/// 1. Collects arguments 2+ into a wire list via `IntoWireList::into_wire_list()`
/// 2. Calls `ctx.with_child(input_wires, |comp, _inputs| { ... })`
/// 3. Executes the original function body with `ctx` renamed to `comp`
/// 4. Returns the output wires with the original return type
#[proc_macro_attribute]
pub fn component(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args with Punctuated::<Meta, Token![,]>::parse_terminated);
    let input_fn = parse_macro_input!(input as ItemFn);

    match ComponentSignature::parse(&input_fn, &args) {
        Ok(sig) => match generate_wrapper(&sig, &input_fn) {
            Ok(tokens) => tokens.into(),
            Err(err) => err.to_compile_error().into(),
        },
        Err(err) => err.to_compile_error().into(),
    }
}
