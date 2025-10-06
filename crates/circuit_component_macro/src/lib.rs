use proc_macro::TokenStream;
use syn::{
    Expr, ItemFn, Lit, Meta, MetaNameValue, Token, parse_macro_input, parse_str,
    punctuated::Punctuated,
};

mod gen_bn_wrapper;
mod gen_wrapper;
mod parse_sig;

use gen_bn_wrapper::generate_bn_wrapper;
use gen_wrapper::generate_wrapper;
use parse_sig::ComponentSignature;

/// Procedural attribute macro for circuit component functions
///
/// This macro transforms a regular Rust function into a circuit component gadget.
/// The first parameter must be `&mut impl CircuitContext`, and all subsequent
/// parameters are automatically converted to input wires using the `WiresObject` trait.
///
/// # Requirements
///
/// - First parameter must be `&mut impl CircuitContext`
/// - Maximum 16 input parameters (excluding context)
/// - All input parameters must implement `WiresObject`
/// - Return type must implement `WiresObject`
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
/// 1. Collects arguments 2+ into a wire list via `WiresObject::to_wires_vec()`
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

/// Procedural attribute macro for circuit component functions returning BigIntWires
///
/// This macro is similar to `#[component]` but allows specifying a dynamic arity expression
/// for functions that return BigIntWires or other types with runtime-determined wire counts.
///
/// # Example
///
/// ```ignore
/// #[bn_component(arity = "a.len() + 1")]
/// fn add_generic(ctx: &mut impl CircuitContext, a: &BigIntWires, b: &BigIntWires) -> BigIntWires {
///     // implementation
/// }
///
/// #[bn_component(arity = "a.len() * 2")]
/// fn mul_generic(ctx: &mut impl CircuitContext, a: &BigIntWires, b: &BigIntWires) -> BigIntWires {
///     // implementation
/// }
///
/// #[bn_component(arity = "power")]
/// fn mul_by_constant_modulo_power_two(ctx: &mut impl CircuitContext, a: &BigIntWires, c: &BigUint, power: usize) -> BigIntWires {
///     // implementation
/// }
/// ```
#[proc_macro_attribute]
pub fn bn_component(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args with Punctuated::<Meta, Token![,]>::parse_terminated);
    let input_fn = parse_macro_input!(input as ItemFn);

    // Extract arity expression from arguments
    let mut arity_expr: Option<Expr> = None;
    let mut other_args = Punctuated::new();

    for arg in args {
        match arg {
            Meta::NameValue(MetaNameValue { path, value, .. }) if path.is_ident("arity") => {
                // Parse the arity expression from string literal to actual expression
                match &value {
                    Expr::Lit(expr_lit) => {
                        match &expr_lit.lit {
                            Lit::Str(lit_str) => {
                                // Parse the string content as an expression
                                match parse_str::<Expr>(&lit_str.value()) {
                                    Ok(parsed_expr) => arity_expr = Some(parsed_expr),
                                    Err(e) => {
                                        return syn::Error::new_spanned(
                                            lit_str,
                                            format!("Failed to parse arity expression: {}", e),
                                        )
                                        .to_compile_error()
                                        .into();
                                    }
                                }
                            }
                            _ => arity_expr = Some(value),
                        }
                    }
                    _ => arity_expr = Some(value),
                }
            }
            other => other_args.push(other),
        }
    }

    let arity_expr = match arity_expr {
        Some(expr) => expr,
        None => {
            return syn::Error::new_spanned(
                &input_fn.sig.ident,
                "bn_component requires an arity expression: #[bn_component(arity = \"...\")]",
            )
            .to_compile_error()
            .into();
        }
    };

    match ComponentSignature::parse(&input_fn, &other_args) {
        Ok(sig) => match generate_bn_wrapper(&sig, &input_fn, &arity_expr) {
            Ok(tokens) => tokens.into(),
            Err(err) => err.to_compile_error().into(),
        },
        Err(err) => err.to_compile_error().into(),
    }
}
