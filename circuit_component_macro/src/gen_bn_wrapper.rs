use proc_macro2::TokenStream;
use quote::quote;
use syn::{Error, Expr, Ident, ItemFn, Pat, Result, visit_mut::VisitMut};

use crate::parse_sig::ComponentSignature;

pub fn generate_bn_wrapper(
    sig: &ComponentSignature,
    original_fn: &ItemFn,
    arity_expr: &Expr,
) -> Result<TokenStream> {
    let fn_name = &original_fn.sig.ident;
    let fn_vis = &original_fn.vis;
    let fn_attrs = &original_fn.attrs;
    let fn_generics = &original_fn.sig.generics;

    // Extract parameter information
    let context_param_name = extract_param_name(&sig.context_param)?;

    // Build a set of ignored parameter names for quick lookup
    let ignored_param_names_set: std::collections::HashSet<String> = sig
        .ignored_params
        .iter()
        .map(|p| extract_param_name(p).map(|id| id.to_string()))
        .collect::<Result<_>>()?;

    // Collect parameters after the context in their original order from the source function
    let mut ordered_param_idents: Vec<Ident> = Vec::new();
    let mut ordered_param_types: Vec<&syn::Type> = Vec::new();

    for arg in original_fn.sig.inputs.iter().skip(1) {
        if let syn::FnArg::Typed(pat_type) = arg {
            let ident = extract_param_name(pat_type)?;
            ordered_param_idents.push(ident);
            ordered_param_types.push(&pat_type.ty);
        } else {
            return Err(Error::new_spanned(
                arg,
                "Component functions cannot have 'self' parameter",
            ));
        }
    }

    // Generate the function body transformation
    let mut transformed_body = original_fn.block.clone();
    let mut renamer = ContextRenamer {
        old_name: context_param_name.clone(),
        new_name: quote! { comp },
    };
    renamer.visit_block_mut(&mut transformed_body);

    // Prepare a filtered list of parameters that contribute input wires
    let included_param_idents: Vec<Ident> = ordered_param_idents
        .iter()
        .filter(|id| !ignored_param_names_set.contains(&id.to_string()))
        .cloned()
        .collect();

    // Generate input wire collection in the original parameter order,
    // skipping any parameters marked as ignored. Ignored params must not
    // appear in the generated code path invoking WiresObject to avoid
    // trait requirements on non-wire types.
    let input_wire_collection = if included_param_idents.is_empty() {
        quote! { Vec::new() }
    } else {
        let idents_for_wires = included_param_idents;

        quote! {
            {
                let mut input_wires = Vec::new();
                #(
                    input_wires.extend(crate::circuit::streaming::WiresObject::to_wires_vec(&#idents_for_wires));
                )*
                input_wires
            }
        }
    };

    // Determine return type based on the original function
    let return_type = &original_fn.sig.output;

    // Convert function name to string literal
    let fn_name_str = fn_name.to_string();

    // Generate the wrapper function with generics
    let (impl_generics, _ty_generics, where_clause) = fn_generics.split_for_impl();

    // Use the original context parameter type from the signature
    let context_param_type = &sig.context_param.ty;

    // The arity expression evaluates to a usize arity
    let arity_value = arity_expr;

    // Generate key generation code based on whether there are ignored parameters
    let key_generation = if sig.ignored_params.is_empty() {
        // No ignored params: just use the component name
        quote! {
            crate::circuit::streaming::generate_component_key(
                concat!(module_path!(), "::", #fn_name_str),
                [] as [(&str, &[u8]); 0]
            )
        }
    } else {
        // Get the ignored parameter names from the signature
        let ignored_param_names: Vec<Ident> = sig
            .ignored_params
            .iter()
            .filter_map(|param| extract_param_name(param).ok())
            .collect();

        // Generate code to collect parameter bytes using OffCircuitParam trait
        quote! {
            {
                use crate::circuit::streaming::OffCircuitParam;

                // Collect parameter bytes
                let mut params = Vec::new();
                #(
                    params.push((
                        stringify!(#ignored_param_names),
                        #ignored_param_names.to_key_bytes()
                    ));
                )*

                // Convert to the format expected by generate_component_key
                let params_refs: Vec<(&str, &[u8])> = params.iter()
                    .map(|(name, bytes)| (*name, bytes.as_slice()))
                    .collect();

                crate::circuit::streaming::generate_component_key(
                    concat!(module_path!(), "::", #fn_name_str),
                    params_refs
                )
            }
        }
    };

    let wrapper = quote! {
        #(#fn_attrs)*
        #fn_vis fn #fn_name #impl_generics(
            #context_param_name: #context_param_type,
            #(#ordered_param_idents: #ordered_param_types),*
        ) #return_type #where_clause {
            let input_wires = #input_wire_collection;

            #context_param_name.with_named_child(&(#key_generation), input_wires, |comp| {
                #transformed_body
            }, #arity_value)
        }
    };

    Ok(wrapper)
}

fn extract_param_name(pat_type: &syn::PatType) -> Result<Ident> {
    match &*pat_type.pat {
        Pat::Ident(ident) => Ok(ident.ident.clone()),
        _ => Err(Error::new_spanned(
            &pat_type.pat,
            "Parameter must be a simple identifier",
        )),
    }
}

struct ContextRenamer {
    old_name: Ident,
    #[allow(dead_code)]
    new_name: TokenStream,
}

impl VisitMut for ContextRenamer {
    fn visit_ident_mut(&mut self, ident: &mut Ident) {
        if ident == &self.old_name {
            // Replace the identifier with the new name
            // This is a bit tricky because we need to replace an Ident with a TokenStream
            // We'll use a placeholder approach
            *ident = syn::parse_quote! { comp };
        }
    }
}
