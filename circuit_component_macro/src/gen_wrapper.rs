use proc_macro2::TokenStream;
use quote::quote;
use syn::{Error, Ident, ItemFn, Pat, Result, visit_mut::VisitMut};

use crate::parse_sig::ComponentSignature;

pub fn generate_wrapper(sig: &ComponentSignature, original_fn: &ItemFn) -> Result<TokenStream> {
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
    };
    renamer.visit_block_mut(&mut transformed_body);

    // Prepare a filtered list of parameters that contribute input wires
    let included_param_idents: Vec<Ident> = ordered_param_idents
        .iter()
        .filter(|id| !ignored_param_names_set.contains(&id.to_string()))
        .cloned()
        .collect();

    // Create mapping from parameter names to their original types for reference detection
    let param_name_to_type: std::collections::HashMap<String, &syn::Type> = ordered_param_idents
        .iter()
        .zip(ordered_param_types.iter())
        .map(|(ident, ty)| (ident.to_string(), *ty))
        .collect();

    // Generate input wire object construction in the original parameter order,
    // skipping any parameters marked as ignored. For reference parameters,
    // we need to clone them to create owned types for WiresObject.
    let input_wires_object = if included_param_idents.is_empty() {
        quote! { Vec::<crate::WireId>::new() }
    } else if included_param_idents.len() == 1 {
        let single_param = &included_param_idents[0];
        let param_name = single_param.to_string();

        // Check if we need to clone a reference parameter
        if param_name_to_type
            .get(&param_name)
            .map_or(false, |ty| matches!(ty, syn::Type::Reference(_)))
        {
            // For slice types, convert to Vec
            if param_name_to_type.get(&param_name).map_or(false, |ty| {
                if let syn::Type::Reference(ref_ty) = ty {
                    matches!(&*ref_ty.elem, syn::Type::Slice(_))
                } else {
                    false
                }
            }) {
                quote! { #single_param.to_vec() }
            } else {
                quote! { #single_param.clone() }
            }
        } else {
            quote! { #single_param }
        }
    } else {
        // For multiple parameters, clone reference parameters as needed
        let param_expressions: Vec<_> = included_param_idents
            .iter()
            .map(|ident| {
                let param_name = ident.to_string();
                if param_name_to_type
                    .get(&param_name)
                    .map_or(false, |ty| matches!(ty, syn::Type::Reference(_)))
                {
                    // For slice types, convert to Vec
                    if param_name_to_type.get(&param_name).map_or(false, |ty| {
                        if let syn::Type::Reference(ref_ty) = ty {
                            matches!(&*ref_ty.elem, syn::Type::Slice(_))
                        } else {
                            false
                        }
                    }) {
                        quote! { #ident.to_vec() }
                    } else {
                        quote! { #ident.clone() }
                    }
                } else {
                    quote! { #ident }
                }
            })
            .collect();

        quote! { (#(#param_expressions,)*) }
    };

    // Determine return type based on the original function
    let return_type = &original_fn.sig.output;

    // Generate arity expression based on return type (usize, not closure)
    let arity_expr = match return_type {
        syn::ReturnType::Default => quote! { 0usize },
        syn::ReturnType::Type(_, ty) => {
            // Use the WiresObject trait's arity method on a temporary instance
            quote! { <#ty as crate::circuit::WiresArity>::ARITY }
        }
    };

    // Convert function name to string literal
    let fn_name_str = fn_name.to_string();

    // Generate the wrapper function with generics
    let (impl_generics, _ty_generics, where_clause) = fn_generics.split_for_impl();

    // Use the original context parameter type from the signature
    let context_param_type = &sig.context_param.ty;

    // Generate key generation code based on whether there are ignored parameters
    let key_generation = if sig.ignored_params.is_empty() {
        // No ignored params: just use the component name
        quote! {
            crate::circuit::generate_component_key(
                concat!(module_path!(), "::", #fn_name_str),
                [] as [(&str, &[u8]); 0],
                #arity_expr,
                crate::circuit::WiresObject::to_wires_vec(&__input_wires).len()
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
                use crate::circuit::OffCircuitParam;

                // Collect parameter bytes
                let mut __params = Vec::new();
                #(
                    __params.push((
                        stringify!(#ignored_param_names),
                        #ignored_param_names.to_key_bytes()
                    ));
                )*

                // Convert to the format expected by generate_component_key
                let __params_refs: Vec<(&str, &[u8])> = __params.iter()
                    .map(|(name, bytes)| (*name, bytes.as_slice()))
                    .collect();

                crate::circuit::generate_component_key(
                    concat!(module_path!(), "::", #fn_name_str),
                    __params_refs,
                    #arity_expr,
                    crate::circuit::WiresObject::to_wires_vec(&__input_wires).len()
                )
            }
        }
    };

    // Helper function to check if we should avoid double referencing
    let is_already_ref = |param_name: &str| -> bool {
        if let Some(ty) = param_name_to_type.get(param_name) {
            matches!(ty, syn::Type::Reference(_))
        } else {
            false
        }
    };

    // Generate the unpacking code based on the number of included parameters
    let unpack_inputs = if included_param_idents.is_empty() {
        // No unpacking needed for empty inputs
        quote! {}
    } else if included_param_idents.len() == 1 {
        let single_param = &included_param_idents[0];
        let param_name = single_param.to_string();

        // Check if original parameter was a reference type
        if is_already_ref(&param_name) {
            // For slice parameters, convert Vec back to slice reference
            if param_name_to_type.get(&param_name).map_or(false, |ty| {
                if let syn::Type::Reference(ref_ty) = ty {
                    matches!(&*ref_ty.elem, syn::Type::Slice(_))
                } else {
                    false
                }
            }) {
                quote! {
                    let #single_param = __inputs.clone();
                    let #single_param = #single_param.as_slice();
                }
            } else {
                quote! {
                    let #single_param = __inputs.clone();
                    let #single_param = &#single_param;
                }
            }
        } else {
            quote! { let #single_param = __inputs.clone(); }
        }
    } else {
        // For multiple parameters, unpack tuple and create reference bindings as needed
        let tuple_destructure: Vec<_> = included_param_idents
            .iter()
            .map(|ident| {
                quote! { #ident }
            })
            .collect();

        let ref_bindings: Vec<_> = included_param_idents
            .iter()
            .map(|ident| {
                let param_name = ident.to_string();
                if is_already_ref(&param_name) {
                    // For slice parameters, convert Vec back to slice reference
                    if param_name_to_type.get(&param_name).map_or(false, |ty| {
                        if let syn::Type::Reference(ref_ty) = ty {
                            matches!(&*ref_ty.elem, syn::Type::Slice(_))
                        } else {
                            false
                        }
                    }) {
                        quote! { let #ident = #ident.as_slice(); }
                    } else {
                        // For other reference parameters, create reference binding
                        quote! { let #ident = &#ident; }
                    }
                } else {
                    // For value parameters, use directly - no rebinding at all!
                    quote! {}
                }
            })
            .collect();

        quote! {
            let (#(#tuple_destructure,)*) = __inputs.clone();
            #(#ref_bindings)*
        }
    };

    let wrapper = quote! {
        #(#fn_attrs)*
        #fn_vis fn #fn_name #impl_generics(
            #context_param_name: #context_param_type,
            #(#ordered_param_idents: #ordered_param_types),*
        ) #return_type #where_clause {
            let __input_wires = #input_wires_object;

            #context_param_name.with_named_child((#key_generation), __input_wires, |mut __comp, __inputs| {
                // Unpack inputs into individual variables
                #unpack_inputs
                #transformed_body
            }, #arity_expr)
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
}

impl VisitMut for ContextRenamer {
    fn visit_ident_mut(&mut self, ident: &mut Ident) {
        if ident == &self.old_name {
            // Replace the identifier with the new name
            // This is a bit tricky because we need to replace an Ident with a TokenStream
            // We'll use a placeholder approach
            *ident = syn::parse_quote! { __comp };
        }
    }
}
