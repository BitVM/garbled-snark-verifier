use proc_macro2::TokenStream;
use quote::quote;
use syn::{Error, Ident, ItemFn, Pat, Result, visit_mut::VisitMut};

use crate::parse_sig::ComponentSignature;

pub fn generate_wrapper(sig: &ComponentSignature, original_fn: &ItemFn) -> Result<TokenStream> {
    let fn_name = &original_fn.sig.ident;
    let fn_vis = &original_fn.vis;
    let fn_attrs = &original_fn.attrs;

    // Extract parameter information
    let context_param_name = extract_param_name(&sig.context_param)?;
    let input_param_names: Vec<Ident> = sig
        .input_params
        .iter()
        .map(extract_param_name)
        .collect::<Result<Vec<_>>>()?;
    let input_param_types: Vec<_> = sig.input_params.iter().map(|p| &p.ty).collect();

    // Generate the function body transformation
    let mut transformed_body = original_fn.block.clone();
    let mut renamer = ContextRenamer {
        old_name: context_param_name.clone(),
        new_name: quote! { comp },
    };
    renamer.visit_block_mut(&mut transformed_body);

    // Generate input wire collection
    let input_wire_collection = if input_param_names.is_empty() {
        quote! { Vec::new() }
    } else {
        quote! {
            {
                let mut input_wires = Vec::new();
                #(
                    input_wires.extend(crate::circuit::streaming::IntoWireList::into_wire_list(#input_param_names));
                )*
                input_wires
            }
        }
    };

    // Determine return type based on the original function
    let return_type = &original_fn.sig.output;

    // Generate the wrapper function
    let wrapper = quote! {
        #(#fn_attrs)*
        #fn_vis fn #fn_name(
            #context_param_name: &mut impl crate::circuit::streaming::CircuitContext,
            #(#input_param_names: #input_param_types),*
        ) #return_type {
            let input_wires = #input_wire_collection;

            #context_param_name.with_child(input_wires, |comp| {
                #transformed_body
            })
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
    #[allow(dead_code)] // TODO #22
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
