use std::collections::HashSet;

use syn::{Error, FnArg, ItemFn, Lit, Meta, Pat, PatType, Result, Token, punctuated::Punctuated};

pub struct ComponentSignature {
    #[allow(dead_code)]
    pub original_fn: ItemFn, // TODO #22
    pub context_param: PatType,
    pub input_params: Vec<PatType>,
    pub ignored_params: Vec<PatType>,
    #[allow(dead_code)]
    pub output_count: usize, // TODO #22
}

impl ComponentSignature {
    pub fn parse(input_fn: &ItemFn, args: &Punctuated<Meta, Token![,]>) -> Result<Self> {
        // Parse optional outputs and ignore parameters from attribute
        let (output_count, ignored_names) = Self::parse_args(args)?;

        // Validate function signature
        let inputs = &input_fn.sig.inputs;

        if inputs.is_empty() {
            return Err(Error::new_spanned(
                &input_fn.sig,
                "Component function must have at least one parameter (&mut impl CircuitContext)",
            ));
        }

        // Extract parameters
        let mut param_iter = inputs.iter();

        // First parameter must be context
        let context_param = match param_iter.next() {
            Some(FnArg::Typed(pat_type)) => {
                Self::validate_context_param(pat_type)?;
                pat_type.clone()
            }
            Some(FnArg::Receiver(_)) => {
                return Err(Error::new_spanned(
                    inputs,
                    "Component functions cannot have 'self' parameter",
                ));
            }
            None => unreachable!(),
        };

        // Collect all parameters
        let all_params: Vec<PatType> = param_iter
            .map(|arg| match arg {
                FnArg::Typed(pat_type) => Ok(pat_type.clone()),
                FnArg::Receiver(_) => Err(Error::new_spanned(
                    arg,
                    "Component functions cannot have 'self' parameter",
                )),
            })
            .collect::<Result<Vec<_>>>()?;

        // Split parameters into regular and ignored based on names
        let mut input_params = Vec::new();
        let mut ignored_params = Vec::new();

        for param in all_params {
            if let Pat::Ident(ident) = &*param.pat {
                if ignored_names.contains(&ident.ident.to_string()) {
                    ignored_params.push(param);
                } else {
                    input_params.push(param);
                }
            } else {
                input_params.push(param);
            }
        }

        if input_params.len() > 16 {
            return Err(Error::new_spanned(
                &input_fn.sig.inputs,
                "Component functions cannot have more than 16 input parameters (excluding context and ignored)",
            ));
        }

        Ok(ComponentSignature {
            original_fn: input_fn.clone(),
            context_param,
            input_params,
            ignored_params,
            output_count,
        })
    }

    fn parse_args(args: &Punctuated<Meta, Token![,]>) -> Result<(usize, HashSet<String>)> {
        let mut output_count = 1; // Default to 1 output if not specified
        let mut ignored_names = HashSet::new();

        for arg in args {
            match arg {
                Meta::NameValue(nv) if nv.path.is_ident("outputs") => match &nv.value {
                    syn::Expr::Lit(expr_lit) => match &expr_lit.lit {
                        Lit::Int(lit_int) => {
                            let value = lit_int.base10_parse::<usize>()?;
                            if value == 0 {
                                return Err(Error::new_spanned(
                                    lit_int,
                                    "outputs parameter must be greater than 0",
                                ));
                            }
                            output_count = value;
                        }
                        _ => {
                            return Err(Error::new_spanned(
                                &expr_lit.lit,
                                "outputs parameter must be an integer literal",
                            ));
                        }
                    },
                    _ => {
                        return Err(Error::new_spanned(
                            &nv.value,
                            "outputs parameter must be an integer literal",
                        ));
                    }
                },
                Meta::NameValue(nv) if nv.path.is_ident("ignore") => match &nv.value {
                    syn::Expr::Lit(expr_lit) => match &expr_lit.lit {
                        Lit::Str(lit_str) => {
                            // Parse comma-separated list of parameter names
                            for name in lit_str.value().split(',') {
                                ignored_names.insert(name.trim().to_string());
                            }
                        }
                        _ => {
                            return Err(Error::new_spanned(
                                &expr_lit.lit,
                                "ignore parameter must be a string literal with comma-separated parameter names",
                            ));
                        }
                    },
                    _ => {
                        return Err(Error::new_spanned(
                            &nv.value,
                            "ignore parameter must be a string literal with comma-separated parameter names",
                        ));
                    }
                },
                _ => {
                    return Err(Error::new_spanned(
                        arg,
                        "Unknown attribute parameter. Only 'outputs' and 'ignore' are supported.",
                    ));
                }
            }
        }

        Ok((output_count, ignored_names))
    }

    fn validate_context_param(pat_type: &PatType) -> Result<()> {
        // Check that the parameter name is suitable for renaming
        match &*pat_type.pat {
            Pat::Ident(ident) => {
                let name = ident.ident.to_string();
                if name == "self" {
                    return Err(Error::new_spanned(
                        ident,
                        "First parameter cannot be named 'self'",
                    ));
                }
            }
            _ => {
                return Err(Error::new_spanned(
                    &pat_type.pat,
                    "First parameter must be a simple identifier",
                ));
            }
        }

        // TODO: Could add more sophisticated type checking here
        // to ensure it's actually `&mut impl CircuitContext`

        Ok(())
    }
}
