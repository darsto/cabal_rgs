/* SPDX-License-Identifier: MIT
 * Copyright(c) 2024 Darek Stojaczyk
 */

extern crate proc_macro;
extern crate quote;
extern crate syn;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use proc_macro2::TokenTree as TokenTree2;
use quote::{quote, quote_spanned};
use syn::parse::{Parse, ParseStream, Result};
use syn::spanned::Spanned;
use syn::token::Underscore;
use syn::{parse_macro_input, Ident, Token};

/// Whole input inside select!
struct SelectInput {
    items: Vec<SelectItem>,
}

/// One arm of select!.
/// The important bit is that we're parsing most of input into
/// arbitrary TokenStream. This makes code blocks like this get
/// parsed successfully and provide normal code completions:
/// ```ignore
/// p = async_fn() => {
///     p.<caret here>
/// }
/// ```
/// If we decided to parse into syn's Expr or Block, the parsing
/// would fail, then we wouldn't get any code completions at all.
struct SelectItem {
    var_name: VarName,
    expr: Option<TokenStream2>,
    body: TokenStream2,
}

/// Either
///   `let varname = ... {`
/// or
///   `default {`
///   `complete {`
enum VarName {
    Ident(Ident),
    Special,
}

impl Parse for SelectInput {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut items = Vec::new();

        while !input.is_empty() {
            // 'varname =' or '_ ='
            let var_name: VarName = if input.peek(Ident) {
                let ident: Ident = input.parse()?;
                match ident.to_string().as_str() {
                    "default" => VarName::Special,
                    "complete" => VarName::Special,
                    _ => VarName::Ident(ident),
                }
            } else {
                let underscore: Underscore = input.parse()?;
                VarName::Ident(Ident::new("_", underscore.span()))
            };

            let expr = match &var_name {
                VarName::Ident(..) => {
                    input.parse::<Token![=]>()?;
                    let mut expr_tokens = TokenStream2::new();

                    // Manually collect tokens until `=>` is encountered
                    while !input.peek(Token![=>]) && !input.is_empty() {
                        expr_tokens.extend(Some(input.parse::<TokenTree2>()?));
                    }

                    input.parse::<Token![=>]>()?;
                    Some(expr_tokens)
                }
                VarName::Special => None,
            };

            // '{ body }'
            let body: TokenStream2 = {
                let content;
                syn::braced!(content in input);
                content.parse::<TokenStream2>()?
            };

            items.push(SelectItem {
                var_name,
                expr,
                body,
            });

            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(SelectInput { items })
    }
}

#[allow(dead_code)]
fn dummy_select_for_ide(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as SelectInput);

    // Transform each SelectInput into the desired output
    let output = input.items.into_iter().map(|item| {
        let var_name = item.var_name;
        let expr = item.expr;
        let body = TokenStream2::from(item.body);

        match var_name {
            VarName::Ident(ident) => {
                quote_spanned! { body.span() =>
                    if true {
                        let #ident = #expr.await;
                        #body
                    }
                }
            }
            VarName::Special => {
                quote_spanned! { body.span() =>
                    if true {
                        #body
                    }
                }
            }
        }
    });

    let result = quote! {
        {
            #(#output)*
        }
    };

    TokenStream::from(result)
}

#[allow(dead_code)]
fn real_select(input: TokenStream) -> TokenStream {
    let input = TokenStream2::from(input);
    TokenStream::from(quote! {
        futures::select! {
            #input
        }
    })
}

#[proc_macro]
pub fn select(input: TokenStream) -> TokenStream {
    if std::env::var("IS_RUST_ANALYZER").is_ok_and(|v| v != "0" && v != "false") {
        dummy_select_for_ide(input)
    } else {
        real_select(input)
    }
}
