/* SPDX-License-Identifier: MIT
 * Copyright(c) 2023 Darek Stojaczyk
 */

extern crate proc_macro;
extern crate syn;
#[macro_use]
extern crate quote;

#[allow(clippy::from_str_radix_10)]
fn parse_int(str: &str) -> Result<usize, std::num::ParseIntError> {
    if let Some(str) = str.strip_prefix("0x") {
        usize::from_str_radix(str, 16)
    } else {
        usize::from_str_radix(str, 10)
    }
}

#[proc_macro_attribute]
pub fn packet(
    attr: proc_macro::TokenStream,
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let id = if !attr.to_string().is_empty() {
        Some(
            parse_int(attr.to_string().as_str())
                .expect("Malformed ID attribute. Expecting e.g.: #[packet(0x42)]"),
        )
    } else {
        None
    };

    let ast = syn::parse_macro_input!(input as syn::DeriveInput);
    let packet_vis = ast.vis;
    let packet_attrs = ast.attrs;
    let packet_ident = ast.ident;

    // Extract the fields
    let mut fields: Vec<syn::Field> = match ast.data {
        syn::Data::Struct(data_struct) => data_struct.fields.into_iter().collect(),
        _ => panic!("#[packet] expects a struct"),
    };

    // Set visibility to each field
    for f in fields.iter_mut() {
        f.vis = packet_vis.clone();
    }

    // Re-create the original struct
    let mut ret_stream = quote! {
        #(#packet_attrs)*
        #[derive(Debug, PartialEq, Default, bincode::Encode, bincode::Decode)]
        #packet_vis struct #packet_ident {
            #(#fields),*
        }
    };

    if let Some(id) = id {
        ret_stream.extend(quote! {
            impl #packet_ident {
                pub const ID: usize = #id;
            }
        });
    }

    ret_stream.into()
}
