/* SPDX-License-Identifier: MIT
 * Copyright(c) 2023 Darek Stojaczyk
 */

use quote::ToTokens;
use syn::spanned::Spanned;

extern crate proc_macro;
extern crate syn;
#[macro_use]
extern crate quote;

mod enum_parse;

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
    let (impl_generics, type_generics, where_clause) = ast.generics.split_for_impl();
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
        #[derive(std::fmt::Debug, PartialEq, Clone, Default, ::bincode::Encode, ::bincode::Decode)]
        #packet_vis struct #packet_ident #impl_generics #where_clause {
            #(#fields),*
        }
    };

    if let Some(id) = id {
        let Ok(id) = u16::try_from(id) else {
            panic!("Packet ID greater than u16::MAX");
        };

        ret_stream.extend(quote! {
            impl #packet_ident #type_generics #where_clause {
                pub const ID: u16 = #id;
            }
            impl #impl_generics crate::Payload for #packet_ident #type_generics #where_clause {
                fn id(&self) -> u16 {
                    Self::ID
                }
            }
        });
    }

    ret_stream.into()
}

#[proc_macro_derive(PacketEnum)]
pub fn derive_packet_enum(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let enum_parse::EnumInfo { name, repr } = syn::parse_macro_input!(input);

    quote! {
        use ::bincode::enc::write::Writer;
        use ::bincode::de::read::Reader;
        impl ::bincode::Encode for #name
        {
            fn encode<E: ::bincode::enc::Encoder>(
                &self,
                encoder: &mut E,
            ) -> std::result::Result<(), ::bincode::error::EncodeError> {
                let val = #repr::from(self.clone());
                encoder
                    .writer()
                    .write(&val.to_le_bytes())
            }
        }

        impl ::bincode::Decode for #name {
            fn decode<D: ::bincode::de::Decoder>(decoder: &mut D) -> std::result::Result<Self, ::bincode::error::DecodeError> {
                let mut buf = [0u8; std::mem::size_of::<#repr>()];
                decoder.reader().read(&mut buf)?;
                let val = #repr::from_le_bytes(buf);

                Self::try_from(val).map_err(|e| ::bincode::error::DecodeError::OtherString(format!("Cannot convert {val} to {}: {e}", stringify!(#name))))
            }
        }

        impl<'a> ::bincode::BorrowDecode<'a> for #name
        {
            fn borrow_decode<D: ::bincode::de::BorrowDecoder<'a>>(_decoder: &mut D) -> Result<Self, ::bincode::error::DecodeError> {
                unimplemented!();
            }
        }
    }.into()
}

/// #[path = path::to::PacketType]
struct PathAttribute {
    path: syn::Path,
}

struct Packet {
    name: syn::Ident,
    path: proc_macro2::TokenStream,
    span: proc_macro2::Span,
}

impl syn::parse::Parse for PathAttribute {
    fn parse(input: syn::parse::ParseStream) -> syn::parse::Result<Self> {
        let name = input.parse::<syn::Ident>()?;
        if name != "path" {
            return Err(syn::parse::Error::new_spanned(name, "Unknown attribute"));
        }
        input.parse::<syn::Token![=]>()?;
        let path: syn::Path = input.parse()?;
        Ok(PathAttribute { path })
    }
}

#[proc_macro_attribute]
pub fn packet_list(
    _: proc_macro::TokenStream,
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);

    let variants: Vec<syn::Variant> = match input.data {
        syn::Data::Enum(data_enum) => data_enum.variants.into_iter().collect(),
        _ => panic!("#[packet_list] expects enum"),
    };
    let enum_attrs = input.attrs;
    let enum_vis = input.vis;
    let enum_name = input.ident;

    let packets: Vec<Packet> = variants
        .into_iter()
        .map(|variant| {
            let span = variant.span();
            let name = variant.ident;
            let mut path = None;
            for attr in variant.attrs.iter() {
                let attr_path = attr.parse_args::<PathAttribute>().unwrap();
                path = Some(attr_path.path.into_token_stream());
            }
            let path = path.unwrap_or(name.to_token_stream());
            Packet { name, path, span }
        })
        .collect();

    let enum_variants = packets.iter().map(|packet| {
        let name = &packet.name;
        let path = &packet.path;
        quote_spanned! { packet.span =>
            #name(#path),
        }
    });
    let mut ret_stream = quote! {
        #(#enum_attrs)*
        #[derive(PartialEq, Clone)]
        #enum_vis enum #enum_name {
            Unknown(Unknown),
            #(#enum_variants)*
        }
    };

    let id_match_arms = packets.iter().map(|packet| {
        let name = &packet.name;
        quote_spanned! { packet.span =>
            Self :: #name ( inner ) => inner.id(),
        }
    });
    ret_stream.extend(quote! {

        impl #enum_name {
            pub fn id(&self) -> u16 {
                match self {
                    Self::Unknown(inner) => inner.id(),
                    #(#id_match_arms)*
                }
            }
        }
    });

    let deser_match_arms = packets.iter().map(|packet| {
        let name = &packet.name;
        let path = &packet.path;
        quote_spanned! { packet.span =>
            #path :: ID => Self :: #name ( _deserialize::<#path>(data)? ),
        }
    });
    ret_stream.extend(quote! {
        impl #enum_name {
            pub fn deserialize_no_hdr(id: u16, data: &[u8]) -> Result<Self, crate::PayloadDeserializeError> {
                fn _deserialize<P: crate::Payload>(data: &[u8]) -> Result<P, crate::PayloadDeserializeError> {
                    P::deserialize_no_hdr(data)
                }

                Ok(match id {
                    #(#deser_match_arms)*
                    _ => {
                        Self::Unknown(Unknown { id, data: data.into() })
                    }
                })
            }
        }
    });

    let ser_match_arms = packets.iter().map(|packet| {
        let name = &packet.name;
        quote_spanned! { packet.span =>
            Self :: #name ( inner ) => _process(inner, ctx),
        }
    }).collect::<Vec<_>>();
    ret_stream.extend(quote! {
        impl crate::Payload for #enum_name {
            fn serialize_no_hdr(&self, dst: &mut Vec<u8>) -> Result<usize, crate::PayloadSerializeError> {
                fn _process<P: crate::Payload>(data: &P, dst: &mut Vec<u8>) -> Result<usize, crate::PayloadSerializeError> {
                    data.serialize_no_hdr(dst)
                }

                let ctx = dst;
                Ok(match self {
                    Self::Unknown(inner) => _process(inner, ctx),
                    #(#ser_match_arms)*
                }?)
            }

            fn id(&self) -> u16 {
                fn _process<T: crate::Payload>(inner: &T, ctx: ()) -> u16 {
                    inner.id()
                }

                let ctx = ();
                match self {
                    Self::Unknown(inner) => inner.id(),
                    #(#ser_match_arms)*
                }
            }
        }
    });

    ret_stream.extend(quote! {
        impl ::std::fmt::Debug for #enum_name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                fn _process<T: ::std::fmt::Debug>(inner: &T, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    inner.fmt(f)
                }
                let ctx = f;
                match self {
                    Self::Unknown(inner) => inner.fmt(ctx),
                    #(#ser_match_arms)*
                }
            }
        }
    });

    ret_stream.extend(quote! {
        impl Default for #enum_name {
            fn default() -> Self {
                unimplemented!("def");
            }
        }

        impl ::bincode::Encode for #enum_name
        {
            fn encode<E: ::bincode::enc::Encoder>(
                &self,
                encoder: &mut E,
            ) -> std::result::Result<(), ::bincode::error::EncodeError> {
                unimplemented!("encode");
            }
        }

        impl ::bincode::Decode for #enum_name {
            fn decode<D: ::bincode::de::Decoder>(decoder: &mut D) -> std::result::Result<Self, ::bincode::error::DecodeError> {
                unimplemented!("decode");
            }
        }

        impl<'a> ::bincode::BorrowDecode<'a> for #enum_name
        {
            fn borrow_decode<D: ::bincode::de::BorrowDecoder<'a>>(_decoder: &mut D) -> Result<Self, ::bincode::error::DecodeError> {
                unimplemented!();
            }
        }
    });

    ret_stream.into()
}
