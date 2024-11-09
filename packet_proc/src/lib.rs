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
        #packet_vis struct #packet_ident {
            #(#fields),*
        }
    };

    if let Some(id) = id {
        let Ok(id) = u16::try_from(id) else {
            panic!("Packet ID greater than u16::MAX");
        };

        ret_stream.extend(quote! {
            impl #packet_ident {
                pub const ID: u16 = #id;
            }
            impl crate::Payload for #packet_ident {
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
        if name.to_string() != "path" {
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
            #path :: ID => Self :: #name ( _deserialize::<#path>(data, &mut len)? ),
        }
    });
    ret_stream.extend(quote! {
        impl #enum_name {
            pub fn deserialize_no_hdr(id: u16, data: &[u8]) -> Result<Self, crate::PayloadDeserializeError> {
                fn _deserialize<D: ::bincode::de::Decode>(data: &[u8], len_p: &mut usize) -> Result<D, crate::PayloadDeserializeError> {
                    let (obj, len) = ::bincode::decode_from_slice::<D, _>(data, ::bincode::config::legacy())?;
                    *len_p = len;
                    Ok(obj)
                }

                let mut len = 0;
                let obj = match id {
                    #(#deser_match_arms)*
                    _ => {
                        Self::Unknown(Unknown { id, data: _deserialize::<crate::pkt_common::UnknownPayload>(data, &mut len)? })
                    }
                };
                if len != data.len() {
                    return Err(crate::PayloadDeserializeError::PacketTooLong {
                        len: data.len() as u16,
                        parsed: len as u16,
                    });
                }
                Ok(obj)
            }
        }
    });

    let ser_match_arms = packets.iter().map(|packet| {
        let name = &packet.name;
        quote_spanned! { packet.span =>
            Self :: #name ( inner ) => _serialize(inner, dst)?,
        }
    });
    ret_stream.extend(quote! {
        impl #enum_name {
            pub fn serialize_no_hdr(&self, dst: &mut Vec<u8>) -> Result<usize, crate::PayloadSerializeError> {
                fn _serialize<E: ::bincode::enc::Encode>(data: &E, dst: &mut Vec<u8>) -> Result<usize, ::bincode::error::EncodeError> {
                    ::bincode::encode_into_std_write(data, dst, ::bincode::config::legacy())
                }

                Ok(match self {
                    Self::Unknown(inner) => _serialize(inner, dst)?,
                    #(#ser_match_arms)*
                })
            }
        }
    });

    let debug_match_arms = packets.iter().map(|packet| {
        let name = &packet.name;
        quote_spanned! { packet.span =>
            Self :: #name ( inner ) => inner.fmt(f),
        }
    });
    ret_stream.extend(quote! {
        impl ::std::fmt::Debug for #enum_name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Self::Unknown(inner) => inner.fmt(f),
                    #(#debug_match_arms)*
                }
            }
        }
    });

    let payload_match_arms = packets.iter().map(|packet| {
        let name = &packet.name;
        quote_spanned! { packet.span =>
            Self :: #name ( inner ) => inner.id(),
        }
    });
    ret_stream.extend(quote! {
        impl crate::Payload for #enum_name {
            fn id(&self) -> u16 {
                match self {
                    Self::Unknown(inner) => inner.id(),
                    #(#payload_match_arms)*
                }
            }
        }

        impl Default for #enum_name {
            fn default() -> Self {
                unimplemented!();
            }
        }

        impl ::bincode::Encode for #enum_name
        {
            fn encode<E: ::bincode::enc::Encoder>(
                &self,
                encoder: &mut E,
            ) -> std::result::Result<(), ::bincode::error::EncodeError> {
                unimplemented!();
            }
        }

        impl ::bincode::Decode for #enum_name {
            fn decode<D: ::bincode::de::Decoder>(decoder: &mut D) -> std::result::Result<Self, ::bincode::error::DecodeError> {
                unimplemented!();
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
