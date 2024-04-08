// copied from num_enum crate:
// https://raw.githubusercontent.com/illicitonion/num_enum/main/num_enum_derive/src/parsing.rs
// stripped down to the minimum functionality

use syn::{
    parse::{Parse, ParseStream},
    parse_quote, Attribute, DeriveInput, Ident, Meta, Result,
};

pub(crate) struct EnumInfo {
    pub(crate) name: Ident,
    pub(crate) repr: Ident,
}

macro_rules! die {
    ($spanned:expr=>
        $msg:expr
    ) => {
        return Err(::syn::Error::new_spanned($spanned, $msg))
    };
}

impl EnumInfo {
    fn parse_attrs<Attrs: Iterator<Item = Attribute>>(attrs: Attrs) -> Result<Ident> {
        let mut maybe_repr = None;
        for attr in attrs {
            if let Meta::List(meta_list) = &attr.meta {
                if let Some(ident) = meta_list.path.get_ident() {
                    if ident == "repr" {
                        let mut nested = meta_list.tokens.clone().into_iter();
                        let repr_tree = match (nested.next(), nested.next()) {
                            (Some(repr_tree), None) => repr_tree,
                            _ => die!(attr =>
                                "Expected exactly one `repr` argument"
                            ),
                        };
                        let repr_ident: Ident = parse_quote! {
                            #repr_tree
                        };
                        if repr_ident == "C" {
                            die!(repr_ident =>
                                "repr(C) doesn't have a well defined size"
                            );
                        } else {
                            maybe_repr = Some(repr_ident);
                        }
                    }
                }
            }
        }
        if maybe_repr.is_none() {
            panic!("Missing `#[repr(Integer)]` attribute");
        }
        Ok(maybe_repr.unwrap())
    }
}

impl Parse for EnumInfo {
    fn parse(input: ParseStream) -> Result<Self> {
        Ok({
            let input: DeriveInput = input.parse()?;
            let name = input.ident;

            let repr = Self::parse_attrs(input.attrs.into_iter())?;

            EnumInfo { name, repr }
        })
    }
}
