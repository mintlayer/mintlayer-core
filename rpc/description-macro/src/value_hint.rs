// Copyright (c) 2024 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::spanned::Spanned;

enum EnumTag {
    External,
    Adjacent(String, String, Span, Span),
    None(Span),
}

impl EnumTag {
    fn span(&self) -> Option<Span> {
        match self {
            EnumTag::External => None,
            EnumTag::Adjacent(_, _, s, _) => Some(*s),
            EnumTag::None(s) => Some(*s),
        }
    }
}

#[must_use = "Must check attributes"]
struct SerdeAttributes {
    enum_tag: EnumTag,
}

impl SerdeAttributes {
    fn new(attrs: &[syn::Attribute]) -> syn::Result<Self> {
        let mut tag_name = None;
        let mut content_key = None;
        let mut untagged = None;

        for attr in attrs.iter().filter(|a| a.path().is_ident("serde")) {
            let err = || {
                let msg = concat!(
                    "The 'serde' attribute changes the structure of the value, ",
                    "please implement ValueHint manually or improve the derive macro.",
                );
                syn::Error::new(attr.span(), msg)
            };

            match &attr.meta {
                syn::Meta::List(la) => {
                    la.parse_nested_meta(|m| {
                        let span = m.path.span();
                        if m.path.is_ident("untagged") {
                            untagged = Some(span);
                        } else if m.path.is_ident("tag") {
                            tag_name = Some((m.value()?.parse::<syn::LitStr>()?.value(), span));
                        } else if m.path.is_ident("content") {
                            content_key = Some((m.value()?.parse::<syn::LitStr>()?.value(), span));
                        } else {
                            return Err(err());
                        }
                        Ok(())
                    })?;
                }
                syn::Meta::Path(_) | syn::Meta::NameValue(_) => return Err(err()),
            }
        }

        let enum_tag = match (tag_name, untagged) {
            (None, None) => EnumTag::External,
            (Some((tag_name, span)), None) => match content_key {
                Some((content_key, ck_span)) => {
                    EnumTag::Adjacent(tag_name, content_key, span, ck_span)
                }
                None => {
                    return Err(syn::Error::new(
                        span,
                        "Internal enum tagging not supported by `HasValueHint` macro",
                    ));
                }
            },
            (None, Some(span)) => EnumTag::None(span),
            (Some(_), Some(span)) => {
                return Err(syn::Error::new(span, "Conflicting tag specifiers"))
            }
        };

        Ok(Self { enum_tag })
    }

    // Require no attribute to be present
    fn check_none(self) -> syn::Result<()> {
        if let Some(span) = self.enum_tag.span() {
            return Err(syn::Error::new(
                span,
                "Enum representation not supported here by `HasValueHint`",
            ));
        }
        Ok(())
    }

    // Get enum tag format. Enforce the adjacent representation has the tag key "type" and content
    // key "content".
    fn into_supported_enum_tag(self) -> syn::Result<EnumTag> {
        let Self { enum_tag } = self;
        match &enum_tag {
            EnumTag::External => (),
            EnumTag::Adjacent(tag, content, tag_s, ck_s) => {
                if tag != "type" {
                    return Err(syn::Error::new(*tag_s, "Tag must be \"type\""));
                }
                if content != "content" {
                    return Err(syn::Error::new(*ck_s, "Content must be \"content\""));
                }
            }
            EnumTag::None(_) => (),
        }
        Ok(enum_tag)
    }
}

fn hint_for_fields(
    fields: &syn::Fields,
    desc_mod: &TokenStream,
    mode: &TokenStream,
) -> syn::Result<TokenStream> {
    let result = match &fields {
        syn::Fields::Named(fields) => {
            let entries = fields
                .named
                .iter()
                .map(|f| {
                    SerdeAttributes::new(&f.attrs)?.check_none()?;
                    let name = f.ident.as_ref().expect("named").to_string();
                    let ty = &f.ty;
                    Ok(quote!((#name, &<#ty as #desc_mod::HasValueHint>::#mode)))
                })
                .collect::<syn::Result<Vec<_>>>()?;

            quote!(#desc_mod::ValueHint::Object(&[#(#entries,)*]))
        }
        syn::Fields::Unnamed(fields) => {
            if fields.unnamed.len() == 1 {
                let field = &fields.unnamed[0];
                SerdeAttributes::new(&field.attrs)?.check_none()?;
                let ty = &field.ty;
                quote!(<#ty as #desc_mod::HasValueHint>::#mode)
            } else {
                let tys = fields
                    .unnamed
                    .iter()
                    .map(|f| {
                        SerdeAttributes::new(&f.attrs)?.check_none()?;
                        Ok(&f.ty)
                    })
                    .collect::<syn::Result<Vec<_>>>()?;
                quote!(<(#(#tys),*) as #desc_mod::HasValueHint>::#mode)
            }
        }
        syn::Fields::Unit => quote!(#desc_mod::ValueHint::NULL),
    };
    Ok(result)
}

fn hint_for_item(
    item: &syn::DeriveInput,
    desc_mod: &TokenStream,
    mode: &TokenStream,
) -> syn::Result<TokenStream> {
    match &item.data {
        syn::Data::Struct(struct_item) => {
            SerdeAttributes::new(&item.attrs)?.check_none()?;
            hint_for_fields(&struct_item.fields, desc_mod, mode)
        }
        syn::Data::Enum(enum_item) => {
            let repr = SerdeAttributes::new(&item.attrs)?.into_supported_enum_tag()?;
            let variants = enum_item
                .variants
                .iter()
                .map(|var| -> syn::Result<_> {
                    SerdeAttributes::new(&var.attrs)?.check_none()?;
                    let name = var.ident.to_string();
                    let hint = match &var.fields {
                        fields @ (syn::Fields::Named(_) | syn::Fields::Unnamed(_)) => {
                            let subhints = hint_for_fields(fields, desc_mod, mode)?;
                            match &repr {
                                EnumTag::External => {
                                    return Err(syn::Error::new(
                                        fields.span(),
                                        "Only data-less enum arms allowed for external format",
                                    ));
                                }
                                EnumTag::Adjacent(tag_name, content_key, _, _) => {
                                    quote! {
                                        #desc_mod::ValueHint::Object(&[
                                            (#tag_name, &#desc_mod::ValueHint::StrLit(#name)),
                                            (#content_key, &#subhints),
                                        ])
                                    }
                                }
                                EnumTag::None(_) => subhints,
                            }
                        }
                        syn::Fields::Unit => match &repr {
                            EnumTag::External => {
                                quote!(#desc_mod::ValueHint::StrLit(#name))
                            }
                            EnumTag::Adjacent(tag_name, _, _, _) => {
                                let tag_val = var.ident.to_string();
                                let val = quote!(#desc_mod::ValueHint::StrLit(#tag_val));
                                quote!(#desc_mod::ValueHint::Object(&[(#tag_name, &#val)]))
                            }
                            EnumTag::None(span) => {
                                let e = syn::Error::new(*span, "Incompatible with unit enum arms");
                                return Err(e);
                            }
                        },
                    };
                    Ok(hint)
                })
                .collect::<syn::Result<Vec<_>>>()?;

            Ok(quote!(#desc_mod::ValueHint::Choice(&[#(&#variants,)*])))
        }
        syn::Data::Union(_) => panic!("HasValueHint not supported for union"),
    }
}

fn process_input(item: syn::DeriveInput, desc_mod: TokenStream) -> syn::Result<TokenStream> {
    let hint_ser = hint_for_item(&item, &desc_mod, &quote!(HINT_SER))?;
    let hint_de = hint_for_item(&item, &desc_mod, &quote!(HINT_DE))?;

    let name = &item.ident;
    let (g_impl, g_ty, g_where) = item.generics.split_for_impl();
    let result = quote! {
        impl #g_impl #desc_mod::HasValueHint for #name #g_ty #g_where {
            const HINT_SER: #desc_mod::ValueHint = #hint_ser;
            const HINT_DE: #desc_mod::ValueHint = #hint_de;
        }
    };

    Ok(result)
}

pub fn derive_has_value_hint(
    item: proc_macro::TokenStream,
    desc_mod: TokenStream,
) -> proc_macro::TokenStream {
    let item: syn::DeriveInput = syn::parse(item).expect("Not a valid derive macro item");
    process_input(item, desc_mod).unwrap_or_else(|e| e.to_compile_error()).into()
}
