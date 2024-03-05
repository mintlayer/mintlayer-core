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

use proc_macro2::TokenStream;
use quote::quote;
use syn::spanned::Spanned;

fn check_attributes(attrs: &[syn::Attribute]) -> syn::Result<()> {
    attrs
        .iter()
        .flat_map(|attr| {
            attr.path().segments.iter().map(|seg| {
                (seg.ident != "serde").then_some(()).ok_or_else(|| {
                    let msg = concat!(
                        "The 'serde' attribute changes the structure of the value, ",
                        "please implement ValueHint manually or improve the derive macro.",
                    );
                    syn::Error::new(attr.span(), msg)
                })
            })
        })
        .collect::<syn::Result<()>>()
}

fn hint_for_fields(fields: &syn::Fields, desc_mod: &TokenStream) -> syn::Result<TokenStream> {
    let result = match &fields {
        syn::Fields::Named(fields) => {
            let entries = fields
                .named
                .iter()
                .map(|f| {
                    check_attributes(&f.attrs)?;
                    let name = f.ident.as_ref().expect("named").to_string();
                    let ty = &f.ty;
                    Ok(quote!((#name, &<#ty as #desc_mod::HasValueHint>::HINT)))
                })
                .collect::<syn::Result<Vec<_>>>()?;

            quote!(#desc_mod::ValueHint::Object(&[#(#entries,)*]))
        }
        syn::Fields::Unnamed(fields) => {
            if fields.unnamed.len() == 1 {
                let field = &fields.unnamed[0];
                check_attributes(&field.attrs)?;
                let ty = &field.ty;
                quote!(<#ty as #desc_mod::HasValueHint>::HINT)
            } else {
                let tys = fields
                    .unnamed
                    .iter()
                    .map(|f| {
                        check_attributes(&f.attrs)?;
                        Ok(&f.ty)
                    })
                    .collect::<syn::Result<Vec<_>>>()?;
                quote!(<(#(#tys),*) as #desc_mod::HasValueHint>::HINT)
            }
        }
        syn::Fields::Unit => quote!(#desc_mod::ValueHint::NULL),
    };
    Ok(result)
}

fn process_input(item: syn::DeriveInput, desc_mod: TokenStream) -> syn::Result<TokenStream> {
    check_attributes(&item.attrs)?;

    let hint = match &item.data {
        syn::Data::Struct(item) => hint_for_fields(&item.fields, &desc_mod)?,
        syn::Data::Enum(item) => {
            let variants = item
                .variants
                .iter()
                .map(|var| -> syn::Result<_> {
                    check_attributes(&var.attrs)?;
                    match &var.fields {
                        fields @ (syn::Fields::Named(_) | syn::Fields::Unnamed(_)) => {
                            let subhints = hint_for_fields(fields, &desc_mod)?;
                            let name = var.ident.to_string();
                            Ok(quote!(#desc_mod::ValueHint::Object(&[(#name, &#subhints)])))
                        }
                        syn::Fields::Unit => {
                            let name = var.ident.to_string();
                            Ok(quote!(#desc_mod::ValueHint::StrLit(#name)))
                        }
                    }
                })
                .collect::<syn::Result<Vec<_>>>()?;

            quote!(#desc_mod::ValueHint::Choice(&[#(&#variants,)*]))
        }
        syn::Data::Union(_) => panic!("ValueHint not supported for union"),
    };

    let name = &item.ident;
    let (g_impl, g_ty, g_where) = item.generics.split_for_impl();
    let result = quote! {
        impl #g_impl #desc_mod::HasValueHint for #name #g_ty #g_where {
            const HINT: #desc_mod::ValueHint = #hint;
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
