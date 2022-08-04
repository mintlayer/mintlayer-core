// Copyright (c) 2022 RBB S.r.l
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
//
// Author(s): L. Kuklinek

//! Derive macro for tagged types

use itertools::Itertools;
use proc_macro2::TokenStream;
use quote::quote;

// Extract variant discriminant from #[codec(index = X)] or Rust discriminant.
pub fn variant_index(variant: &syn::Variant) -> Option<TokenStream> {
    let index_annotation: Option<u8> = variant
        .attrs
        .iter()
        .filter_map(|a| {
            a.path.is_ident("codec").then(|| ())?;
            match a.parse_args().expect("Can't parse metadata") {
                syn::NestedMeta::Meta(syn::Meta::NameValue(nv)) => {
                    nv.path.is_ident("index").then(|| match nv.lit {
                        syn::Lit::Int(n) => n.base10_parse::<u8>().expect("codec index invalid"),
                        _ => panic!("codec index should be a numeric value"),
                    })
                }
                _ => None,
            }
        })
        .at_most_one()
        .expect("Multiple #[codec(index = X)] annotations");

    let enum_discriminant: Option<&syn::Expr> = variant.discriminant.as_ref().map(|d| &d.1);

    match (index_annotation, enum_discriminant) {
        (Some(_), Some(_)) => panic!("Cannot have both enum discriminant and #[codec(index = X)]"),
        (Some(index), None) => Some(quote!(#index)),
        (None, Some(discr)) => Some(quote!(#discr)),
        (None, None) => None,
    }
}

// Derive macro implementation for the `Tagged` trait
pub fn derive_tagged(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;
    let (impl_gen, ty_gen, _) = ast.generics.split_for_impl();

    let (tag_expr, tag_type) = match &ast.data {
        syn::Data::Enum(syn::DataEnum { variants, .. }) => {
            let variant =
                variants.iter().exactly_one().ok().expect("Only single-variant enums allowed");
            let tag_expr = variant_index(variant).expect("Variant index or discriminant required");
            (tag_expr, None)
        }
        syn::Data::Struct(syn::DataStruct { fields, .. }) => {
            let head_ty =
                &fields.iter().next().expect("Tagged struct must have at least one field").ty;
            let tag_expr = quote!(<#head_ty as ::serialization::tagged::Tagged>::TAG);
            (tag_expr, Some(head_ty))
        }
        syn::Data::Union(_) => {
            panic!("Deriving `Tagged` on a union is not supported")
        }
    };

    let where_clause = tag_type
        .map(|ty| quote!(where #ty: ::serialization::tagged::Tagged))
        .unwrap_or_default();

    quote! {
        const _: () = {
            impl #impl_gen ::serialization::tagged::Tagged for #name #ty_gen #where_clause {
                const TAG: u8 = #tag_expr;
            }
        };
    }
}
