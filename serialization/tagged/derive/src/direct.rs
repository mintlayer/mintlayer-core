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

//! Derive macro for encoding/decoging enums without the extra tag byte

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Ident, Variant};

struct VariantInfo<'a> {
    the_enum: &'a syn::ItemEnum,
    variant: &'a Variant,
}

impl<'a> VariantInfo<'a> {
    fn new(the_enum: &'a syn::ItemEnum, variant: &'a Variant) -> VariantInfo<'a> {
        Self { the_enum, variant }
    }

    fn collect(the_enum: &'a syn::ItemEnum) -> Vec<VariantInfo<'a>> {
        the_enum.variants.iter().map(|variant| Self::new(the_enum, variant)).collect()
    }

    fn full_name(&self) -> TokenStream {
        let ename = &self.the_enum.ident;
        let vname = &self.variant.ident;
        quote!(#ename::#vname)
    }

    fn vars(&self) -> impl Iterator<Item = Ident> + ExactSizeIterator {
        (0..self.variant.fields.len()).map(|i| format_ident!("x{}", i))
    }

    fn constructor(&self) -> TokenStream {
        let name = self.full_name();
        let vars = self.vars();
        match &self.variant.fields {
            syn::Fields::Unit => quote!(),
            syn::Fields::Unnamed(_) => quote!(#name(#(#vars),*)),
            syn::Fields::Named(fields) => {
                let fields = fields.named.iter().map(|f| f.ident.as_ref().expect("is named"));
                quote!(#name { #(#fields: #vars),* })
            }
        }
    }

    fn field_tys(&self) -> impl Iterator<Item = &syn::Type> + ExactSizeIterator + '_ {
        self.variant.fields.iter().map(|f| &f.ty)
    }

    fn first_ty(&self) -> &'_ syn::Type {
        &self
            .variant
            .fields
            .iter()
            .next()
            .expect("Each variant has to have at least 1 field")
            .ty
    }
}

fn tag_disjoint_check(variants: &[VariantInfo<'_>]) -> TokenStream {
    if variants.len() < 2 || !variants[0].the_enum.generics.params.is_empty() {
        // The static_assertions crate does not handle generics at the moment, bail if we see any
        return TokenStream::default();
    }
    let tag_tys = variants.iter().map(|v| v.first_ty());
    quote! {
        ::serialization::tagged::derive_support::sa::assert_type_ne_all!(
            #(::serialization::tagged::Tag<{<#tag_tys as ::serialization::tagged::Tagged>::TAG}>),*
        );
    }
}

pub fn derive_encode(the_enum: &syn::ItemEnum) -> TokenStream {
    let name = &the_enum.ident;
    let (impl_gen, ty_gen, _) = the_enum.generics.split_for_impl();
    let vi = VariantInfo::collect(the_enum);

    let encode_tys = vi.iter().flat_map(|v| v.field_tys());
    let disjoint_check = tag_disjoint_check(&vi);

    let match_arms = vi.iter().map(|vi| {
        let vars = vi.vars();
        let pattern = vi.constructor();
        quote!(#pattern => ::serialization::Encode::encode_to(&(#(#vars,)*), out))
    });

    quote! {
        const _: () = {
            impl #impl_gen ::serialization::Encode for #name #ty_gen
            where #(#encode_tys: ::serialization::Encode,)*
            {
                fn encode_to<Out>(&self, out: &mut Out)
                    where Out: ::serialization::Output + ?::core::marker::Sized,
                {
                    match self { #(#match_arms,)* }
                }
            }
            #disjoint_check
        };
    }
}

pub fn derive_decode(the_enum: &syn::ItemEnum) -> TokenStream {
    let name = &the_enum.ident;
    let (impl_gen, ty_gen, _) = the_enum.generics.split_for_impl();
    let vi = VariantInfo::collect(the_enum);

    let decode_tys_flat = vi.iter().flat_map(|v| v.field_tys());
    let tagged_tys = vi.iter().map(|v| v.first_ty());
    let disjoint_check = tag_disjoint_check(&vi);

    let if_clauses = vi.iter().map(|v| {
        let vars: Vec<_> = v.vars().collect();
        let first_ty = v.first_ty();
        let construct = v.constructor();
        quote! {
            if tag == <#first_ty as ::serialization::tagged::Tagged>::TAG {
                let (#(#vars,)*) = ::serialization::Decode::decode(&mut input)?;
                #construct
            }
        }
    });

    quote! {
        const _: () = {
            impl #impl_gen ::serialization::Decode for #name #ty_gen
            where
                #(#decode_tys_flat: ::serialization::Decode,)*
                #(#tagged_tys: ::serialization::tagged::Tagged,)*
            {
                fn decode<I: ::serialization::Input>(
                    input: &mut I
                ) -> ::core::result::Result<Self, ::serialization::Error> {
                    let mut input = ::serialization::tagged::derive_support::Peekable::new(input);
                    let tag = input.peek()?;
                    let result = #(#if_clauses else)* {
                        ::serialization::Input::read_byte(&mut input)?;
                        return Err(::core::convert::Into::into("Unrecognized tag"))
                    };
                    Ok(result)
                }
            }
            #disjoint_check
        };
    }
}
