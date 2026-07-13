// Copyright (c) 2026 RBB S.r.l
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

use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Index, parse_macro_input};

/// Derive the `IsEmpty` trait for a struct.
///
/// The generated implementation considers the struct empty when all of its fields are empty. Each
/// field's own `is_empty` method is used, so every field type must have one (for example the
/// standard collections, `String`, or another type that implements `IsEmpty`). A struct with no
/// fields is always empty.
#[proc_macro_derive(IsEmpty)]
pub fn derive(input: TokenStream) -> TokenStream {
    let DeriveInput {
        ident,
        generics,
        data,
        ..
    } = parse_macro_input!(input);

    let fields = match data {
        Data::Struct(data) => data.fields,
        Data::Enum(_) | Data::Union(_) => {
            return syn::Error::new_spanned(ident, "IsEmpty can only be derived for structs")
                .to_compile_error()
                .into();
        }
    };

    let checks: Vec<_> = match fields {
        Fields::Named(fields) => fields
            .named
            .into_iter()
            .map(|field| {
                let name = field.ident.expect("a named field always has an identifier");
                quote!(self.#name.is_empty())
            })
            .collect(),
        Fields::Unnamed(fields) => (0..fields.unnamed.len())
            .map(|i| {
                let index = Index::from(i);
                quote!(self.#index.is_empty())
            })
            .collect(),
        Fields::Unit => Vec::new(),
    };

    let body = match checks.split_first() {
        Some((first, rest)) => quote!(#first #(&& #rest)*),
        None => quote!(true),
    };

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote! {
        impl #impl_generics IsEmpty for #ident #ty_generics #where_clause {
            fn is_empty(&self) -> bool {
                #body
            }
        }
    }
    .into()
}
