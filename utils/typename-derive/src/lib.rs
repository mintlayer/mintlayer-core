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

use itertools::Itertools;
use proc_macro::{self, TokenStream};
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(TypeName)]
pub fn derive(input: TokenStream) -> TokenStream {
    let DeriveInput {
        ident,
        attrs: _attrs,
        vis: _vis,
        generics,
        data: _data,
    } = parse_macro_input!(input);
    let output = if generics.params.is_empty() {
        let type_name = ident.to_string();
        quote! {
            impl TypeName for #ident {
                fn typename_str() -> std::borrow::Cow<'static, str> {
                    #type_name.into()
                }
            }
        }
    } else {
        let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
        let type_name = ident.to_string();
        #[allow(unstable_name_collisions)]
        let gen_params = generics
            .type_params()
            .into_iter()
            .cloned()
            .map(|t| {
                let ident = t.ident;
                quote!(#ident::typename_str().as_ref())
            })
            .intersperse(quote! {+ "," +});

        quote! {
            impl #impl_generics TypeName for #ident #ty_generics #where_clause {
                fn typename_str() -> std::borrow::Cow<'static, str> {
                    std::borrow::Cow::Owned(#type_name.to_owned() + "<" + #(#gen_params)* + ">")
                }
            }
        }
    };
    output.into()
}
