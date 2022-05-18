// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): A. Altonen
use convert_case::{Case, Casing};
use proc_macro::{self, TokenStream};
use proc_macro2::Span;
use quote::{quote, ToTokens};
use syn::{
    parse::{Parse, ParseStream},
    parse2, parse_macro_input, DeriveInput, Ident, Result, Token, Type,
};

#[derive(Debug)]
struct Retval {
    _oneshot_tok: Ident,
    _sep1: Token![::],
    _sender_tok: Ident,
    _sep2: Token![<],
    inner: Type,
    _sep3: Token![>],
}

impl Parse for Retval {
    fn parse(input: ParseStream) -> Result<Self> {
        Ok(Retval {
            _oneshot_tok: input.parse()?,
            _sep1: input.parse()?,
            _sender_tok: input.parse()?,
            _sep2: input.parse()?,
            inner: input.parse()?,
            _sep3: input.parse()?,
        })
    }
}

#[proc_macro_derive(Handle, attributes(name))]
pub fn message(input: TokenStream) -> TokenStream {
    let data = parse_macro_input!(input as DeriveInput);
    let orig = data.ident.clone();
    let ident = syn::Ident::new(format!("{}Handle", data.ident).as_str(), Span::call_site());

    let filtered = if let syn::Data::Enum(syn::DataEnum { variants, .. }) = data.data {
        variants.into_iter().collect::<Vec<_>>()
    } else {
        panic!("`#[derive(Handle)]` can only be used with enums!");
    };

    let methods = filtered.iter().map(|f| {
        let name = &f.ident;
        let fields = &f.fields;
        let attrs = &f.attrs;

        let real_name = if attrs.len() == 1 {
            if !attrs[0].path.is_ident("name") {
                panic!("Unknown attribute")
            }

            let ident = if let Ok(syn::Meta::NameValue(syn::MetaNameValue {
                lit: syn::Lit::Str(litstr), ..
            })) = attrs[0].parse_meta() {
                syn::Ident::new(
                    litstr.value().as_str(),
                    Span::call_site()
                )
            } else {
                panic!("Invalid attribute");
            };

            quote! { #ident }
        } else {
            let name = syn::Ident::new(
                &name.to_string().to_case(Case::Snake),
                Span::call_site()
            );
            quote! { #name }
        };

        let (func_args, chan_args): (Vec<_>, Vec<_>) = fields.iter().zip(0..fields.len() - 1).map(|(field, _)| {
            let ident = &field.ident;
            let ty = &field.ty;

            (
                quote! {
                    , #ident: #ty
                },
                quote! {
                    #ident
                }
            )
        }).unzip();

        let retval = if let Some(syn::Field {
            ty: syn::Type::Path(buffer), ..
        }) = fields.iter().last() {
            let retval: Retval = parse2(buffer.into_token_stream()).expect("Invalid return value");
            let inner = retval.inner;
            quote! { #inner }
        } else {
            panic!("Enum must have `oneshot::Sender` for return value");
        };

        quote! {
            pub async fn #real_name(&mut self #(#func_args)*) -> Result<#retval, crate::error::P2pError> {
                let (tx, rx) = oneshot::channel();
                self.tx.send(P2pEvent::#name { #(#chan_args,)* response: tx }).await?;
                rx.await.map_err(|_| crate::error::P2pError::ChannelClosed)
            }
        }
    });

    quote! {
        pub struct #ident {
            tx: mpsc::Sender<#orig>,
        }

        impl #ident {
            pub fn new(tx: mpsc::Sender<#orig>) -> Self {
                Self { tx }
            }

            #(#methods)*
        }
    }
    .into()
}
