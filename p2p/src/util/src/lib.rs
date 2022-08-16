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

use convert_case::{Case, Casing};
use proc_macro::{self, TokenStream};
use proc_macro2::Span;
use quote::{quote, ToTokens};
use syn::{
    parse::{Parse, ParseStream},
    parse2, parse_macro_input, Attribute, DeriveInput, Fields, Ident, Result, Token, Type,
};

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

// try to parse real name for the function if it was supplied using `#[real_name = "..."]`
fn parse_real_name(attributes: &[Attribute]) -> Option<proc_macro2::TokenStream> {
    if let Some(attr) = attributes.iter().find(|attr| attr.path.is_ident("name")) {
        let ident = if let Ok(syn::Meta::NameValue(syn::MetaNameValue {
            lit: syn::Lit::Str(litstr),
            ..
        })) = attr.parse_meta()
        {
            syn::Ident::new(litstr.value().as_str(), Span::call_site())
        } else {
            panic!("`name` attribute in invalid form");
        };

        return Some(quote! { #ident });
    }

    None
}

// try to find entry with `#[return_value]` attribute and extract its type into `proc_macro2` token stream
fn parse_return_value(
    fields: &Fields,
) -> Option<(proc_macro2::TokenStream, proc_macro2::TokenStream)> {
    let retvals = fields
        .iter()
        .flat_map(|field| {
            field
                .attrs
                .iter()
                .find(|attr| attr.path.is_ident("return_value"))
                .map(|_| field)
        })
        .collect::<Vec<_>>();

    assert!(retvals.len() <= 1, "only one return value allowed");

    retvals.get(0).map(|field| {
        let ty = &field.ty;
        let ident = &field.ident;
        let retval: Retval = parse2(ty.into_token_stream())
            .expect("Return value is expected to be in form `oneshot::Sender<type>`");
        let inner = retval.inner;

        (
            quote! {
                #ident
            },
            quote! {
                #inner
            },
        )
    })
}

#[proc_macro_derive(Handle, attributes(name, return_value))]
pub fn event(input: TokenStream) -> TokenStream {
    let data = parse_macro_input!(input as DeriveInput);
    let orig = data.ident.clone();
    let sender = syn::Ident::new(format!("{}Sender", data.ident).as_str(), Span::call_site());

    let filtered = if let syn::Data::Enum(syn::DataEnum { variants, .. }) = data.data {
        variants.into_iter()
    } else {
        panic!("`#[derive(Handle)]` can only be used with enums!");
    };

    let methods = filtered
        .map(|f| {
            let name = &f.ident;
            let fields = &f.fields;

            let real_name = parse_real_name(&f.attrs).unwrap_or_else(|| {
                let name = syn::Ident::new(&name.to_string().to_case(Case::Snake), Span::call_site());
                quote! { #name }
            });

            let (func_args, chan_args): (Vec<_>, Vec<_>) = fields
                .iter()
                .filter_map(|field| {
                    let ident = &field.ident;
                    let ty = &field.ty;

                    (!field
                        .attrs
                        .iter()
                        .any(|attr| attr.path.is_ident("return_value")))
                    .then_some((
                        quote! {
                            #ident: #ty
                        },
                        quote! {
                            #ident
                        },
                    ))
                })
                .unzip();

            if let Some((retval_name, retval_type)) = parse_return_value(fields) {
                quote! {
                    pub async fn #real_name(&mut self #(, #func_args)*) -> core::result::Result<#retval_type, P2pError> {
                        let (tx, rx) = oneshot::channel();
                        self.tx
                            .send(#orig::#name { #(#chan_args,)* #retval_name: tx })
                            .map_err(|_| P2pError::ChannelClosed)?;
                        rx.await.map_err(|_| P2pError::ChannelClosed)
                    }
                }
            } else {
                quote! {
                    pub fn #real_name(&mut self #(, #func_args)*) -> core::result::Result<(), P2pError> {
                        self.tx
                            .send(#orig::#name { #(#chan_args,)* })
                            .map_err(|_| P2pError::ChannelClosed)
                    }
                }
            }
        })
        .collect::<Vec<_>>();

    quote! {
        #[derive(Debug, Clone)]
        pub struct #sender {
            tx: mpsc::UnboundedSender<#orig>,
        }

        impl #sender {
            pub fn new(tx: mpsc::UnboundedSender<#orig>) -> Self {
                Self { tx }
            }

            #(#methods)*
        }
    }
    .into()
}
