// Copyright (c) 2021 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): A. Altonen
use proc_macro::{self, TokenStream};
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(Message)]
pub fn message(input: TokenStream) -> TokenStream {
    let data = parse_macro_input!(input as DeriveInput);
    let ident = data.ident;

    let fields = if let syn::Data::Struct(syn::DataStruct {
        fields: syn::Fields::Named(syn::FieldsNamed { ref named, .. }),
        ..
    }) = data.data
    {
        named
    } else {
        panic!("`#[derive(Message)]` can only be used with structs!");
    };

    let build_list = fields.iter().map(|f| {
        let name = &f.ident;
        let ty = &f.ty;

        quote! {
            #name: #ty
        }
    });

    let build_vars = fields.iter().map(|f| {
        let name = &f.ident;

        quote! {
            #name
        }
    });

    quote! {
        impl #ident {
            pub fn new(#(#build_list,)*) -> Self {
                Self {
                    #(#build_vars,)*
                }
            }
        }

        impl std::convert::Into<Message> for #ident {
            fn into(self) -> Message {
                let encoded = self.encode();
                Message {
                    magic: MAGIC_BYTES,
                    msg_type: MessageType::#ident,
                    size: encoded.len() as u32,
                    payload: encoded,
                }
            }
        }

        impl std::convert::TryFrom<Message> for #ident {
            type Error = crate::error::P2pError;

            fn try_from(msg: Message) -> Result<#ident, Self::Error> {
                if msg.msg_type != MessageType::#ident {
                    return Err(
                        Self::Error::DecodeFailure("Invalid message type".to_string())
                    );
                }

                Ok(Decode::decode(&mut &msg.payload[..])?)
            }
        }
    }
    .into()
}
