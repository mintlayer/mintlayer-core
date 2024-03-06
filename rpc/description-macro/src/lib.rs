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

use proc_macro::TokenStream;

mod describe_impl;
mod value_hint;

#[proc_macro_attribute]
pub fn describe(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item: syn::ItemTrait = syn::parse(item).expect("rpc::description not applied to a trait");

    describe_impl::process_trait(item)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

#[proc_macro_derive(HasValueHint)]
pub fn derive_has_value_hint_rpc_desc(item: TokenStream) -> TokenStream {
    value_hint::derive_has_value_hint(item, quote::quote!(::rpc_description))
}
