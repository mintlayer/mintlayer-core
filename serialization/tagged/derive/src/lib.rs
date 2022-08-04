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

mod direct;
mod tagged;

use proc_macro::TokenStream;

#[proc_macro_derive(Tagged)]
pub fn derive_tagged(input: TokenStream) -> TokenStream {
    tagged::derive_tagged(&syn::parse(input).expect("not a derivable item")).into()
}

#[proc_macro_derive(DirectEncode)]
pub fn derive_direct_encode(input: TokenStream) -> TokenStream {
    direct::derive_encode(&syn::parse(input).expect("not an enum")).into()
}

#[proc_macro_derive(DirectDecode)]
pub fn derive_direct_decode(input: TokenStream) -> TokenStream {
    direct::derive_decode(&syn::parse(input).expect("not an enum")).into()
}
