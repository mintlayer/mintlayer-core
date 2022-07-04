// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

mod errors;
pub use errors::*;
mod base32;
mod bech32m;
mod decoded;
pub use bech32m::arbitrary_data_to_bech32m as encode;
pub use bech32m::bech32m_to_arbitrary_data as decode;
pub use decoded::DecodedArbitraryDataFromBech32;
pub use decoded::DecodedBase32FromBech32;

#[cfg(test)]
mod tests;
