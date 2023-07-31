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

use crate::chain::ChainConfig;

pub trait Addressable {
    type Error: std::error::Error;

    #[must_use]
    fn address_prefix(&self, chain_config: &ChainConfig) -> &str;

    #[must_use]
    fn encode_to_bytes_for_address(&self) -> Vec<u8>;

    fn decode_from_bytes_from_address<T: AsRef<[u8]>>(
        address_bytes: T,
    ) -> Result<Self, Self::Error>
    where
        Self: Sized;
}
