// Copyright (c) 2023 RBB S.r.l
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

use crate::chain::{tokens::TokenId, ChainConfig, DelegationId, Destination, PoolId};

use super::hexified::HexifiedAddress;

#[allow(clippy::let_and_return)]
pub fn dehexify_all_addresses(conf: &ChainConfig, input: &str) -> String {
    let result = HexifiedAddress::<Destination>::replace_with_address(conf, input).to_string();
    let result = HexifiedAddress::<PoolId>::replace_with_address(conf, &result).to_string();
    let result = HexifiedAddress::<DelegationId>::replace_with_address(conf, &result).to_string();
    let result = HexifiedAddress::<TokenId>::replace_with_address(conf, &result).to_string();

    result
}

// TODO: add tests that create blocks, and ensure the replacement in json works properly.
