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

use rpc_description::HasValueHint;

use crate::{
    chain::{output_value::RpcOutputValue, AccountNonce, Destination},
    primitives::Amount,
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct RpcOrderInfo {
    pub conclude_key: Destination,

    pub initially_asked: RpcOutputValue,
    pub initially_given: RpcOutputValue,

    // left to offer
    pub give_balance: Amount,
    // how much more is expected to get in return
    pub ask_balance: Amount,

    pub nonce: Option<AccountNonce>,
}
