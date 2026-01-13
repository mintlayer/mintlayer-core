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
    chain::{
        output_value::RpcOutputValue, output_values_holder::RpcOutputValuesHolder, AccountNonce,
        Destination,
    },
    primitives::Amount,
};

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct RpcOrderInfo {
    pub conclude_key: Destination,

    pub initially_asked: RpcOutputValue,
    pub initially_given: RpcOutputValue,

    // The remaining amount of the "ask" currency that the order is expected to receive in
    // exchange for the remaining amount of the "give" currency.
    pub ask_balance: Amount,
    // The remaining amount of the "give" currency.
    pub give_balance: Amount,

    pub nonce: Option<AccountNonce>,

    pub is_frozen: bool,
}

impl RpcOutputValuesHolder for RpcOrderInfo {
    fn rpc_output_values_iter(&self) -> impl Iterator<Item = &RpcOutputValue> {
        [&self.initially_asked, &self.initially_given].into_iter()
    }
}
