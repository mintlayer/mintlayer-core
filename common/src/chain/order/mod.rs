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

use serialization::{Decode, Encode};

use super::{output_value::OutputValue, Destination};

mod order_id;
pub use order_id::OrderId;

mod rpc;
pub use rpc::RpcOrderInfo;

/// Order data provides unified data structure to represent an order.
/// There are no buy or sell types of orders per se but rather exchanges.
/// The fields represent currencies and amounts to be exchanged and the trading pair can be deducted from it.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, serde::Serialize, serde::Deserialize)]
pub struct OrderData {
    /// The key that can authorize conclusion of an order.
    /// Conclusion closes an order and withdraws available funds.
    conclude_key: Destination,
    /// `Ask` and `give` fields represent amounts of currencies
    /// that an order maker wants to exchange.
    /// E.g. Creator of an order asks for 5 coins and gives 10 tokens in exchange.
    ask: OutputValue,
    give: OutputValue,
}

impl OrderData {
    pub fn new(conclude_key: Destination, ask: OutputValue, give: OutputValue) -> Self {
        Self {
            conclude_key,
            ask,
            give,
        }
    }

    pub fn conclude_key(&self) -> &Destination {
        &self.conclude_key
    }

    pub fn ask(&self) -> &OutputValue {
        &self.ask
    }

    pub fn give(&self) -> &OutputValue {
        &self.give
    }

    pub fn consume(self) -> (Destination, OutputValue, OutputValue) {
        (self.conclude_key, self.ask, self.give)
    }
}
