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

use std::collections::BTreeMap;

use accounting::{DeltaAmountCollection, DeltaDataCollection, DeltaDataUndoCollection};
use common::{
    chain::{output_value::OutputValue, Destination, OrderId},
    primitives::Amount,
};
use serialization::{Decode, Encode};

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct OrderData {
    conclude_key: Destination,
    ask: OutputValue,
    give: OutputValue,
    is_freezed: bool,
}

impl OrderData {
    pub fn new(conclude_key: Destination, ask: OutputValue, give: OutputValue) -> Self {
        Self {
            conclude_key,
            ask,
            give,
            is_freezed: false,
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

    pub fn is_freezed(&self) -> bool {
        self.is_freezed
    }

    pub fn try_freeze(self) -> Result<Self, Self> {
        if self.is_freezed() {
            Err(self)
        } else {
            Ok(Self {
                conclude_key: self.conclude_key,
                ask: self.ask,
                give: self.give,
                is_freezed: true,
            })
        }
    }
}

impl From<common::chain::OrderData> for OrderData {
    fn from(other: common::chain::OrderData) -> Self {
        let (conclude_key, ask, give) = other.consume();
        OrderData::new(conclude_key, ask, give)
    }
}

#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq)]
pub struct OrdersAccountingData {
    pub order_data: BTreeMap<OrderId, OrderData>,
    pub ask_balances: BTreeMap<OrderId, Amount>,
    pub give_balances: BTreeMap<OrderId, Amount>,
}

impl OrdersAccountingData {
    pub fn new() -> Self {
        Self {
            order_data: BTreeMap::new(),
            ask_balances: BTreeMap::new(),
            give_balances: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq)]
pub struct OrdersAccountingDeltaData {
    pub(crate) order_data: DeltaDataCollection<OrderId, OrderData>,
    pub(crate) ask_balances: DeltaAmountCollection<OrderId>,
    pub(crate) give_balances: DeltaAmountCollection<OrderId>,
}

impl OrdersAccountingDeltaData {
    pub fn merge_with_delta(
        &mut self,
        other: OrdersAccountingDeltaData,
    ) -> Result<OrdersAccountingDeltaUndoData, crate::error::Error> {
        let order_data_undo = self.order_data.merge_delta_data(other.order_data)?;

        let ask_balance_undo = other.ask_balances.clone();
        self.ask_balances.merge_delta_amounts(other.ask_balances)?;

        let give_balance_undo = other.give_balances.clone();
        self.give_balances.merge_delta_amounts(other.give_balances)?;

        Ok(OrdersAccountingDeltaUndoData {
            order_data: order_data_undo,
            ask_balances: ask_balance_undo,
            give_balances: give_balance_undo,
        })
    }
}

impl OrdersAccountingDeltaData {
    pub fn new() -> Self {
        Self {
            order_data: DeltaDataCollection::new(),
            ask_balances: DeltaAmountCollection::new(),
            give_balances: DeltaAmountCollection::new(),
        }
    }
}

#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq)]
pub struct OrdersAccountingDeltaUndoData {
    pub(crate) order_data: DeltaDataUndoCollection<OrderId, OrderData>,
    pub(crate) ask_balances: DeltaAmountCollection<OrderId>,
    pub(crate) give_balances: DeltaAmountCollection<OrderId>,
}

impl OrdersAccountingDeltaUndoData {
    pub fn new() -> Self {
        Self {
            order_data: DeltaDataUndoCollection::new(),
            ask_balances: DeltaAmountCollection::new(),
            give_balances: DeltaAmountCollection::new(),
        }
    }
}
