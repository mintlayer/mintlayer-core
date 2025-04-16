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

use common::{chain::OrderId, primitives::Amount};

use crate::OrderData;

use super::{OrdersAccountingStorageRead, OrdersAccountingStorageWrite};

#[must_use]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct InMemoryOrdersAccounting {
    orders_data: BTreeMap<OrderId, OrderData>,
    ask_balances: BTreeMap<OrderId, Amount>,
    give_balances: BTreeMap<OrderId, Amount>,
}

impl InMemoryOrdersAccounting {
    pub fn new() -> Self {
        Self {
            orders_data: Default::default(),
            ask_balances: Default::default(),
            give_balances: Default::default(),
        }
    }

    pub fn from_values(
        orders_data: BTreeMap<OrderId, OrderData>,
        ask_balances: BTreeMap<OrderId, Amount>,
        give_balances: BTreeMap<OrderId, Amount>,
    ) -> Self {
        Self {
            orders_data,
            ask_balances,
            give_balances,
        }
    }

    pub fn orders_data(&self) -> &BTreeMap<OrderId, OrderData> {
        &self.orders_data
    }

    pub fn ask_balances(&self) -> &BTreeMap<OrderId, Amount> {
        &self.ask_balances
    }

    pub fn give_balances(&self) -> &BTreeMap<OrderId, Amount> {
        &self.give_balances
    }
}

impl OrdersAccountingStorageRead for InMemoryOrdersAccounting {
    type Error = crate::Error;

    fn get_order_data(&self, id: &OrderId) -> Result<Option<OrderData>, Self::Error> {
        Ok(self.orders_data.get(id).cloned())
    }

    fn get_ask_balance(&self, id: &OrderId) -> Result<Option<Amount>, Self::Error> {
        Ok(self.ask_balances.get(id).cloned())
    }

    fn get_give_balance(&self, id: &OrderId) -> Result<Option<Amount>, Self::Error> {
        Ok(self.give_balances.get(id).cloned())
    }
}

impl OrdersAccountingStorageWrite for InMemoryOrdersAccounting {
    fn set_order_data(&mut self, id: &OrderId, data: &OrderData) -> Result<(), Self::Error> {
        self.orders_data.insert(*id, data.clone());
        Ok(())
    }

    fn del_order_data(&mut self, id: &OrderId) -> Result<(), Self::Error> {
        self.orders_data.remove(id);
        Ok(())
    }

    fn set_ask_balance(&mut self, id: &OrderId, balance: &Amount) -> Result<(), Self::Error> {
        self.ask_balances.insert(*id, *balance);
        Ok(())
    }

    fn del_ask_balance(&mut self, id: &OrderId) -> Result<(), Self::Error> {
        self.ask_balances.remove(id);
        Ok(())
    }

    fn set_give_balance(&mut self, id: &OrderId, balance: &Amount) -> Result<(), Self::Error> {
        self.give_balances.insert(*id, *balance);
        Ok(())
    }

    fn del_give_balance(&mut self, id: &OrderId) -> Result<(), Self::Error> {
        self.give_balances.remove(id);
        Ok(())
    }
}
