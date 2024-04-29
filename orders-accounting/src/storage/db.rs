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

use std::{collections::BTreeMap, ops::Neg};

use accounting::{
    combine_amount_delta, combine_data_with_delta, DeltaAmountCollection, DeltaDataUndoCollection,
};
use common::{chain::OrderId, primitives::Amount};

use crate::{
    data::{OrderData, OrdersAccountingDeltaData, OrdersAccountingDeltaUndoData},
    error::Error,
    view::{FlushableOrdersAccountingView, OrdersAccountingView},
};

use super::{OrdersAccountingStorageRead, OrdersAccountingStorageWrite};

#[must_use]
pub struct OrdersAccountingDB<S>(S);

impl<S: OrdersAccountingStorageRead> OrdersAccountingDB<S> {
    pub fn new(store: S) -> Self {
        Self(store)
    }
}

impl<S: OrdersAccountingStorageRead> OrdersAccountingView for OrdersAccountingDB<S> {
    type Error = S::Error;

    fn get_order_data(&self, id: &OrderId) -> Result<Option<OrderData>, Self::Error> {
        self.0.get_order_data(id)
    }

    fn get_ask_balance(&self, id: &OrderId) -> Result<Option<Amount>, Self::Error> {
        self.0.get_ask_balance(id)
    }

    fn get_give_balance(&self, id: &OrderId) -> Result<Option<Amount>, Self::Error> {
        self.0.get_give_balance(id)
    }
}

impl<S: OrdersAccountingStorageRead> OrdersAccountingStorageRead for OrdersAccountingDB<S> {
    type Error = S::Error;

    fn get_order_data(&self, id: &OrderId) -> Result<Option<OrderData>, Self::Error> {
        self.0.get_order_data(id)
    }

    fn get_ask_balance(&self, id: &OrderId) -> Result<Option<Amount>, Self::Error> {
        self.0.get_ask_balance(id)
    }

    fn get_give_balance(&self, id: &OrderId) -> Result<Option<Amount>, Self::Error> {
        self.0.get_give_balance(id)
    }
}

impl<S: OrdersAccountingStorageWrite> OrdersAccountingStorageWrite for OrdersAccountingDB<S> {
    fn set_order_data(&mut self, id: &OrderId, data: &OrderData) -> Result<(), Self::Error> {
        self.0.set_order_data(id, data)
    }

    fn del_order_data(&mut self, id: &OrderId) -> Result<(), Self::Error> {
        self.0.del_order_data(id)
    }

    fn set_ask_balance(&mut self, id: &OrderId, balance: &Amount) -> Result<(), Self::Error> {
        self.0.set_ask_balance(id, balance)
    }

    fn del_ask_balance(&mut self, id: &OrderId) -> Result<(), Self::Error> {
        self.0.del_ask_balance(id)
    }

    fn set_give_balance(&mut self, id: &OrderId, balance: &Amount) -> Result<(), Self::Error> {
        self.0.set_give_balance(id, balance)
    }

    fn del_give_balance(&mut self, id: &OrderId) -> Result<(), Self::Error> {
        self.0.del_give_balance(id)
    }
}

impl<S: OrdersAccountingStorageWrite> FlushableOrdersAccountingView for OrdersAccountingDB<S> {
    type Error = Error;

    fn batch_write_orders_data(
        &mut self,
        delta: OrdersAccountingDeltaData,
    ) -> Result<OrdersAccountingDeltaUndoData, Self::Error> {
        //self.merge_with_delta(delta).log_err().map_err(|_| Error::StorageWrite)
        todo!()
    }
}
