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
use utils::tap_log::TapLog;

use crate::{
    data::{OrdersAccountingDeltaData, OrdersAccountingDeltaUndoData},
    error::Error,
    view::{FlushableOrdersAccountingView, OrdersAccountingView},
    OrderData,
};

use super::{OrdersAccountingStorageRead, OrdersAccountingStorageWrite};

#[must_use]
pub struct OrdersAccountingDB<S>(S);

impl<S: OrdersAccountingStorageRead> OrdersAccountingDB<S> {
    pub fn new(store: S) -> Self {
        Self(store)
    }
}

impl<S: OrdersAccountingStorageWrite> OrdersAccountingDB<S> {
    pub fn merge_with_delta(
        &mut self,
        other: OrdersAccountingDeltaData,
    ) -> Result<OrdersAccountingDeltaUndoData, Error> {
        let data_undo = other
            .order_data
            .consume()
            .into_iter()
            .map(|(id, delta)| -> Result<_, Error> {
                let undo = delta.clone().invert();
                let old_data = self.0.get_order_data(&id).log_err().map_err(|_| Error::ViewFail)?;
                match combine_data_with_delta(old_data, Some(delta))? {
                    Some(result) => self
                        .0
                        .set_order_data(&id, &result)
                        .log_err()
                        .map_err(|_| Error::StorageWrite)?,
                    None => {
                        self.0.del_order_data(&id).log_err().map_err(|_| Error::StorageWrite)?
                    }
                };
                Ok((id, undo))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        let ask_balance_undo = other
            .ask_balances
            .consume()
            .into_iter()
            .map(|(id, delta)| -> Result<_, Error> {
                let balance = self
                    .0
                    .get_ask_balance(&id)
                    .log_err()
                    .map_err(|_| Error::ViewFail)?
                    .unwrap_or(Amount::ZERO);
                let result = combine_amount_delta(balance, Some(delta))?;
                if result > Amount::ZERO {
                    self.0
                        .set_ask_balance(&id, &result)
                        .log_err()
                        .map_err(|_| Error::StorageWrite)?
                } else {
                    self.0.del_ask_balance(&id).log_err().map_err(|_| Error::StorageWrite)?
                };
                let balance_undo = delta.neg().expect("amount negation some");
                Ok((id, balance_undo))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        let give_balance_undo = other
            .give_balances
            .consume()
            .into_iter()
            .map(|(id, delta)| -> Result<_, Error> {
                let balance = self
                    .0
                    .get_give_balance(&id)
                    .log_err()
                    .map_err(|_| Error::ViewFail)?
                    .unwrap_or(Amount::ZERO);
                let result = combine_amount_delta(balance, Some(delta))?;
                if result > Amount::ZERO {
                    self.0
                        .set_give_balance(&id, &result)
                        .log_err()
                        .map_err(|_| Error::StorageWrite)?
                } else {
                    self.0.del_give_balance(&id).log_err().map_err(|_| Error::StorageWrite)?
                };
                let balance_undo = delta.neg().expect("amount negation some");
                Ok((id, balance_undo))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        Ok(OrdersAccountingDeltaUndoData {
            order_data: DeltaDataUndoCollection::from_data(data_undo),
            ask_balances: DeltaAmountCollection::from_iter(ask_balance_undo),
            give_balances: DeltaAmountCollection::from_iter(give_balance_undo),
        })
    }
}

impl<S: OrdersAccountingStorageRead> OrdersAccountingView for OrdersAccountingDB<S> {
    type Error = S::Error;

    fn get_order_data(&self, id: &OrderId) -> Result<Option<OrderData>, Self::Error> {
        self.0.get_order_data(id)
    }

    fn get_ask_balance(&self, id: &OrderId) -> Result<Amount, Self::Error> {
        self.0.get_ask_balance(id).map(|v| v.unwrap_or(Amount::ZERO))
    }

    fn get_give_balance(&self, id: &OrderId) -> Result<Amount, Self::Error> {
        self.0.get_give_balance(id).map(|v| v.unwrap_or(Amount::ZERO))
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
        self.merge_with_delta(delta).log_err().map_err(|_| Error::StorageWrite)
    }
}
