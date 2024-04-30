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

use common::{
    chain::{output_value::OutputValue, OrderData, OrderId},
    primitives::Amount,
};
use utils::ensure;

use crate::{
    calculate_fill_order,
    data::OrdersAccountingDeltaData,
    error::{Error, Result},
    operations::{
        CreateOrderUndo, FillOrderUndo, OrdersAccountingOperations, OrdersAccountingUndo,
    },
    view::OrdersAccountingView,
};

pub struct OrdersAccountingCache<P> {
    parent: P,
    data: OrdersAccountingDeltaData,
}

impl<P: OrdersAccountingView> OrdersAccountingCache<P> {
    pub fn new(parent: P) -> Self {
        Self {
            parent,
            data: OrdersAccountingDeltaData::new(),
        }
    }

    pub fn consume(self) -> OrdersAccountingDeltaData {
        self.data
    }

    pub fn data(&self) -> &OrdersAccountingDeltaData {
        &self.data
    }
}

impl<P: OrdersAccountingView> OrdersAccountingView for OrdersAccountingCache<P> {
    type Error = Error;

    fn get_order_data(&self, id: &OrderId) -> Result<Option<OrderData>> {
        todo!()
    }

    fn get_ask_balance(&self, id: &OrderId) -> Result<Option<Amount>> {
        todo!()
    }

    fn get_give_balance(&self, id: &OrderId) -> Result<Option<Amount>> {
        todo!()
    }
}

impl<P: OrdersAccountingView> OrdersAccountingOperations for OrdersAccountingCache<P> {
    fn create_order(&mut self, id: OrderId, data: OrderData) -> Result<OrdersAccountingUndo> {
        if self.get_order_data(&id)?.is_some() {
            return Err(Error::OrderAlreadyExists(id));
        }

        if self.get_ask_balance(&id)?.is_some() {
            return Err(Error::OrderAlreadyExists(id));
        }

        // FIXME: ask type != give ?
        let ask_value = data.ask.clone();
        let give_value = data.give.clone();
        let undo_data = self
            .data
            .order_data
            .merge_delta_data_element(id, accounting::DataDelta::new(None, Some(data)))?;

        self.data.ask_balances.add_unsigned(id, ask_value.amount())?;
        self.data.give_balances.add_unsigned(id, give_value.amount())?;

        Ok(OrdersAccountingUndo::CreateOrder(CreateOrderUndo {
            id,
            undo_data,
        }))
    }

    fn fill_order(&mut self, id: OrderId, fill_value: OutputValue) -> Result<OrdersAccountingUndo> {
        let filled_amount = calculate_fill_order(self, id, &fill_value)?;

        self.data.give_balances.sub_unsigned(id, filled_amount)?;
        self.data.ask_balances.sub_unsigned(id, fill_value.amount())?;

        Ok(OrdersAccountingUndo::FillOrder(FillOrderUndo {
            id,
            sub_ask_value: fill_value.amount(),
            sub_give_value: filled_amount,
        }))
    }

    fn undo(&mut self, undo_data: OrdersAccountingUndo) -> Result<()> {
        todo!()
    }
}
