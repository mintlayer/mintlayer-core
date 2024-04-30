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
        let order_data = self.get_order_data(&id)?.ok_or(Error::OrderDataNotFound(id))?;
        let give_balance =
            self.get_give_balance(&id)?.ok_or(Error::OrderGiveBalanceNotFound(id))?;
        let ask_balance = self.get_ask_balance(&id)?.ok_or(Error::OrderAskBalanceNotFound(id))?;

        {
            let ask_balance = match order_data.ask {
                OutputValue::Coin(_) => OutputValue::Coin(ask_balance),
                OutputValue::TokenV0(_) => return Err(Error::UnsupportedTokenVersion),
                OutputValue::TokenV1(token_id, _) => OutputValue::TokenV1(token_id, ask_balance),
            };

            // FIXME: given_value > ask_balance should be possible
            ensure_currencies_and_amounts_match(id, &ask_balance, &fill_value)?;
        }

        let filled_amount = calculate_filled_amount(ask_balance, give_balance, fill_value.amount())
            .ok_or(Error::OrderOverflow(id))?;

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

fn calculate_filled_amount(ask: Amount, give: Amount, fill: Amount) -> Option<Amount> {
    (give * fill.into_atoms()).and_then(|v| v / ask.into_atoms())
}

fn ensure_currencies_and_amounts_match(
    order_id: OrderId,
    left: &OutputValue,
    right: &OutputValue,
) -> Result<()> {
    match (left, right) {
        (OutputValue::Coin(amount1), OutputValue::Coin(amount2)) => {
            ensure!(amount1 >= amount2, Error::OrderOverflow(order_id));
            Ok(())
        }
        (OutputValue::TokenV1(id1, amount1), OutputValue::TokenV1(id2, amount2)) => {
            ensure!(amount1 >= amount2, Error::OrderOverflow(order_id));
            ensure!(id1 == id2, Error::CurrencyMismatch);
            Ok(())
        }
        (OutputValue::Coin(_), OutputValue::TokenV1(_, _))
        | (OutputValue::TokenV1(_, _), OutputValue::Coin(_)) => Err(Error::CurrencyMismatch),
        (OutputValue::TokenV0(_), _) | (_, OutputValue::TokenV0(_)) => {
            Err(Error::UnsupportedTokenVersion)
        }
    }
}
