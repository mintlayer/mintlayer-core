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

use accounting::combine_amount_delta;
use common::{
    chain::{OrderData, OrderId, OrdersVersion},
    primitives::Amount,
};
use logging::log;
use utils::ensure;

use crate::{
    calculate_fill_order,
    data::OrdersAccountingDeltaData,
    error::{Error, Result},
    operations::{
        ConcludeOrderUndo, CreateOrderUndo, FillOrderUndo, OrdersAccountingOperations,
        OrdersAccountingUndo,
    },
    view::OrdersAccountingView,
    FlushableOrdersAccountingView, OrdersAccountingDeltaUndoData,
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

    fn undo_create_order(&mut self, undo: CreateOrderUndo) -> Result<()> {
        ensure!(
            self.get_ask_balance(&undo.id)? == undo.ask_balance,
            Error::InvariantOrderAskBalanceChangedForUndo(undo.id)
        );
        self.data.ask_balances.sub_unsigned(undo.id, undo.ask_balance)?;

        ensure!(
            self.get_give_balance(&undo.id)? == undo.give_balance,
            Error::InvariantOrderGiveBalanceChangedForUndo(undo.id)
        );
        self.data.give_balances.sub_unsigned(undo.id, undo.give_balance)?;

        ensure!(
            self.get_order_data(&undo.id)?.is_some(),
            Error::InvariantOrderDataNotFoundForUndo(undo.id)
        );
        self.data.order_data.undo_merge_delta_data_element(undo.id, undo.undo_data)?;

        Ok(())
    }

    fn undo_conclude_order(&mut self, undo: ConcludeOrderUndo) -> Result<()> {
        ensure!(
            self.get_order_data(&undo.id)?.is_none(),
            Error::InvariantOrderDataExistForConcludeUndo(undo.id)
        );
        self.data.order_data.undo_merge_delta_data_element(undo.id, undo.undo_data)?;

        ensure!(
            self.get_ask_balance(&undo.id)? == Amount::ZERO,
            Error::InvariantOrderAskBalanceExistForConcludeUndo(undo.id)
        );
        self.data.ask_balances.add_unsigned(undo.id, undo.ask_balance)?;

        ensure!(
            self.get_give_balance(&undo.id)? == Amount::ZERO,
            Error::InvariantOrderGiveBalanceExistForConcludeUndo(undo.id)
        );
        self.data.give_balances.add_unsigned(undo.id, undo.give_balance)?;

        Ok(())
    }

    fn undo_fill_order(&mut self, undo: FillOrderUndo) -> Result<()> {
        self.data.ask_balances.add_unsigned(undo.id, undo.ask_balance)?;
        self.data.give_balances.add_unsigned(undo.id, undo.give_balance)?;

        Ok(())
    }
}

impl<P: OrdersAccountingView> OrdersAccountingView for OrdersAccountingCache<P> {
    type Error = Error;

    fn get_order_data(&self, id: &OrderId) -> Result<Option<OrderData>> {
        match self.data.order_data.get_data(id) {
            accounting::GetDataResult::Present(d) => Ok(Some(d.clone())),
            accounting::GetDataResult::Deleted => Ok(None),
            accounting::GetDataResult::Missing => {
                Ok(self.parent.get_order_data(id).map_err(|_| Error::ViewFail)?)
            }
        }
    }

    fn get_ask_balance(&self, id: &OrderId) -> Result<Amount> {
        let parent_supply = self.parent.get_ask_balance(id).map_err(|_| Error::ViewFail)?;
        let local_delta = self.data.ask_balances.data().get(id).cloned();
        combine_amount_delta(parent_supply, local_delta).map_err(Error::AccountingError)
    }

    fn get_give_balance(&self, id: &OrderId) -> Result<Amount> {
        let parent_supply = self.parent.get_give_balance(id).map_err(|_| Error::ViewFail)?;
        let local_delta = self.data.give_balances.data().get(id).cloned();
        combine_amount_delta(parent_supply, local_delta).map_err(Error::AccountingError)
    }
}

impl<P: OrdersAccountingView> OrdersAccountingOperations for OrdersAccountingCache<P> {
    fn create_order(&mut self, id: OrderId, data: OrderData) -> Result<OrdersAccountingUndo> {
        log::debug!("Creating an order: {:?} {:?}", id, data);

        ensure!(
            self.get_order_data(&id)?.is_none(),
            Error::OrderAlreadyExists(id)
        );

        ensure!(
            self.get_ask_balance(&id)? == Amount::ZERO,
            Error::OrderAlreadyExists(id)
        );

        let ask_amount = crate::output_value_amount(data.ask())?;
        let give_amount = crate::output_value_amount(data.give())?;

        ensure!(
            ask_amount > Amount::ZERO && give_amount > Amount::ZERO,
            Error::OrderWithZeroValue(id)
        );

        let undo_data = self
            .data
            .order_data
            .merge_delta_data_element(id, accounting::DataDelta::new(None, Some(data)))?;

        self.data.ask_balances.add_unsigned(id, ask_amount)?;
        self.data.give_balances.add_unsigned(id, give_amount)?;

        Ok(OrdersAccountingUndo::CreateOrder(CreateOrderUndo {
            id,
            undo_data,
            ask_balance: ask_amount,
            give_balance: give_amount,
        }))
    }

    fn conclude_order(&mut self, id: OrderId) -> Result<OrdersAccountingUndo> {
        log::debug!("Concluding an order: {:?}", id);

        let order_data = self
            .get_order_data(&id)?
            .ok_or(Error::AttemptedConcludeNonexistingOrderData(id))?;
        let ask_balance = self.get_ask_balance(&id)?;
        let give_balance = self.get_give_balance(&id)?;

        let undo_data = self
            .data
            .order_data
            .merge_delta_data_element(id, accounting::DataDelta::new(Some(order_data), None))?;

        self.data.ask_balances.sub_unsigned(id, ask_balance)?;
        self.data.give_balances.sub_unsigned(id, give_balance)?;

        Ok(OrdersAccountingUndo::ConcludeOrder(ConcludeOrderUndo {
            id,
            undo_data,
            ask_balance,
            give_balance,
        }))
    }

    fn fill_order(
        &mut self,
        id: OrderId,
        fill_amount_in_ask_currency: Amount,
        orders_version: OrdersVersion,
    ) -> Result<OrdersAccountingUndo> {
        log::debug!(
            "Filling an order: {:?} {:?}",
            id,
            fill_amount_in_ask_currency
        );

        ensure!(
            self.get_order_data(&id)?.is_some(),
            Error::OrderDataNotFound(id)
        );

        let filled_amount =
            calculate_fill_order(self, id, fill_amount_in_ask_currency, orders_version)?;

        self.data.give_balances.sub_unsigned(id, filled_amount)?;
        self.data.ask_balances.sub_unsigned(id, fill_amount_in_ask_currency)?;

        Ok(OrdersAccountingUndo::FillOrder(FillOrderUndo {
            id,
            ask_balance: fill_amount_in_ask_currency,
            give_balance: filled_amount,
        }))
    }

    fn undo(&mut self, undo_data: OrdersAccountingUndo) -> Result<()> {
        log::debug!("Undo an order: {:?}", undo_data);
        match undo_data {
            OrdersAccountingUndo::CreateOrder(undo) => self.undo_create_order(undo),
            OrdersAccountingUndo::ConcludeOrder(undo) => self.undo_conclude_order(undo),
            OrdersAccountingUndo::FillOrder(undo) => self.undo_fill_order(undo),
        }
    }
}

impl<P> FlushableOrdersAccountingView for OrdersAccountingCache<P> {
    type Error = Error;

    fn batch_write_orders_data(
        &mut self,
        delta: OrdersAccountingDeltaData,
    ) -> Result<OrdersAccountingDeltaUndoData> {
        self.data.merge_with_delta(delta)
    }
}
