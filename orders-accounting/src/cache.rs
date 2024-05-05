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
        WithdrawOrderUndo,
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
            self.get_order_data(&undo.id)?.is_some(),
            Error::InvariantOrderDataNotFoundForUndo(undo.id)
        );
        self.data.order_data.undo_merge_delta_data_element(undo.id, undo.undo_data)?;

        match self.get_ask_balance(&undo.id)? {
            Some(balance) => {
                if balance != undo.ask_balance {
                    return Err(Error::InvariantOrderAskBalanceChangedForUndo(undo.id));
                }
            }
            None => return Err(Error::InvariantOrderAskBalanceNotFoundForUndo(undo.id)),
        }
        self.data.ask_balances.sub_unsigned(undo.id, undo.ask_balance)?;

        match self.get_give_balance(&undo.id)? {
            Some(balance) => {
                if balance != undo.give_balance {
                    return Err(Error::InvariantOrderGiveBalanceChangedForUndo(undo.id));
                }
            }
            None => return Err(Error::InvariantOrderGiveBalanceNotFoundForUndo(undo.id)),
        }
        self.data.give_balances.sub_unsigned(undo.id, undo.give_balance)?;

        Ok(())
    }

    fn undo_withdraw_order(&mut self, undo: WithdrawOrderUndo) -> Result<()> {
        ensure!(
            self.get_order_data(&undo.id)?.is_none(),
            Error::InvariantOrderDataExistForWithdrawUndo(undo.id)
        );
        self.data.order_data.undo_merge_delta_data_element(undo.id, undo.undo_data)?;

        ensure!(
            self.get_ask_balance(&undo.id)?.unwrap_or(Amount::ZERO) == Amount::ZERO,
            Error::InvariantOrderAskBalanceExistForWithdrawUndo(undo.id)
        );
        self.data.ask_balances.add_unsigned(undo.id, undo.ask_balance)?;

        ensure!(
            self.get_give_balance(&undo.id)?.unwrap_or(Amount::ZERO) == Amount::ZERO,
            Error::InvariantOrderGiveBalanceExistForWithdrawUndo(undo.id)
        );
        self.data.give_balances.add_unsigned(undo.id, undo.give_balance)?;

        Ok(())
    }

    fn undo_fill_order(&mut self, undo: FillOrderUndo) -> Result<()> {
        if let Some(undo_data) = undo.undo_data {
            ensure!(
                self.get_order_data(&undo.id)?.is_none(),
                Error::InvariantOrderDataExistForWithdrawUndo(undo.id)
            );
            self.data.order_data.undo_merge_delta_data_element(undo.id, undo_data)?;
        }

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

    fn get_ask_balance(&self, id: &OrderId) -> Result<Option<Amount>> {
        let parent_supply = self.parent.get_ask_balance(id).map_err(|_| Error::ViewFail)?;
        let local_delta = self.data.ask_balances.data().get(id).cloned();
        combine_amount_delta(&parent_supply, &local_delta).map_err(Error::AccountingError)
    }

    fn get_give_balance(&self, id: &OrderId) -> Result<Option<Amount>> {
        let parent_supply = self.parent.get_give_balance(id).map_err(|_| Error::ViewFail)?;
        let local_delta = self.data.give_balances.data().get(id).cloned();
        combine_amount_delta(&parent_supply, &local_delta).map_err(Error::AccountingError)
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

        let ask_value = data.ask().clone();
        let give_value = data.give().clone();
        let undo_data = self
            .data
            .order_data
            .merge_delta_data_element(id, accounting::DataDelta::new(None, Some(data)))?;

        self.data.ask_balances.add_unsigned(id, ask_value.amount())?;
        self.data.give_balances.add_unsigned(id, give_value.amount())?;

        Ok(OrdersAccountingUndo::CreateOrder(CreateOrderUndo {
            id,
            undo_data,
            ask_balance: ask_value.amount(),
            give_balance: give_value.amount(),
        }))
    }

    fn withdraw_order(&mut self, id: OrderId) -> Result<OrdersAccountingUndo> {
        let order_data = self
            .get_order_data(&id)?
            .ok_or(Error::AttemptedWithdrawNonexistingOrderData(id))?;
        let ask_balance = self
            .get_ask_balance(&id)?
            .ok_or(Error::AttemptedWithdrawNonexistingAskBalance(id))?;
        let give_balance = self
            .get_give_balance(&id)?
            .ok_or(Error::AttemptedWithdrawNonexistingGiveBalance(id))?;

        let undo_data = self
            .data
            .order_data
            .merge_delta_data_element(id, accounting::DataDelta::new(Some(order_data), None))?;

        self.data.ask_balances.sub_unsigned(id, ask_balance)?;
        self.data.give_balances.sub_unsigned(id, give_balance)?;

        Ok(OrdersAccountingUndo::WithdrawOrder(WithdrawOrderUndo {
            id,
            undo_data,
            ask_balance,
            give_balance,
        }))
    }

    fn fill_order(&mut self, id: OrderId, fill_value: OutputValue) -> Result<OrdersAccountingUndo> {
        let filled_amount = calculate_fill_order(self, id, &fill_value)?;

        let ask_balance = self.get_ask_balance(&id)?.ok_or(Error::OrderAskBalanceNotFound(id))?;
        let give_balance =
            self.get_give_balance(&id)?.ok_or(Error::OrderGiveBalanceNotFound(id))?;

        // in case the order is completely filled it can be removed
        let undo_data = if fill_value.amount() == ask_balance {
            ensure!(
                filled_amount == give_balance,
                Error::FillOrderChangeLeft(id)
            );

            let order_data = self.get_order_data(&id)?.ok_or(Error::OrderDataNotFound(id))?;
            let undo = self
                .data
                .order_data
                .merge_delta_data_element(id, accounting::DataDelta::new(Some(order_data), None))?;
            Some(undo)
        } else {
            None
        };

        self.data.give_balances.sub_unsigned(id, filled_amount)?;
        self.data.ask_balances.sub_unsigned(id, fill_value.amount())?;

        Ok(OrdersAccountingUndo::FillOrder(FillOrderUndo {
            id,
            undo_data,
            ask_balance: fill_value.amount(),
            give_balance: filled_amount,
        }))
    }

    fn undo(&mut self, undo_data: OrdersAccountingUndo) -> Result<()> {
        match undo_data {
            OrdersAccountingUndo::CreateOrder(undo) => self.undo_create_order(undo),
            OrdersAccountingUndo::WithdrawOrder(undo) => self.undo_withdraw_order(undo),
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
