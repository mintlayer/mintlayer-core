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

use std::ops::Deref;

use common::{chain::OrderId, primitives::Amount};

use crate::data::{OrderData, OrdersAccountingDeltaData, OrdersAccountingDeltaUndoData};

pub trait OrdersAccountingView {
    /// Error that can occur during queries
    type Error: std::error::Error;

    fn get_order_data(&self, id: &OrderId) -> Result<Option<OrderData>, Self::Error>;
    fn get_ask_balance(&self, id: &OrderId) -> Result<Amount, Self::Error>;
    fn get_give_balance(&self, id: &OrderId) -> Result<Amount, Self::Error>;
}

pub trait FlushableOrdersAccountingView {
    /// Errors potentially triggered by flushing the view
    type Error: std::error::Error;

    /// Performs bulk modification
    fn batch_write_orders_data(
        &mut self,
        delta: OrdersAccountingDeltaData,
    ) -> Result<OrdersAccountingDeltaUndoData, Self::Error>;
}

impl<T> OrdersAccountingView for T
where
    T: Deref,
    <T as Deref>::Target: OrdersAccountingView,
{
    type Error = <T::Target as OrdersAccountingView>::Error;

    fn get_order_data(&self, id: &OrderId) -> Result<Option<OrderData>, Self::Error> {
        self.deref().get_order_data(id)
    }

    fn get_ask_balance(&self, id: &OrderId) -> Result<Amount, Self::Error> {
        self.deref().get_ask_balance(id)
    }

    fn get_give_balance(&self, id: &OrderId) -> Result<Amount, Self::Error> {
        self.deref().get_give_balance(id)
    }
}
