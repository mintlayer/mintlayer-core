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

use accounting::DataDeltaUndo;
use common::{
    chain::{OrderId, OrdersVersion},
    primitives::Amount,
};
use serialization::{Decode, Encode};
use strum::EnumCount;

use crate::{error::Result, OrderData};

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct CreateOrderUndo {
    pub(crate) id: OrderId,
    pub(crate) undo_data: DataDeltaUndo<OrderData>,
    pub(crate) ask_balance: Amount,
    pub(crate) give_balance: Amount,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct ConcludeOrderUndo {
    pub(crate) id: OrderId,
    pub(crate) undo_data: DataDeltaUndo<OrderData>,
    pub(crate) ask_balance: Amount,
    pub(crate) give_balance: Amount,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct FillOrderUndo {
    pub(crate) id: OrderId,
    pub(crate) ask_balance: Amount,
    pub(crate) give_balance: Amount,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct FreezeOrderUndo {
    pub(crate) id: OrderId,
    pub(crate) undo_data: DataDeltaUndo<OrderData>,
}

#[must_use]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, EnumCount)]
pub enum OrdersAccountingUndo {
    CreateOrder(CreateOrderUndo),
    ConcludeOrder(ConcludeOrderUndo),
    FillOrder(FillOrderUndo),
    FreezeOrder(FreezeOrderUndo),
}

pub trait OrdersAccountingOperations {
    fn create_order(&mut self, id: OrderId, data: OrderData) -> Result<OrdersAccountingUndo>;
    fn conclude_order(&mut self, id: OrderId) -> Result<OrdersAccountingUndo>;
    fn fill_order(
        &mut self,
        id: OrderId,
        fill_amount_in_ask_currency: Amount,
        orders_version: OrdersVersion,
    ) -> Result<OrdersAccountingUndo>;
    fn freeze_order(&mut self, id: OrderId) -> Result<OrdersAccountingUndo>;

    fn undo(&mut self, undo_data: OrdersAccountingUndo) -> Result<()>;
}
