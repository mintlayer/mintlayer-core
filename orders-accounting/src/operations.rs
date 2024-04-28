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
    chain::{output_value::OutputValue, OrderId},
    primitives::Amount,
};
use serialization::{Decode, Encode};
use variant_count::VariantCount;

use crate::{data::OrderData, error::Result};

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct CreateOrderUndo {
    pub(crate) id: OrderId,
    pub(crate) undo_data: DataDeltaUndo<OrderData>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct CancelOrderUndo {
    pub(crate) id: OrderId,
    pub(crate) undo_data: DataDeltaUndo<OrderData>,
    pub(crate) ask_value: OutputValue,
    pub(crate) give_value: OutputValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct FillOrderUndo {
    pub(crate) id: OrderId,
    pub(crate) sub_ask_value: Amount,
    pub(crate) sub_give_value: Amount,
}

#[must_use]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, VariantCount)]
pub enum OrdersAccountingUndo {
    CreateOrder(CreateOrderUndo),
    CancelOrder(CancelOrderUndo),
    FillOrder(FillOrderUndo),
}

pub trait OrdersAccountingOperations {
    fn create_order(&mut self, id: OrderId, data: OrderData) -> Result<OrdersAccountingUndo>;

    fn fill_order(&mut self, id: OrderId, value: OutputValue) -> Result<OrdersAccountingUndo>;

    fn undo(&mut self, undo_data: OrdersAccountingUndo) -> Result<()>;
}
