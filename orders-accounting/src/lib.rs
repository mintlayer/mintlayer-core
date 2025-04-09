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

mod cache;
mod data;
mod error;
mod operations;
mod price_calculation;
mod storage;
mod view;

pub use {
    cache::OrdersAccountingCache,
    data::{OrdersAccountingData, OrdersAccountingDeltaData, OrdersAccountingDeltaUndoData},
    error::Error,
    operations::{OrdersAccountingOperations, OrdersAccountingUndo},
    price_calculation::{calculate_fill_order, calculate_filled_amount},
    storage::{
        db::OrdersAccountingDB, in_memory::InMemoryOrdersAccounting, OrdersAccountingStorageRead,
        OrdersAccountingStorageWrite,
    },
    view::{FlushableOrdersAccountingView, OrdersAccountingView},
};

use common::{chain::output_value::OutputValue, primitives::Amount};

fn output_value_amount(value: &OutputValue) -> error::Result<Amount> {
    match value {
        OutputValue::Coin(amount) | OutputValue::TokenV1(_, amount) => Ok(*amount),
        OutputValue::TokenV0(_) => Err(Error::UnsupportedTokenVersion),
    }
}

#[cfg(test)]
mod tests;
