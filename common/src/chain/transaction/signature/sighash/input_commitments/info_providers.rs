// Copyright (c) 2021-2025 RBB S.r.l
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

use std::{borrow::Cow, collections::BTreeMap};

use crate::{
    chain::{output_value::OutputValue, OrderId, PoolId, TxOutput, UtxoOutPoint},
    primitives::Amount,
};

#[derive(Debug, Clone)]
pub struct PoolInfo {
    pub staker_balance: Amount,
}

#[derive(Debug, Clone)]
pub struct OrderInfo {
    pub initially_asked: OutputValue,
    pub initially_given: OutputValue,
    pub ask_balance: Amount,
    pub give_balance: Amount,
}

pub trait UtxoProvider<'a> {
    type Error: std::error::Error;

    fn get_utxo(
        &self,
        tx_input_index: usize,
        outpoint: &UtxoOutPoint,
    ) -> Result<Option<Cow<'a, TxOutput>>, Self::Error>;
}

pub struct TrivialUtxoProvider<'a>(pub &'a [Option<TxOutput>]);

impl<'a> UtxoProvider<'a> for TrivialUtxoProvider<'a> {
    type Error = std::convert::Infallible;

    fn get_utxo(
        &self,
        tx_input_index: usize,
        _outpoint: &UtxoOutPoint,
    ) -> Result<Option<Cow<'a, TxOutput>>, Self::Error> {
        Ok(self.0.get(tx_input_index).and_then(|utxo| utxo.as_ref().map(Cow::Borrowed)))
    }
}

pub trait PoolInfoProvider {
    type Error: std::error::Error;

    fn get_pool_info(&self, pool_id: &PoolId) -> Result<Option<PoolInfo>, Self::Error>;
}

impl PoolInfoProvider for BTreeMap<PoolId, PoolInfo> {
    type Error = std::convert::Infallible;

    fn get_pool_info(&self, pool_id: &PoolId) -> Result<Option<PoolInfo>, Self::Error> {
        Ok(self.get(pool_id).cloned())
    }
}

pub trait OrderInfoProvider {
    type Error: std::error::Error;

    fn get_order_info(&self, order_id: &OrderId) -> Result<Option<OrderInfo>, Self::Error>;
}

impl OrderInfoProvider for BTreeMap<OrderId, OrderInfo> {
    type Error = std::convert::Infallible;

    fn get_order_info(&self, order_id: &OrderId) -> Result<Option<OrderInfo>, Self::Error> {
        Ok(self.get(order_id).cloned())
    }
}
