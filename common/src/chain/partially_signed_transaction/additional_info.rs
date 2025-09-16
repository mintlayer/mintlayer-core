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

use std::collections::BTreeMap;

use serialization::{Decode, Encode};

use crate::{
    chain::{
        output_value::OutputValue,
        signature::sighash::{self},
        tokens::TokenId,
        OrderId, PoolId,
    },
    primitives::Amount,
};

// TODO: get rid of TokenAdditionalInfo here. Currently it's only used when
// PartiallySignedTransaction is passed to a hardware wallet and it provides
// the wallet with the token info to show to the user during signing.
// The problem is that this info should not be trusted by the hardware wallet
// anyway. A hardware wallet should only trust external token infos that are
// signed by a predefined key, but such signed infos should not be part of
// PartiallySignedTransaction anyway.
#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub struct TokenAdditionalInfo {
    pub num_decimals: u8,
    pub ticker: Vec<u8>,
}

/// Pool additional info, which must be present for each ProduceBlockFromStake UTXO consumed by
/// the transaction. Transaction's signature commits to this info since SighashInputCommitments::V1.
// TODO: rename to DecommissionedPoolAdditionalInfo? (or even DecommissionedPoolCommitmentInfo,
// to suggest that it's related to commitments and isn't some arbitrary info about the pool).
#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub struct PoolAdditionalInfo {
    pub staker_balance: Amount,
}

/// Order additional info, which must be present for each FillOrder and ConcludeOrder input consumed
/// by the transaction. Transaction's signature commits to this info since SighashInputCommitments::V1.
/// 
/// Note though that only ConcludeOrder commitments include both initial and current balances,
/// while FillOrder commitments only include the initial ones. So this info representation
/// is not ideal, as it forces the caller to provide additional info that will not actually
/// be used.
// TODO: perhaps it's better to split the struct and the corresponding map into two -
// for the initial and current balances. Also, perhaps the naming should suggest that it
// contains commitments for signing and not just arbitrary info.
#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub struct OrderAdditionalInfo {
    pub initially_asked: OutputValue,
    pub initially_given: OutputValue,
    pub ask_balance: Amount,
    pub give_balance: Amount,
}

#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub struct TxAdditionalInfo {
    token_info: BTreeMap<TokenId, TokenAdditionalInfo>,
    pool_info: BTreeMap<PoolId, PoolAdditionalInfo>,
    order_info: BTreeMap<OrderId, OrderAdditionalInfo>,
}

impl TxAdditionalInfo {
    pub fn new() -> Self {
        Self {
            token_info: BTreeMap::new(),
            pool_info: BTreeMap::new(),
            order_info: BTreeMap::new(),
        }
    }

    pub fn with_token_info(mut self, token_id: TokenId, info: TokenAdditionalInfo) -> Self {
        self.token_info.insert(token_id, info);
        self
    }

    pub fn with_pool_info(mut self, pool_id: PoolId, info: PoolAdditionalInfo) -> Self {
        self.pool_info.insert(pool_id, info);
        self
    }

    pub fn with_order_info(mut self, order_id: OrderId, info: OrderAdditionalInfo) -> Self {
        self.order_info.insert(order_id, info);
        self
    }

    pub fn add_token_info(&mut self, token_id: TokenId, info: TokenAdditionalInfo) {
        self.token_info.insert(token_id, info);
    }

    pub fn add_pool_info(&mut self, pool_id: PoolId, info: PoolAdditionalInfo) {
        self.pool_info.insert(pool_id, info);
    }

    pub fn add_order_info(&mut self, order_id: OrderId, info: OrderAdditionalInfo) {
        self.order_info.insert(order_id, info);
    }

    pub fn join(mut self, other: Self) -> Self {
        self.token_info.extend(other.token_info);
        self.pool_info.extend(other.pool_info);
        self.order_info.extend(other.order_info);
        Self {
            token_info: self.token_info,
            pool_info: self.pool_info,
            order_info: self.order_info,
        }
    }

    pub fn get_token_info(&self, token_id: &TokenId) -> Option<&TokenAdditionalInfo> {
        self.token_info.get(token_id)
    }

    pub fn get_pool_info(&self, pool_id: &PoolId) -> Option<&PoolAdditionalInfo> {
        self.pool_info.get(pool_id)
    }

    pub fn get_order_info(&self, order_id: &OrderId) -> Option<&OrderAdditionalInfo> {
        self.order_info.get(order_id)
    }

    pub fn token_info_iter(&self) -> impl Iterator<Item = (&'_ TokenId, &'_ TokenAdditionalInfo)> {
        self.token_info.iter()
    }

    pub fn pool_info_iter(&self) -> impl Iterator<Item = (&'_ PoolId, &'_ PoolAdditionalInfo)> {
        self.pool_info.iter()
    }

    pub fn order_info_iter(&self) -> impl Iterator<Item = (&'_ OrderId, &'_ OrderAdditionalInfo)> {
        self.order_info.iter()
    }
}

impl sighash::input_commitments::PoolInfoProvider for TxAdditionalInfo {
    type Error = std::convert::Infallible;

    fn get_pool_info(
        &self,
        pool_id: &PoolId,
    ) -> Result<Option<sighash::input_commitments::PoolInfo>, Self::Error> {
        Ok(
            self.pool_info.get(pool_id).map(|info| sighash::input_commitments::PoolInfo {
                staker_balance: info.staker_balance,
            }),
        )
    }
}

impl sighash::input_commitments::OrderInfoProvider for TxAdditionalInfo {
    type Error = std::convert::Infallible;

    fn get_order_info(
        &self,
        order_id: &OrderId,
    ) -> Result<Option<sighash::input_commitments::OrderInfo>, Self::Error> {
        Ok(
            self.order_info.get(order_id).map(|info| sighash::input_commitments::OrderInfo {
                initially_asked: info.initially_asked.clone(),
                initially_given: info.initially_given.clone(),
                ask_balance: info.ask_balance,
                give_balance: info.give_balance,
            }),
        )
    }
}
