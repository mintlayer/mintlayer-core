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

use super::super::*;
use crate::translate::InputInfo;

use common::chain::{OrderData, OrderId};
use pos_accounting::{DelegationData, PoolData};
use tokens_accounting::TokenData;

use std::collections::BTreeMap;

pub struct MockSigInfoProvider<'a> {
    input_info: InputInfo<'a>,
    witness: InputWitness,
    tokens: BTreeMap<TokenId, TokenData>,
    pools: BTreeMap<PoolId, PoolData>,
    delegations: BTreeMap<DelegationId, DelegationData>,
    orders: BTreeMap<OrderId, OrderData>,
}

impl<'a> MockSigInfoProvider<'a> {
    pub fn new(
        input_info: InputInfo<'a>,
        witness: InputWitness,
        tokens: impl IntoIterator<Item = (TokenId, TokenData)>,
        pools: impl IntoIterator<Item = (PoolId, PoolData)>,
        delegations: impl IntoIterator<Item = (DelegationId, DelegationData)>,
        orders: impl IntoIterator<Item = (OrderId, OrderData)>,
    ) -> Self {
        Self {
            input_info,
            witness,
            tokens: tokens.into_iter().collect(),
            pools: pools.into_iter().collect(),
            delegations: delegations.into_iter().collect(),
            orders: orders.into_iter().collect(),
        }
    }
}

impl crate::translate::InputInfoProvider for MockSigInfoProvider<'_> {
    fn input_info(&self) -> &InputInfo<'_> {
        &self.input_info
    }

    fn witness(&self) -> &InputWitness {
        &self.witness
    }
}

impl crate::translate::SignatureInfoProvider for MockSigInfoProvider<'_> {
    fn get_pool_decommission_destination(
        &self,
        pool_id: &PoolId,
    ) -> Result<Option<Destination>, pos_accounting::Error> {
        Ok(self.pools.get(pool_id).map(|pool| pool.decommission_destination().clone()))
    }

    fn get_delegation_spend_destination(
        &self,
        delegation_id: &DelegationId,
    ) -> Result<Option<Destination>, pos_accounting::Error> {
        Ok(self
            .delegations
            .get(delegation_id)
            .map(|delegation| delegation.spend_destination().clone()))
    }

    fn get_tokens_authority(
        &self,
        token_id: &TokenId,
    ) -> Result<Option<Destination>, tokens_accounting::Error> {
        Ok(self.tokens.get(token_id).map(|token| match token {
            TokenData::FungibleToken(data) => data.authority().clone(),
        }))
    }

    fn get_orders_conclude_destination(
        &self,
        order_id: &OrderId,
    ) -> Result<Option<Destination>, orders_accounting::Error> {
        Ok(self.orders.get(order_id).map(|data| data.conclude_key().clone()))
    }
}
