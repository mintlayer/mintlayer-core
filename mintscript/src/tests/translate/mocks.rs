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

use pos_accounting::{DelegationData, PoolData};
use tokens_accounting::TokenData;

use std::collections::BTreeMap;

pub struct MockSigInfoProvider<'a> {
    input_info: InputInfo<'a>,
    witness: InputWitness,
    tokens: BTreeMap<TokenId, TokenData>,
    pools: BTreeMap<PoolId, PoolData>,
    delegations: BTreeMap<DelegationId, DelegationData>,
}

impl<'a> MockSigInfoProvider<'a> {
    pub fn new(
        input_info: InputInfo<'a>,
        witness: InputWitness,
        tokens: impl IntoIterator<Item = (TokenId, TokenData)>,
        pools: impl IntoIterator<Item = (PoolId, PoolData)>,
        delegations: impl IntoIterator<Item = (DelegationId, DelegationData)>,
    ) -> Self {
        Self {
            input_info,
            witness,
            tokens: tokens.into_iter().collect(),
            pools: pools.into_iter().collect(),
            delegations: delegations.into_iter().collect(),
        }
    }
}

impl crate::translate::InputInfoProvider for MockSigInfoProvider<'_> {
    fn input_info(&self) -> &InputInfo {
        &self.input_info
    }

    fn witness(&self) -> &InputWitness {
        &self.witness
    }
}

impl crate::translate::SignatureInfoProvider for MockSigInfoProvider<'_> {
    type PoSAccounting = Self;
    type Tokens = Self;

    fn pos_accounting(&self) -> &Self::PoSAccounting {
        self
    }

    fn tokens(&self) -> &Self::Tokens {
        self
    }
}

impl pos_accounting::PoSAccountingView for MockSigInfoProvider<'_> {
    type Error = pos_accounting::Error;

    fn pool_exists(&self, id: PoolId) -> Result<bool, Self::Error> {
        Ok(self.pools.contains_key(&id))
    }

    fn get_pool_balance(&self, _id: PoolId) -> Result<Option<Amount>, Self::Error> {
        unreachable!("not used in these tests")
    }

    fn get_pool_data(&self, id: PoolId) -> Result<Option<PoolData>, Self::Error> {
        Ok(self.pools.get(&id).cloned())
    }

    fn get_pool_delegations_shares(
        &self,
        _id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, Self::Error> {
        unreachable!("not used in these tests")
    }

    fn get_delegation_balance(&self, _id: DelegationId) -> Result<Option<Amount>, Self::Error> {
        unreachable!("not used in these tests")
    }

    fn get_delegation_data(&self, id: DelegationId) -> Result<Option<DelegationData>, Self::Error> {
        Ok(self.delegations.get(&id).cloned())
    }

    fn get_pool_delegation_share(
        &self,
        _pid: PoolId,
        _did: DelegationId,
    ) -> Result<Option<Amount>, Self::Error> {
        unreachable!("not used in these tests")
    }
}

impl tokens_accounting::TokensAccountingView for MockSigInfoProvider<'_> {
    type Error = tokens_accounting::Error;

    fn get_token_data(&self, id: &TokenId) -> Result<Option<TokenData>, Self::Error> {
        Ok(self.tokens.get(id).cloned())
    }

    fn get_circulating_supply(&self, _id: &TokenId) -> Result<Option<Amount>, Self::Error> {
        unreachable!("not used in these tests")
    }
}
