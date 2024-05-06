// Copyright (c) 2023 RBB S.r.l
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

use common::{chain::tokens::TokenId, primitives::Amount};

use crate::TokenData;

use super::{TokensAccountingStorageRead, TokensAccountingStorageWrite};

#[must_use]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct InMemoryTokensAccounting {
    tokens_data: BTreeMap<TokenId, TokenData>,
    circulating_supply: BTreeMap<TokenId, Amount>,
}

impl InMemoryTokensAccounting {
    pub fn new() -> Self {
        Self {
            tokens_data: Default::default(),
            circulating_supply: Default::default(),
        }
    }

    pub fn from_values(
        tokens_data: BTreeMap<TokenId, TokenData>,
        circulating_supply: BTreeMap<TokenId, Amount>,
    ) -> Self {
        Self {
            tokens_data,
            circulating_supply,
        }
    }

    pub fn tokens_data(&self) -> &BTreeMap<TokenId, TokenData> {
        &self.tokens_data
    }

    pub fn circulating_supply(&self) -> &BTreeMap<TokenId, Amount> {
        &self.circulating_supply
    }
}

impl TokensAccountingStorageRead for InMemoryTokensAccounting {
    type Error = chainstate_types::storage_result::Error;

    fn get_token_data(&self, id: &TokenId) -> Result<Option<TokenData>, Self::Error> {
        Ok(self.tokens_data.get(id).cloned())
    }

    fn get_circulating_supply(&self, id: &TokenId) -> Result<Option<Amount>, Self::Error> {
        Ok(self.circulating_supply.get(id).cloned())
    }
}

impl TokensAccountingStorageWrite for InMemoryTokensAccounting {
    fn set_token_data(&mut self, id: &TokenId, data: &crate::TokenData) -> Result<(), Self::Error> {
        self.tokens_data.insert(*id, data.clone());
        Ok(())
    }

    fn del_token_data(&mut self, id: &TokenId) -> Result<(), Self::Error> {
        self.tokens_data.remove(id);
        Ok(())
    }

    fn set_circulating_supply(&mut self, id: &TokenId, supply: &Amount) -> Result<(), Self::Error> {
        self.circulating_supply.insert(*id, *supply);
        Ok(())
    }

    fn del_circulating_supply(&mut self, id: &TokenId) -> Result<(), Self::Error> {
        self.circulating_supply.remove(id);
        Ok(())
    }
}
