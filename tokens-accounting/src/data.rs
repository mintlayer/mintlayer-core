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

use accounting::{DeltaAmountCollection, DeltaDataCollection, DeltaDataUndoCollection};
use common::{
    chain::{
        tokens::{TokenId, TokenIssuance, TokenTotalSupply},
        Destination,
    },
    primitives::Amount,
};
use serialization::{Decode, Encode};

use crate::Error;

#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq)]
pub struct TokensAccountingData {
    pub token_data: BTreeMap<TokenId, TokenData>,
    pub circulating_supply: BTreeMap<TokenId, Amount>,
}

impl TokensAccountingData {
    pub fn new() -> Self {
        Self {
            token_data: BTreeMap::new(),
            circulating_supply: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq)]
pub struct TokensAccountingDeltaData {
    pub(crate) token_data: DeltaDataCollection<TokenId, TokenData>,
    pub(crate) circulating_supply: DeltaAmountCollection<TokenId>,
}

impl TokensAccountingDeltaData {
    pub fn new() -> Self {
        Self {
            token_data: DeltaDataCollection::new(),
            circulating_supply: DeltaAmountCollection::new(),
        }
    }

    pub fn merge_with_delta(
        &mut self,
        other: TokensAccountingDeltaData,
    ) -> Result<TokensAccountingDeltaUndoData, Error> {
        let token_data_undo = self.token_data.merge_delta_data(other.token_data)?;

        let circulating_supply_undo = other.circulating_supply.clone();
        self.circulating_supply.merge_delta_amounts(other.circulating_supply)?;

        Ok(TokensAccountingDeltaUndoData {
            token_data: token_data_undo,
            circulating_supply: circulating_supply_undo,
        })
    }
}

#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq)]
pub struct TokensAccountingDeltaUndoData {
    pub(crate) token_data: DeltaDataUndoCollection<TokenId, TokenData>,
    pub(crate) circulating_supply: DeltaAmountCollection<TokenId>,
}

impl TokensAccountingDeltaUndoData {
    pub fn new() -> Self {
        Self {
            token_data: DeltaDataUndoCollection::new(),
            circulating_supply: DeltaAmountCollection::new(),
        }
    }
}

#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq)]
pub enum TokenData {
    FungibleToken(FungibleTokenData),
}

#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq)]
pub struct FungibleTokenData {
    token_ticker: Vec<u8>,
    number_of_decimals: u8,
    metadata_uri: Vec<u8>,
    total_supply: TokenTotalSupply,
    locked: bool,
    reissuance_controller: Destination,
}

impl FungibleTokenData {
    pub fn new_unchecked(
        token_ticker: Vec<u8>,
        number_of_decimals: u8,
        metadata_uri: Vec<u8>,
        total_supply: TokenTotalSupply,
        locked: bool,
        reissuance_controller: Destination,
    ) -> Self {
        Self {
            token_ticker,
            number_of_decimals,
            metadata_uri,
            total_supply,
            locked,
            reissuance_controller,
        }
    }

    pub fn token_ticker(&self) -> &[u8] {
        self.token_ticker.as_ref()
    }

    pub fn number_of_decimals(&self) -> u8 {
        self.number_of_decimals
    }

    pub fn metadata_uri(&self) -> &[u8] {
        self.metadata_uri.as_ref()
    }

    pub fn total_supply(&self) -> &TokenTotalSupply {
        &self.total_supply
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }

    pub fn reissuance_controller(&self) -> &Destination {
        &self.reissuance_controller
    }

    pub fn try_lock(self) -> Result<Self, Self> {
        match self.total_supply {
            TokenTotalSupply::Fixed(_) | TokenTotalSupply::Unlimited => Err(self),
            TokenTotalSupply::Lockable => Ok(Self {
                token_ticker: self.token_ticker,
                number_of_decimals: self.number_of_decimals,
                metadata_uri: self.metadata_uri,
                total_supply: self.total_supply,
                locked: true,
                reissuance_controller: self.reissuance_controller,
            }),
        }
    }
}

impl From<TokenIssuance> for FungibleTokenData {
    fn from(issuance: TokenIssuance) -> Self {
        match issuance {
            TokenIssuance::V1(issuance) => Self {
                token_ticker: issuance.token_ticker,
                number_of_decimals: issuance.number_of_decimals,
                metadata_uri: issuance.metadata_uri,
                total_supply: issuance.total_supply,
                locked: false,
                reissuance_controller: issuance.reissuance_controller,
            },
        }
    }
}
