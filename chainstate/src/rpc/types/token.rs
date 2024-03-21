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

use common::{
    address::{AddressError, RpcAddress},
    chain::{
        tokens::{IsTokenFreezable, NftIssuance, TokenIssuance, TokenTotalSupply},
        ChainConfig, Destination,
    },
    primitives::amount::RpcAmountOut,
};
use serialization::extras::non_empty_vec::DataOrNoVec;

#[derive(Debug, Clone, serde::Serialize)]
pub enum RpcTokenTotalSupply {
    Fixed(RpcAmountOut),
    Lockable,
    Unlimited,
}

impl RpcTokenTotalSupply {
    pub fn new(chain_config: &ChainConfig, supply: TokenTotalSupply) -> Result<Self, AddressError> {
        let result = match supply {
            TokenTotalSupply::Fixed(amount) => RpcTokenTotalSupply::Fixed(
                RpcAmountOut::from_amount(amount, chain_config.coin_decimals()),
            ),
            TokenTotalSupply::Lockable => RpcTokenTotalSupply::Lockable,
            TokenTotalSupply::Unlimited => RpcTokenTotalSupply::Unlimited,
        };
        Ok(result)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub enum RpcIsTokenFreezable {
    No,
    Yes,
}

impl From<IsTokenFreezable> for RpcIsTokenFreezable {
    fn from(value: IsTokenFreezable) -> Self {
        match value {
            IsTokenFreezable::No => RpcIsTokenFreezable::No,
            IsTokenFreezable::Yes => RpcIsTokenFreezable::Yes,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RpcTokenIssuance {
    pub token_ticker: Vec<u8>,
    pub number_of_decimals: u8,
    pub metadata_uri: Vec<u8>,
    pub total_supply: RpcTokenTotalSupply,
    pub authority: RpcAddress<Destination>,
    pub is_freezable: RpcIsTokenFreezable,
}

impl RpcTokenIssuance {
    pub fn new(chain_config: &ChainConfig, issuance: &TokenIssuance) -> Result<Self, AddressError> {
        let result = match issuance {
            TokenIssuance::V1(issuance) => Self {
                token_ticker: issuance.token_ticker.clone(),
                number_of_decimals: issuance.number_of_decimals,
                metadata_uri: issuance.metadata_uri.clone(),
                total_supply: RpcTokenTotalSupply::new(chain_config, issuance.total_supply)?,
                authority: RpcAddress::new(chain_config, issuance.authority.clone())?,
                is_freezable: issuance.is_freezable.into(),
            },
        };

        Ok(result)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RpcNftIssuance {
    pub metadata: RpcNftMetadata,
}

impl RpcNftIssuance {
    pub fn new(chain_config: &ChainConfig, issuance: &NftIssuance) -> Result<Self, AddressError> {
        let result = match issuance {
            NftIssuance::V0(issuance) => Self {
                metadata: RpcNftMetadata::new(chain_config, &issuance.metadata)?,
            },
        };
        Ok(result)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RpcNftMetadata {
    pub creator: Option<RpcAddress<Destination>>,
    pub name: Vec<u8>,
    pub description: Vec<u8>,
    pub ticker: Vec<u8>,
    pub icon_uri: DataOrNoVec<u8>,
    pub additional_metadata_uri: DataOrNoVec<u8>,
    pub media_uri: DataOrNoVec<u8>,
    pub media_hash: Vec<u8>,
}

impl RpcNftMetadata {
    fn new(
        chain_config: &ChainConfig,
        metadata: &common::chain::tokens::Metadata,
    ) -> Result<Self, AddressError> {
        let result = Self {
            creator: metadata
                .creator
                .clone()
                .map(|c| RpcAddress::new(chain_config, Destination::PublicKey(c.public_key)))
                .transpose()?,
            name: metadata.name.clone(),
            description: metadata.description.clone(),
            ticker: metadata.ticker.clone(),
            icon_uri: metadata.icon_uri.clone(),
            additional_metadata_uri: metadata.additional_metadata_uri.clone(),
            media_uri: metadata.media_uri.clone(),
            media_hash: metadata.media_hash.clone(),
        };
        Ok(result)
    }
}
