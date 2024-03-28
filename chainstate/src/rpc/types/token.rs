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
use rpc::types::{RpcHexString, RpcString};

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type")]
pub enum RpcTokenTotalSupply {
    Fixed { amount: RpcAmountOut },
    Lockable,
    Unlimited,
}

impl RpcTokenTotalSupply {
    pub fn new(chain_config: &ChainConfig, supply: TokenTotalSupply) -> Result<Self, AddressError> {
        let result = match supply {
            TokenTotalSupply::Fixed(amount) => RpcTokenTotalSupply::Fixed {
                amount: RpcAmountOut::from_amount(amount, chain_config.coin_decimals()),
            },
            TokenTotalSupply::Lockable => RpcTokenTotalSupply::Lockable,
            TokenTotalSupply::Unlimited => RpcTokenTotalSupply::Unlimited,
        };
        Ok(result)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RpcTokenIssuance {
    pub token_ticker: RpcString,
    pub number_of_decimals: u8,
    pub metadata_uri: RpcString,
    pub total_supply: RpcTokenTotalSupply,
    pub authority: RpcAddress<Destination>,
    pub is_freezable: bool,
}

impl RpcTokenIssuance {
    pub fn new(chain_config: &ChainConfig, issuance: &TokenIssuance) -> Result<Self, AddressError> {
        let result = match issuance {
            TokenIssuance::V1(issuance) => Self {
                token_ticker: RpcString::from_bytes(issuance.token_ticker.clone()),
                number_of_decimals: issuance.number_of_decimals,
                metadata_uri: RpcString::from_bytes(issuance.metadata_uri.clone()),
                total_supply: RpcTokenTotalSupply::new(chain_config, issuance.total_supply)?,
                authority: RpcAddress::new(chain_config, issuance.authority.clone())?,
                is_freezable: match issuance.is_freezable {
                    IsTokenFreezable::No => false,
                    IsTokenFreezable::Yes => true,
                },
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
    pub name: RpcString,
    pub description: RpcString,
    pub ticker: RpcString,
    pub icon_uri: Option<RpcString>,
    pub additional_metadata_uri: Option<RpcString>,
    pub media_uri: Option<RpcString>,
    pub media_hash: RpcHexString,
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
            name: RpcString::from_bytes(metadata.name.clone()),
            description: RpcString::from_bytes(metadata.description.clone()),
            ticker: RpcString::from_bytes(metadata.ticker.clone()),
            icon_uri: metadata.icon_uri.as_opt_slice().map(|d| RpcString::from_bytes(d.to_owned())),
            additional_metadata_uri: metadata
                .additional_metadata_uri
                .as_opt_slice()
                .map(|d| RpcString::from_bytes(d.to_owned())),
            media_uri: metadata
                .media_uri
                .as_opt_slice()
                .map(|d| RpcString::from_bytes(d.to_owned())),
            media_hash: RpcHexString::from_bytes(metadata.media_hash.clone()),
        };
        Ok(result)
    }
}
