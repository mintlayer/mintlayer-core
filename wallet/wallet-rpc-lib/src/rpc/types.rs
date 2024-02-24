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

//! Types supporting the RPC interface

use common::{
    address::Address,
    chain::{
        block::timestamp::BlockTimestamp,
        signature::DestinationSigError,
        tokens::{self, IsTokenFreezable, Metadata, TokenCreator},
        ChainConfig, DelegationId, Destination, PoolId, Transaction, TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, Id},
};
use crypto::{
    key::{
        hdkd::{child_number::ChildNumber, u31::U31},
        PublicKey,
    },
    vrf::VRFPublicKey,
};
use serialization::hex::HexEncode;

pub use mempool_types::tx_options::TxOptionsOverrides;
pub use serde_json::Value as JsonValue;
pub use serialization::hex_encoded::HexEncoded;
use wallet::account::PoolData;
pub use wallet_controller::types::{
    Balances, BlockInfo, DecimalAmount, InsepectTransaction, SignatureStats, ValidatedSignatures,
};
pub use wallet_controller::{ControllerConfig, NodeInterface};

use crate::service::SubmitError;

#[derive(Debug, thiserror::Error)]
pub enum RpcError<N: NodeInterface> {
    #[error("Account index out of supported range")]
    AcctIndexOutOfRange,

    #[error("Invalid coin amount")]
    InvalidCoinAmount,

    #[error("Invalid address")]
    InvalidAddress,

    #[error("Failed to parse margin_ratio_per_thousand. The decimal must be in the range [0.001,1.000] or [0.1%,100%]")]
    InvalidMarginRatio,

    #[error("Invalid pool ID")]
    InvalidPoolId,

    #[error("Invalid delegation ID")]
    InvalidDelegationId,

    #[error("Invalid token ID")]
    InvalidTokenId,

    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(wallet_controller::mnemonic::Error),

    #[error("Invalid ip address")]
    InvalidIpAddress,

    #[error("Invalid block ID")]
    InvalidBlockId,

    #[error("Wallet error: {0}")]
    Controller(#[from] wallet_controller::ControllerError<N>),

    #[error("RPC error: {0}")]
    RpcError(N::Error),

    #[error("No wallet opened")]
    NoWalletOpened,

    #[error("{0}")]
    SubmitError(#[from] SubmitError),

    #[error("Invalid hex encoded transaction")]
    InvalidRawTransaction,

    #[error("Invalid hex encoded partially signed transaction")]
    InvalidPartialTransaction,

    #[error("{0}")]
    DestinationSigError(#[from] DestinationSigError),

    #[error("Invalid hex data deposit")]
    InvalidHexData,
}

impl<N: NodeInterface> From<RpcError<N>> for rpc::Error {
    fn from(e: RpcError<N>) -> Self {
        Self::owned::<()>(-1, e.to_string(), None)
    }
}

/// Struct representing empty arguments to RPC call, for forwards compatibility
#[derive(Debug, Eq, PartialEq, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct EmptyArgs {}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub struct AccountIndexArg {
    pub account: u32,
}

impl AccountIndexArg {
    pub fn index<N: NodeInterface>(&self) -> Result<U31, RpcError<N>> {
        U31::from_u32(self.account).ok_or(RpcError::AcctIndexOutOfRange)
    }
}

impl From<U31> for AccountIndexArg {
    fn from(value: U31) -> Self {
        Self {
            account: value.into_u32(),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub struct AddressInfo {
    pub address: String,
    pub index: String,
}

impl AddressInfo {
    pub fn new(child_number: ChildNumber, address: Address<Destination>) -> Self {
        Self {
            address: address.to_string(),
            index: child_number.to_string(),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub struct AddressWithUsageInfo {
    pub address: String,
    pub index: String,
    pub used: bool,
}

impl AddressWithUsageInfo {
    pub fn new(child_number: ChildNumber, address: Address<Destination>, used: bool) -> Self {
        Self {
            address: address.to_string(),
            index: child_number.to_string(),
            used,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub struct PublicKeyInfo {
    pub public_key_hex: String,
    pub public_key_address: String,
}

impl PublicKeyInfo {
    pub fn new(pub_key: PublicKey, chain_config: &ChainConfig) -> Self {
        Self {
            public_key_hex: pub_key.hex_encode(),
            public_key_address: Address::new(chain_config, &Destination::PublicKey(pub_key))
                .expect("addressable")
                .to_string(),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub struct LegacyVrfPublicKeyInfo {
    pub vrf_public_key: String,
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub struct VrfPublicKeyInfo {
    pub vrf_public_key: String,
    pub child_number: u32,
    pub used: bool,
}

impl VrfPublicKeyInfo {
    pub fn new(pub_key: Address<VRFPublicKey>, child_number: ChildNumber, used: bool) -> Self {
        Self {
            vrf_public_key: pub_key.to_string(),
            child_number: child_number.get_index().into_u32(),
            used,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct UtxoInfo {
    pub outpoint: UtxoOutPoint,
    pub output: TxOutput,
}

impl UtxoInfo {
    pub fn from_tuple((outpoint, output): (UtxoOutPoint, TxOutput)) -> Self {
        Self { outpoint, output }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NewAccountInfo {
    pub account: u32,
    pub name: Option<String>,
}

impl NewAccountInfo {
    pub fn new(account: U31, name: Option<String>) -> Self {
        let account = account.into_u32();
        Self { account, name }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TransactionOptions {
    pub in_top_x_mb: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PoolInfo {
    pub pool_id: String,
    pub pledge: DecimalAmount,
    pub balance: DecimalAmount,
    pub height: BlockHeight,
    pub block_timestamp: BlockTimestamp,
    pub vrf_public_key: String,
    pub decommission_key: String,
    pub staker: String,
}

impl PoolInfo {
    pub fn new(
        pool_id: PoolId,
        pool_data: PoolData,
        balance: Amount,
        pledge: Amount,
        chain_config: &ChainConfig,
    ) -> Self {
        let decimals = chain_config.coin_decimals();
        let balance = DecimalAmount::from_amount_minimal(balance, decimals);
        let pledge = DecimalAmount::from_amount_minimal(pledge, decimals);

        Self {
            pool_id: Address::new(chain_config, &pool_id).expect("addressable").to_string(),
            balance,
            pledge,
            height: pool_data.creation_block.height,
            block_timestamp: pool_data.creation_block.timestamp,
            vrf_public_key: Address::new(chain_config, &pool_data.vrf_public_key)
                .expect("addressable")
                .to_string(),
            decommission_key: Address::new(chain_config, &pool_data.decommission_key)
                .expect("addressable")
                .to_string(),
            staker: Address::new(chain_config, &pool_data.stake_destination)
                .expect("addressable")
                .to_string(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NewDelegation {
    pub tx_id: Id<Transaction>,
    pub delegation_id: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DelegationInfo {
    pub delegation_id: String,
    pub balance: DecimalAmount,
}

impl DelegationInfo {
    pub fn new(delegation_id: DelegationId, balance: Amount, chain_config: &ChainConfig) -> Self {
        let decimals = chain_config.coin_decimals();
        let balance = DecimalAmount::from_amount_minimal(balance, decimals);

        Self {
            delegation_id: Address::new(chain_config, &delegation_id)
                .expect("addressable")
                .get()
                .to_owned(),
            balance,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NftMetadata {
    pub media_hash: String,
    pub name: String,
    pub description: String,
    pub ticker: String,
    pub creator: Option<HexEncoded<PublicKey>>,
    pub icon_uri: Option<String>,
    pub media_uri: Option<String>,
    pub additional_metadata_uri: Option<String>,
}

impl NftMetadata {
    pub fn into_metadata(self) -> Metadata {
        Metadata {
            creator: self.creator.map(|pk| TokenCreator {
                public_key: pk.take(),
            }),
            name: self.name.into_bytes(),
            description: self.description.into_bytes(),
            ticker: self.ticker.into_bytes(),
            icon_uri: self.icon_uri.map(|x| x.into_bytes()).into(),
            additional_metadata_uri: self.additional_metadata_uri.map(|x| x.into_bytes()).into(),
            media_uri: self.media_uri.map(|x| x.into_bytes()).into(),
            media_hash: self.media_hash.into_bytes(),
        }
    }
}

#[derive(Debug, Copy, Clone, serde::Serialize, serde::Deserialize)]
pub enum TokenTotalSupply {
    Fixed(DecimalAmount),
    Lockable,
    Unlimited,
}

impl TokenTotalSupply {
    fn into_token_supply<N: NodeInterface>(
        self,
        chain_config: &ChainConfig,
    ) -> Result<tokens::TokenTotalSupply, RpcError<N>> {
        match self {
            Self::Lockable => Ok(tokens::TokenTotalSupply::Lockable),
            Self::Unlimited => Ok(tokens::TokenTotalSupply::Unlimited),
            Self::Fixed(amount) => {
                let decimals = chain_config.coin_decimals();
                let amount = amount.to_amount(decimals).ok_or(RpcError::InvalidCoinAmount)?;
                Ok(tokens::TokenTotalSupply::Fixed(amount))
            }
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TokenMetadata {
    pub token_ticker: String,
    pub number_of_decimals: u8,
    pub metadata_uri: String,
    pub token_supply: TokenTotalSupply,
    pub is_freezable: bool,
}

impl TokenMetadata {
    pub fn token_supply<N: NodeInterface>(
        &self,
        chain_config: &ChainConfig,
    ) -> Result<tokens::TokenTotalSupply, RpcError<N>> {
        self.token_supply.into_token_supply(chain_config)
    }

    pub fn is_freezable(&self) -> IsTokenFreezable {
        if self.is_freezable {
            IsTokenFreezable::Yes
        } else {
            IsTokenFreezable::No
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StakePoolBalance {
    pub balance: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RpcTokenId {
    pub token_id: String,
    pub tx_id: Id<Transaction>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NewTransaction {
    pub tx_id: Id<Transaction>,
}

impl NewTransaction {
    pub fn new(tx_id: Id<Transaction>) -> Self {
        Self { tx_id }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NodeVersion {
    pub version: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum StakingStatus {
    Staking,
    NotStaking,
}

impl StakingStatus {
    pub fn new(is_staking: bool) -> Self {
        if is_staking {
            Self::Staking
        } else {
            Self::NotStaking
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum CreatedWallet {
    UserProvidedMenmonic,
    NewlyGeneratedMnemonic(String, Option<String>),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComposedTransaction {
    pub hex: String,
    pub fees: Balances,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MaybeSignedTransaction {
    pub hex: String,
    pub is_complete: bool,
}
