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
        ChainConfig, DelegationId, Destination, PoolId, SignedTransaction, Transaction, TxOutput,
        UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, Id, Idable},
};
use crypto::{
    key::{
        hdkd::{child_number::ChildNumber, u31::U31},
        PublicKey,
    },
    vrf::VRFPublicKey,
};
use rpc::description::{HasValueHint, ValueHint as VH};
use serialization::hex::HexEncode;
use wallet::account::PoolData;

pub use common::primitives::amount::{RpcAmountIn, RpcAmountOut};
pub use mempool_types::tx_options::TxOptionsOverrides;
pub use rpc::types::RpcStringIn;
pub use serde_json::Value as JsonValue;
pub use serialization::hex_encoded::HexEncoded;
pub use wallet_controller::types::{
    Balances, BlockInfo, InspectTransaction, SignatureStats, ValidatedSignatures,
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

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct AccountArg(pub u32);

impl AccountArg {
    pub fn index<N: NodeInterface>(&self) -> Result<U31, RpcError<N>> {
        U31::from_u32(self.0).ok_or(RpcError::AcctIndexOutOfRange)
    }
}

impl From<U31> for AccountArg {
    fn from(idx: U31) -> Self {
        Self(idx.into())
    }
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
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

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
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

impl rpc::description::HasValueHint for PublicKeyInfo {
    const HINT_SER: VH = VH::Object(&[
        ("public_key_hex", &VH::HEX_STRING),
        ("public_key_address", &VH::BECH32_STRING),
    ]);
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub struct LegacyVrfPublicKeyInfo {
    pub vrf_public_key: String,
}

impl rpc::description::HasValueHint for LegacyVrfPublicKeyInfo {
    const HINT_SER: VH = VH::Object(&[("vrf_public_key", &VH::STRING)]);
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

impl rpc::description::HasValueHint for VrfPublicKeyInfo {
    const HINT_SER: VH = VH::Object(&[
        ("vrf_public_key", &VH::HEX_STRING),
        ("child_number", &u32::HINT_SER),
        ("used", &bool::HINT_SER),
    ]);
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct UtxoInfo {
    pub outpoint: UtxoOutPoint,
    pub output: TxOutput,
}

impl rpc::description::HasValueHint for UtxoInfo {
    const HINT_SER: VH =
        VH::Object(&[("outpoint", &UtxoOutPoint::HINT_SER), ("output", &VH::GENERIC_OBJECT)]);
}

impl UtxoInfo {
    pub fn from_tuple((outpoint, output): (UtxoOutPoint, TxOutput)) -> Self {
        Self { outpoint, output }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct TransactionOptions {
    pub in_top_x_mb: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct PoolInfo {
    pub pool_id: String,
    pub pledge: RpcAmountOut,
    pub balance: RpcAmountOut,
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
        let balance = RpcAmountOut::from_amount_no_padding(balance, decimals);
        let pledge = RpcAmountOut::from_amount_no_padding(pledge, decimals);

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

impl rpc::description::HasValueHint for NewDelegation {
    const HINT_SER: VH = VH::Object(&[
        ("tx_id", &<Id<Transaction>>::HINT_SER),
        ("delegation_id", &VH::BECH32_STRING),
    ]);
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DelegationInfo {
    pub delegation_id: String,
    pub balance: RpcAmountOut,
}

impl rpc::description::HasValueHint for DelegationInfo {
    const HINT_SER: VH =
        VH::Object(&[("delegation_id", &VH::BECH32_STRING), ("balance", &RpcAmountOut::HINT_SER)]);
    const HINT_DE: VH =
        VH::Object(&[("delegation_id", &VH::BECH32_STRING), ("balance", &RpcAmountOut::HINT_DE)]);
}

impl DelegationInfo {
    pub fn new(delegation_id: DelegationId, balance: Amount, chain_config: &ChainConfig) -> Self {
        let decimals = chain_config.coin_decimals();
        let balance = RpcAmountOut::from_amount_no_padding(balance, decimals);

        Self {
            delegation_id: Address::new(chain_config, &delegation_id)
                .expect("addressable")
                .get()
                .to_owned(),
            balance,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct NftMetadata {
    pub media_hash: String,
    pub name: RpcStringIn,
    pub description: RpcStringIn,
    pub ticker: String,
    pub creator: Option<HexEncoded<PublicKey>>,
    pub icon_uri: Option<RpcStringIn>,
    pub media_uri: Option<RpcStringIn>,
    pub additional_metadata_uri: Option<RpcStringIn>,
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub enum TokenTotalSupply {
    Fixed(RpcAmountIn),
    Lockable,
    Unlimited,
}

impl TokenTotalSupply {
    fn to_token_supply(&self, decimals: u8) -> Option<tokens::TokenTotalSupply> {
        match self {
            Self::Lockable => Some(tokens::TokenTotalSupply::Lockable),
            Self::Unlimited => Some(tokens::TokenTotalSupply::Unlimited),
            Self::Fixed(amount) => amount.to_amount(decimals).map(tokens::TokenTotalSupply::Fixed),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct TokenMetadata {
    pub token_ticker: RpcStringIn,
    pub number_of_decimals: u8,
    pub metadata_uri: RpcStringIn,
    pub token_supply: TokenTotalSupply,
    pub is_freezable: bool,
}

impl TokenMetadata {
    pub fn token_supply<N: NodeInterface>(&self) -> Result<tokens::TokenTotalSupply, RpcError<N>> {
        self.token_supply
            .to_token_supply(self.number_of_decimals)
            .ok_or(RpcError::InvalidCoinAmount)
    }

    pub fn is_freezable(&self) -> IsTokenFreezable {
        if self.is_freezable {
            IsTokenFreezable::Yes
        } else {
            IsTokenFreezable::No
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct StakePoolBalance {
    pub balance: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RpcTokenId {
    pub token_id: String,
    pub tx_id: Id<Transaction>,
}

impl rpc::description::HasValueHint for RpcTokenId {
    const HINT_SER: VH =
        VH::Object(&[("token_id", &VH::BECH32_STRING), ("tx_id", &VH::HEX_STRING)]);
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct NewTransaction {
    pub tx_id: Id<Transaction>,
}

impl NewTransaction {
    pub fn new(tx: SignedTransaction) -> Self {
        Self {
            tx_id: tx.transaction().get_id(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct NodeVersion {
    pub version: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub enum CreatedWallet {
    UserProvidedMnemonic,
    NewlyGeneratedMnemonic(String, Option<String>),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct ComposedTransaction {
    pub hex: String,
    pub fees: Balances,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct MaybeSignedTransaction {
    pub hex: String,
    pub is_complete: bool,
}
