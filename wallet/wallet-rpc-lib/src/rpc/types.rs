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

use chainstate::rpc::{RpcTxOutput, RpcUtxoOutpoint};
use common::{
    address::{pubkeyhash::PublicKeyHash, Address, AddressError},
    chain::{
        block::timestamp::BlockTimestamp,
        classic_multisig::ClassicMultisigChallengeError,
        signature::DestinationSigError,
        tokens::{self, IsTokenFreezable, Metadata, TokenCreator, TokenId},
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
use rpc::description::HasValueHint;
use rpc_description::ValueHint;
use wallet::account::PoolData;

pub use common::{
    address::RpcAddress,
    primitives::amount::{RpcAmountIn, RpcAmountOut},
};
pub use mempool_types::tx_options::TxOptionsOverrides;
pub use rpc::types::{RpcHexString, RpcString};
pub use serde_json::Value as JsonValue;
pub use serialization::hex_encoded::HexEncoded;
pub use wallet_controller::types::{
    Balances, BlockInfo, InspectTransaction, SignatureStats, ValidatedSignatures,
};
pub use wallet_controller::{ControllerConfig, NodeInterface};
use wallet_controller::{UtxoState, UtxoType};

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

    #[error("Can't compose a transaction without any inputs")]
    ComposeTransactionEmptyInputs,

    #[error("Provided address to create a Multisig address at index {0} is not a valid public key. Only public keys can be used.")]
    MultisigNotPublicKey(usize),

    #[error("Invalid multisig: {0}")]
    InvalidMultisigChallenge(#[from] ClassicMultisigChallengeError),

    #[error("Minimum number of signatures can't be 0")]
    InvalidMultisigMinSignature,
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

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum RpcStandaloneAddressDetails {
    WatchOnly,
    FromPrivateKey,
    Multisig {
        min_required_signatures: u8,
        public_keys: Vec<RpcAddress<Destination>>,
    },
}

impl HasValueHint for RpcStandaloneAddressDetails {
    const HINT_SER: ValueHint = ValueHint::Choice(&[
        &ValueHint::object(&[("type", &ValueHint::StrLit("WatchOnly"))]),
        &ValueHint::object(&[("type", &ValueHint::StrLit("FromPrivateKey"))]),
        &ValueHint::object(&[
            ("type", &ValueHint::StrLit("Multisig")),
            (
                "content",
                &ValueHint::object(&[
                    ("min_required_signatures", &u8::HINT_SER),
                    ("public_keys", &Vec::<RpcAddress<Destination>>::HINT_SER),
                ]),
            ),
        ]),
    ]);
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct StandaloneAddressWithDetails {
    pub address: String,
    pub label: Option<String>,
    pub details: RpcStandaloneAddressDetails,
    pub balances: Balances,
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct RpcStandaloneAddresses {
    pub watch_only_addresses: Vec<RpcStandaloneAddress>,
    pub multisig_addresses: Vec<RpcStandaloneAddress>,
    pub private_key_addresses: Vec<RpcStandalonePrivateKeyAddress>,
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct RpcStandaloneAddress {
    pub address: RpcAddress<Destination>,
    pub label: Option<String>,
}

impl RpcStandaloneAddress {
    pub fn new(dest: Destination, label: Option<String>, chain_config: &ChainConfig) -> Self {
        Self {
            address: Address::new(chain_config, dest).expect("addressable").into(),
            label,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct RpcStandalonePrivateKeyAddress {
    pub public_key: RpcAddress<Destination>,
    pub public_key_hash: RpcAddress<Destination>,
    pub label: Option<String>,
}

impl RpcStandalonePrivateKeyAddress {
    pub fn new(
        public_key: PublicKey,
        public_key_hash: PublicKeyHash,
        label: Option<String>,
        chain_config: &ChainConfig,
    ) -> Self {
        Self {
            public_key: Address::new(chain_config, Destination::PublicKey(public_key))
                .expect("addressable")
                .into(),
            public_key_hash: Address::new(
                chain_config,
                Destination::PublicKeyHash(public_key_hash),
            )
            .expect("addressable")
            .into(),
            label,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct AddressWithUsageInfo {
    pub address: RpcAddress<Destination>,
    pub index: String,
    pub used: bool,
}

impl AddressWithUsageInfo {
    pub fn new(child_number: ChildNumber, address: Address<Destination>, used: bool) -> Self {
        Self {
            address: address.into(),
            index: child_number.to_string(),
            used,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct PublicKeyInfo {
    pub public_key_hex: PublicKey,
    pub public_key_address: RpcAddress<Destination>,
}

impl PublicKeyInfo {
    pub fn new(pub_key: PublicKey, chain_config: &ChainConfig) -> Self {
        let public_key_address =
            RpcAddress::new(chain_config, Destination::PublicKey(pub_key.clone()))
                .expect("addressable");
        Self {
            public_key_hex: pub_key,
            public_key_address,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct LegacyVrfPublicKeyInfo {
    pub vrf_public_key: String,
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct VrfPublicKeyInfo {
    pub vrf_public_key: RpcAddress<VRFPublicKey>,
    pub child_number: u32,
    pub used: bool,
}

impl VrfPublicKeyInfo {
    pub fn new(pub_key: Address<VRFPublicKey>, child_number: ChildNumber, used: bool) -> Self {
        Self {
            vrf_public_key: pub_key.into(),
            child_number: child_number.get_index().into_u32(),
            used,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct UtxoInfo {
    pub outpoint: RpcUtxoOutpoint,
    pub output: RpcTxOutput,
}

impl UtxoInfo {
    pub fn new(
        outpoint: UtxoOutPoint,
        output: TxOutput,
        chain_config: &ChainConfig,
    ) -> Result<Self, AddressError> {
        Ok(Self {
            output: RpcTxOutput::new(chain_config, output)?,
            outpoint: RpcUtxoOutpoint::new(outpoint),
        })
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
    pub in_top_x_mb: Option<usize>,
}

impl TransactionOptions {
    const DEFAULT_IN_TOP_X_MB: usize = 5;

    pub fn from_controller_config(config: &ControllerConfig) -> Self {
        let in_top_x_mb = Some(config.in_top_x_mb);
        Self { in_top_x_mb }
    }

    pub fn in_top_x_mb(&self) -> usize {
        self.in_top_x_mb.unwrap_or(Self::DEFAULT_IN_TOP_X_MB)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct PoolInfo {
    pub pool_id: RpcAddress<PoolId>,
    pub pledge: RpcAmountOut,
    pub balance: RpcAmountOut,
    pub height: BlockHeight,
    pub block_timestamp: BlockTimestamp,
    pub vrf_public_key: RpcAddress<VRFPublicKey>,
    pub decommission_key: RpcAddress<Destination>,
    pub staker: RpcAddress<Destination>,
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
            pool_id: RpcAddress::new(chain_config, pool_id).expect("addressable"),
            balance,
            pledge,
            height: pool_data.creation_block.height,
            block_timestamp: pool_data.creation_block.timestamp,
            vrf_public_key: RpcAddress::new(chain_config, pool_data.vrf_public_key)
                .expect("addressable"),
            decommission_key: RpcAddress::new(chain_config, pool_data.decommission_key)
                .expect("addressable"),
            staker: RpcAddress::new(chain_config, pool_data.stake_destination)
                .expect("addressable"),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct NewDelegation {
    pub tx_id: Id<Transaction>,
    pub delegation_id: RpcAddress<DelegationId>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct DelegationInfo {
    pub delegation_id: RpcAddress<DelegationId>,
    pub balance: RpcAmountOut,
}

impl DelegationInfo {
    pub fn new(delegation_id: DelegationId, balance: Amount, chain_config: &ChainConfig) -> Self {
        let decimals = chain_config.coin_decimals();
        let balance = RpcAmountOut::from_amount_no_padding(balance, decimals);

        Self {
            delegation_id: RpcAddress::new(chain_config, delegation_id).expect("addressable"),
            balance,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct NftMetadata {
    pub media_hash: String,
    pub name: RpcString,
    pub description: RpcString,
    pub ticker: String,
    pub creator: Option<HexEncoded<PublicKey>>,
    pub icon_uri: Option<RpcString>,
    pub media_uri: Option<RpcString>,
    pub additional_metadata_uri: Option<RpcString>,
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

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, HasValueHint)]
pub enum RpcUtxoType {
    Transfer,
    LockThenTransfer,
    IssueNft,
    CreateStakePool,
    ProduceBlockFromStake,
}

impl From<&RpcUtxoType> for UtxoType {
    fn from(value: &RpcUtxoType) -> Self {
        match value {
            RpcUtxoType::Transfer => UtxoType::Transfer,
            RpcUtxoType::LockThenTransfer => UtxoType::LockThenTransfer,
            RpcUtxoType::IssueNft => UtxoType::IssueNft,
            RpcUtxoType::CreateStakePool => UtxoType::CreateStakePool,
            RpcUtxoType::ProduceBlockFromStake => UtxoType::ProduceBlockFromStake,
        }
    }
}

impl From<&UtxoType> for RpcUtxoType {
    fn from(value: &UtxoType) -> Self {
        match value {
            UtxoType::Transfer => RpcUtxoType::Transfer,
            UtxoType::LockThenTransfer => RpcUtxoType::LockThenTransfer,
            UtxoType::IssueNft => RpcUtxoType::IssueNft,
            UtxoType::CreateStakePool => RpcUtxoType::CreateStakePool,
            UtxoType::ProduceBlockFromStake => RpcUtxoType::ProduceBlockFromStake,
        }
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, HasValueHint)]
pub enum RpcUtxoState {
    Confirmed,
    Conflicted,
    Inactive,
    Abandoned,
    InMempool,
}

impl From<&RpcUtxoState> for UtxoState {
    fn from(value: &RpcUtxoState) -> Self {
        match value {
            RpcUtxoState::Confirmed => UtxoState::Confirmed,
            RpcUtxoState::Inactive => UtxoState::Inactive,
            RpcUtxoState::Abandoned => UtxoState::Abandoned,
            RpcUtxoState::Conflicted => UtxoState::Conflicted,
            RpcUtxoState::InMempool => UtxoState::InMempool,
        }
    }
}

impl From<&UtxoState> for RpcUtxoState {
    fn from(value: &UtxoState) -> Self {
        match value {
            UtxoState::Confirmed => RpcUtxoState::Confirmed,
            UtxoState::Inactive => RpcUtxoState::Inactive,
            UtxoState::Abandoned => RpcUtxoState::Abandoned,
            UtxoState::Conflicted => RpcUtxoState::Conflicted,
            UtxoState::InMempool => RpcUtxoState::InMempool,
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
    pub token_ticker: RpcString,
    pub number_of_decimals: u8,
    pub metadata_uri: RpcString,
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct RpcTokenId {
    pub token_id: RpcAddress<TokenId>,
    pub tx_id: Id<Transaction>,
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn transaction_options_optional() {
        let empty_obj = serde_json::Value::Object(Default::default());
        let opts = serde_json::from_value::<TransactionOptions>(empty_obj).unwrap();
        assert_eq!(opts.in_top_x_mb(), 5);
    }
}
