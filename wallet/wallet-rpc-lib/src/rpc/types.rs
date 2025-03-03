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
    address::{pubkeyhash::PublicKeyHash, Address, AddressError},
    chain::{
        block::timestamp::BlockTimestamp,
        classic_multisig::ClassicMultisigChallengeError,
        signature::DestinationSigError,
        timelock::OutputTimeLock,
        tokens::{self, IsTokenFreezable, Metadata, TokenCreator, TokenId},
        ChainConfig, DelegationId, Destination, OrderId, PoolId, SignedTransaction, Transaction,
        TxOutput, UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, Amount, BlockHeight, Id, Idable},
};
use crypto::{
    key::{
        hdkd::{child_number::ChildNumber, u31::U31},
        PublicKey,
    },
    vrf::VRFPublicKey,
};
use rpc::description::HasValueHint;
use utils::ensure;
use wallet::account::PoolData;

pub use chainstate::{
    rpc::{
        RpcOutputValueIn, RpcOutputValueOut, RpcSignedTransaction, RpcTxOutput, RpcUtxoOutpoint,
    },
    ChainInfo,
};
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
use wallet_controller::{types::WalletTypeArgs, UtxoState, UtxoType};
pub use wallet_controller::{ControllerConfig, NodeInterface};
use wallet_types::{
    partially_signed_transaction::PartiallySignedTransaction, seed_phrase::StoreSeedPhrase,
    signature_status::SignatureStatus,
};

use crate::service::SubmitError;

#[derive(Debug, thiserror::Error)]
pub enum RpcError<N: NodeInterface> {
    #[error("Account index out of supported range")]
    AcctIndexOutOfRange,

    #[error("Invalid coin amount")]
    InvalidCoinAmount,

    #[error("Invalid address")]
    InvalidAddress,

    // Same as InvalidAddress, but for cases when it's not clear which address is invalid.
    #[error("Invalid address: {0}")]
    InvalidAddressWithAddr(String),

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

    #[error("Cannot recover a software wallet without providing a mnemonic")]
    EmptyMnemonic,

    #[error("Cannot specify a mnemonic or passphrase when creating a hardware wallet")]
    HardwareWalletWithMnemonicOrPassphrase,

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

    #[error(transparent)]
    Address(#[from] AddressError),

    #[error("The specified address {0} is not a multisig address")]
    NotMultisigAddress(String),

    #[error(
        "There are no UTXOs corresponding to the specified multisig address for tokens: {0:?}"
    )]
    NoUtxosForMultisigAddressForTokens(Vec<TokenId>),

    #[error("No outputs specified")]
    NoOutputsSpecified,

    #[error("Invalid HTLC secret")]
    InvalidHtlcSecret,

    #[error("Invalid HTLC secret hash")]
    InvalidHtlcSecretHash,
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
#[serde(tag = "type", content = "content")]
pub enum RpcStandaloneAddressDetails {
    WatchOnly,
    FromPrivateKey,
    Multisig {
        min_required_signatures: u8,
        public_keys: Vec<RpcAddress<Destination>>,
    },
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
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
    pub margin_ratio_per_thousand: PerThousand,
    pub cost_per_block: RpcAmountOut,
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
        let cost_per_block =
            RpcAmountOut::from_amount_no_padding(pool_data.cost_per_block, decimals);

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
            margin_ratio_per_thousand: pool_data.margin_ratio_per_thousand,
            cost_per_block,
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
    pub pool_id: RpcAddress<PoolId>,
    pub balance: RpcAmountOut,
}

impl DelegationInfo {
    pub fn new(
        delegation_id: DelegationId,
        pool_id: PoolId,
        balance: Amount,
        chain_config: &ChainConfig,
    ) -> Self {
        let decimals = chain_config.coin_decimals();
        let balance = RpcAmountOut::from_amount_no_padding(balance, decimals);

        Self {
            delegation_id: RpcAddress::new(chain_config, delegation_id).expect("addressable"),
            pool_id: RpcAddress::new(chain_config, pool_id).expect("addressable"),
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
    Htlc,
}

impl From<&RpcUtxoType> for UtxoType {
    fn from(value: &RpcUtxoType) -> Self {
        match value {
            RpcUtxoType::Transfer => UtxoType::Transfer,
            RpcUtxoType::LockThenTransfer => UtxoType::LockThenTransfer,
            RpcUtxoType::IssueNft => UtxoType::IssueNft,
            RpcUtxoType::CreateStakePool => UtxoType::CreateStakePool,
            RpcUtxoType::ProduceBlockFromStake => UtxoType::ProduceBlockFromStake,
            RpcUtxoType::Htlc => UtxoType::Htlc,
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
            UtxoType::Htlc => RpcUtxoType::Htlc,
        }
    }
}

#[derive(
    Debug, Clone, Copy, serde::Serialize, serde::Deserialize, HasValueHint, enum_iterator::Sequence,
)]
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
#[serde(tag = "type", content = "content")]
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
#[serde(tag = "type", content = "content")]
pub enum MnemonicInfo {
    UserProvided,
    NewlyGenerated { mnemonic: String },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct CreatedWallet {
    pub mnemonic: MnemonicInfo,
}

impl From<wallet_controller::types::CreatedWallet> for CreatedWallet {
    fn from(value: wallet_controller::types::CreatedWallet) -> Self {
        let mnemonic = match value {
            wallet_controller::types::CreatedWallet::UserProvidedMnemonic => {
                MnemonicInfo::UserProvided
            }
            wallet_controller::types::CreatedWallet::NewlyGeneratedMnemonic(mnemonic) => {
                MnemonicInfo::NewlyGenerated {
                    mnemonic: mnemonic.to_string(),
                }
            }
        };
        Self { mnemonic }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct ComposedTransaction {
    pub hex: String,
    pub fees: Balances,
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize, HasValueHint)]
#[serde(tag = "type", content = "content")]
pub enum RpcSignatureStatus {
    NotSigned,
    InvalidSignature,
    UnknownSignature,
    FullySigned,
    PartialMultisig {
        required_signatures: u8,
        num_signatures: u8,
    },
}

impl From<SignatureStatus> for RpcSignatureStatus {
    fn from(value: SignatureStatus) -> Self {
        match value {
            SignatureStatus::NotSigned => Self::NotSigned,
            SignatureStatus::InvalidSignature => Self::InvalidSignature,
            SignatureStatus::UnknownSignature => Self::UnknownSignature,
            SignatureStatus::FullySigned => Self::FullySigned,
            SignatureStatus::PartialMultisig {
                required_signatures,
                num_signatures,
            } => Self::PartialMultisig {
                required_signatures,
                num_signatures,
            },
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct MaybeSignedTransaction {
    pub hex: String,
    pub is_complete: bool,
    pub previous_signatures: Vec<RpcSignatureStatus>,
    pub current_signatures: Vec<RpcSignatureStatus>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct SendTokensFromMultisigAddressResult {
    pub transaction: HexEncoded<PartiallySignedTransaction>,
    pub current_signatures: Vec<RpcSignatureStatus>,
    pub fees: Balances,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct RpcValidatedSignatures {
    pub num_valid_signatures: usize,
    pub num_invalid_signatures: usize,
    pub signature_statuses: Vec<RpcSignatureStatus>,
}

impl From<ValidatedSignatures> for RpcValidatedSignatures {
    fn from(value: ValidatedSignatures) -> Self {
        Self {
            num_valid_signatures: value.num_valid_signatures,
            num_invalid_signatures: value.num_invalid_signatures,
            signature_statuses: value.signature_statuses.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct RpcSignatureStats {
    pub num_inputs: usize,
    pub total_signatures: usize,
    pub validated_signatures: Option<RpcValidatedSignatures>,
}

impl From<SignatureStats> for RpcSignatureStats {
    fn from(value: SignatureStats) -> Self {
        Self {
            num_inputs: value.num_inputs,
            total_signatures: value.total_signatures,
            validated_signatures: value.validated_signatures.map(Into::into),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct RpcInspectTransaction {
    pub tx: HexEncoded<Transaction>,
    pub fees: Option<Balances>,
    pub stats: RpcSignatureStats,
}

impl From<InspectTransaction> for RpcInspectTransaction {
    fn from(value: InspectTransaction) -> Self {
        Self {
            tx: value.tx,
            fees: value.fees,
            stats: value.stats.into(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct RpcHashedTimelockContract {
    pub secret_hash: RpcHexString,
    pub spend_address: RpcAddress<Destination>,
    pub refund_address: RpcAddress<Destination>,
    pub refund_timelock: OutputTimeLock,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct NewOrder {
    pub tx_id: Id<Transaction>,
    pub order_id: RpcAddress<OrderId>,
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
#[serde(tag = "type", content = "content")]
pub enum RpcCurrency {
    Coin,
    Token { token_id: RpcAddress<TokenId> },
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, HasValueHint)]
pub enum HardwareWalletType {
    #[cfg(feature = "trezor")]
    Trezor,
}

impl HardwareWalletType {
    pub fn into_wallet_args<N: NodeInterface>(
        hardware_wallet: Option<Self>,
        store_seed_phrase: bool,
        mnemonic: Option<String>,
        passphrase: Option<String>,
    ) -> Result<WalletTypeArgs, RpcError<N>> {
        let store_seed_phrase = if store_seed_phrase {
            StoreSeedPhrase::Store
        } else {
            StoreSeedPhrase::DoNotStore
        };

        match hardware_wallet {
            None => Ok(WalletTypeArgs::Software {
                mnemonic,
                passphrase,
                store_seed_phrase,
            }),
            Some(hw_type) => {
                ensure!(
                    mnemonic.is_none()
                        && passphrase.is_none()
                        && store_seed_phrase == StoreSeedPhrase::DoNotStore,
                    RpcError::HardwareWalletWithMnemonicOrPassphrase
                );
                match hw_type {
                    #[cfg(feature = "trezor")]
                    HardwareWalletType::Trezor => Ok(WalletTypeArgs::Trezor),
                }
            }
        }
    }
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
