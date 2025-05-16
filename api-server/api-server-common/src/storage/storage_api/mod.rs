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

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
    str::FromStr,
};

use common::{
    address::Address,
    chain::{
        block::timestamp::BlockTimestamp,
        timelock::OutputTimeLock,
        tokens::{
            IsTokenFreezable, IsTokenFrozen, IsTokenUnfreezable, NftIssuance, RPCFungibleTokenInfo,
            TokenId, TokenTotalSupply,
        },
        AccountNonce, Block, ChainConfig, DelegationId, Destination, IdCreationError, OrderId,
        PoolId, SignedTransaction, Transaction, TxOutput, UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, Amount, BlockHeight, CoinOrTokenId, Id},
};
use crypto::vrf::VRFPublicKey;
use pos_accounting::{Error as PosError, PoolData};
use serialization::{Decode, Encode};

use self::block_aux_data::{BlockAuxData, BlockWithExtraData};

pub mod block_aux_data;

#[allow(dead_code)]
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum ApiServerStorageError {
    #[error("Low level storage error: {0}")]
    LowLevelStorageError(String),
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    #[error("Storage initialization failed: {0}")]
    InitializationError(String),
    #[error("Invalid initialized state")]
    InvalidInitializedState(String),
    #[error("Acquiring connection from the pool/transaction failed with error: {0}")]
    AcquiringConnectionFailed(String),
    #[error("Read-only tx begin failed: {0}")]
    RoTxBeginFailed(String),
    #[error("Read/write tx begin failed: {0}")]
    RwTxBeginFailed(String),
    #[error("Transaction commit failed: {0}")]
    TxCommitFailed(String),
    #[error("Transaction rw rollback failed: {0}")]
    TxRwRollbackFailed(String),
    #[error("Invalid block received: {0}")]
    InvalidBlock(String),
    #[error("Addressable error")]
    AddressableError,
    #[error("Block timestamp too high: {0}")]
    TimestampTooHigh(BlockTimestamp),
    #[error("Id creation error: {0}")]
    IdCreationError(#[from] IdCreationError),
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum CoinOrTokenStatistic {
    CirculatingSupply,
    Staked,
    Burned,
    Preminted,
}

impl FromStr for CoinOrTokenStatistic {
    type Err = ApiServerStorageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let statistic = match s {
            "CirculatingSupply" => Self::CirculatingSupply,
            "Staked" => Self::Staked,
            "Burned" => Self::Burned,
            "Preminted" => Self::Preminted,
            _ => {
                return Err(ApiServerStorageError::DeserializationError(format!(
                    "invalid coin or token statistic type: {s}"
                )))
            }
        };

        Ok(statistic)
    }
}

impl Display for CoinOrTokenStatistic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            Self::CirculatingSupply => "CirculatingSupply",
            Self::Staked => "Staked",
            Self::Burned => "Burned",
            Self::Preminted => "Preminted",
        };

        f.write_str(str)
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub struct Delegation {
    creation_block_height: BlockHeight,
    spend_destination: Destination,
    pool_id: PoolId,
    balance: Amount,
    next_nonce: AccountNonce,
}

impl Delegation {
    pub fn new(
        creation_block_height: BlockHeight,
        spend_destination: Destination,
        pool_id: PoolId,
        balance: Amount,
        next_nonce: AccountNonce,
    ) -> Self {
        Self {
            creation_block_height,
            spend_destination,
            pool_id,
            balance,
            next_nonce,
        }
    }

    pub fn creation_block_height(&self) -> BlockHeight {
        self.creation_block_height
    }

    pub fn spend_destination(&self) -> &Destination {
        &self.spend_destination
    }

    pub fn pool_id(&self) -> &PoolId {
        &self.pool_id
    }

    pub fn balance(&self) -> &Amount {
        &self.balance
    }

    pub fn next_nonce(&self) -> &AccountNonce {
        &self.next_nonce
    }

    pub fn stake(self, rewards: Amount) -> Self {
        Self {
            spend_destination: self.spend_destination,
            pool_id: self.pool_id,
            balance: (self.balance + rewards).expect("no overflow"),
            next_nonce: self.next_nonce,
            creation_block_height: self.creation_block_height,
        }
    }

    pub fn spend_share(self, amount: Amount, nonce: AccountNonce) -> Self {
        Self {
            spend_destination: self.spend_destination,
            pool_id: self.pool_id,
            balance: (self.balance - amount).expect("not underflow"),
            next_nonce: nonce.increment().expect("no overflow"),
            creation_block_height: self.creation_block_height,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub struct PoolDataWithExtraInfo {
    pub pool_data: PoolData,
    pub delegations_balance: Amount,
}

impl PoolDataWithExtraInfo {
    pub fn new(pool_data: PoolData) -> Self {
        Self {
            pool_data,
            delegations_balance: Amount::ZERO,
        }
    }

    pub fn increase_delegation_balance(self, stake: Amount) -> Self {
        Self {
            pool_data: self.pool_data,
            delegations_balance: (self.delegations_balance + stake).expect("no overflow"),
        }
    }

    pub fn decrease_delegation_balance(self, stake: Amount) -> Self {
        Self {
            pool_data: self.pool_data,
            delegations_balance: (self.delegations_balance - stake).expect("no overflow"),
        }
    }

    pub fn staker_balance(&self) -> Result<Amount, PosError> {
        self.pool_data.staker_balance()
    }

    pub fn is_decommissioned(&self) -> bool {
        self.pool_data.is_decommissioned()
    }

    pub fn decommission_destination(&self) -> &Destination {
        self.pool_data.decommission_destination()
    }

    pub fn pledge_amount(&self) -> Amount {
        self.pool_data.pledge_amount()
    }

    pub fn vrf_public_key(&self) -> &VRFPublicKey {
        self.pool_data.vrf_public_key()
    }

    pub fn cost_per_block(&self) -> Amount {
        self.pool_data.cost_per_block()
    }

    pub fn margin_ratio_per_thousand(&self) -> PerThousand {
        self.pool_data.margin_ratio_per_thousand()
    }

    pub fn decommission_pool(self) -> Self {
        Self {
            pool_data: self.pool_data.decommission_pool(),
            delegations_balance: self.delegations_balance,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub struct Order {
    pub creation_block_height: BlockHeight,
    pub conclude_destination: Destination,

    pub give_currency: CoinOrTokenId,
    pub initially_given: Amount,
    pub give_balance: Amount,

    pub ask_currency: CoinOrTokenId,
    pub initially_asked: Amount,
    pub ask_balance: Amount,

    pub is_frozen: bool,

    pub next_nonce: AccountNonce,
}

impl Order {
    pub fn fill(
        self,
        chain_config: &ChainConfig,
        block_height: BlockHeight,
        fill_amount_in_ask_currency: Amount,
    ) -> Self {
        let (ask_balance, give_balance) = match chain_config
            .chainstate_upgrades()
            .version_at_height(block_height)
            .1
            .orders_version()
        {
            common::chain::OrdersVersion::V0 => (self.ask_balance, self.give_balance),
            common::chain::OrdersVersion::V1 => (self.initially_asked, self.initially_given),
        };
        let filled_amount = orders_accounting::calculate_filled_amount(
            ask_balance,
            give_balance,
            fill_amount_in_ask_currency,
        )
        .expect("must succeed");

        Self {
            creation_block_height: self.creation_block_height,
            conclude_destination: self.conclude_destination,
            give_currency: self.give_currency,
            initially_given: self.initially_given,
            give_balance: (self.give_balance - filled_amount).expect("no overflow"),
            ask_currency: self.ask_currency,
            initially_asked: self.initially_asked,
            ask_balance: (self.ask_balance - fill_amount_in_ask_currency).expect("no overflow"),
            is_frozen: self.is_frozen,
            next_nonce: self.next_nonce.increment().expect("no overflow"),
        }
    }

    pub fn conclude(self) -> Self {
        Self {
            creation_block_height: self.creation_block_height,
            conclude_destination: self.conclude_destination,
            give_currency: self.give_currency,
            initially_given: self.initially_given,
            give_balance: Amount::ZERO,
            ask_currency: self.ask_currency,
            initially_asked: self.initially_asked,
            ask_balance: Amount::ZERO,
            is_frozen: self.is_frozen,
            next_nonce: self.next_nonce.increment().expect("no overflow"),
        }
    }

    pub fn freeze(self) -> Self {
        assert!(!self.is_frozen);
        Self {
            creation_block_height: self.creation_block_height,
            conclude_destination: self.conclude_destination,
            give_currency: self.give_currency,
            initially_given: self.initially_given,
            give_balance: self.give_balance,
            ask_currency: self.ask_currency,
            initially_asked: self.initially_asked,
            ask_balance: self.ask_balance,
            is_frozen: true,
            next_nonce: self.next_nonce,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum UtxoLock {
    UntilHeight(BlockHeight),
    UntilTime(BlockTimestamp),
}

impl UtxoLock {
    pub fn from_output_lock(
        lock: OutputTimeLock,
        block_timestamp: BlockTimestamp,
        block_height: BlockHeight,
    ) -> Self {
        match lock {
            OutputTimeLock::UntilTime(time) => UtxoLock::UntilTime(time),
            OutputTimeLock::UntilHeight(height) => UtxoLock::UntilHeight(height),
            OutputTimeLock::ForSeconds(time) => {
                UtxoLock::UntilTime(block_timestamp.add_int_seconds(time).expect("no overflow"))
            }
            OutputTimeLock::ForBlockCount(height) => {
                UtxoLock::UntilHeight(block_height.checked_add(height).expect("no overflow"))
            }
        }
    }

    pub fn into_time_and_height(self) -> (Option<BlockTimestamp>, Option<BlockHeight>) {
        match self {
            Self::UntilHeight(height) => (None, Some(height)),
            Self::UntilTime(time) => (Some(time), None),
        }
    }
}

#[derive(Debug, Clone, Encode, Decode, PartialEq, Eq)]
pub struct UtxoWithExtraInfo {
    pub output: TxOutput,
    pub token_decimals: Option<u8>,
}

impl UtxoWithExtraInfo {
    pub fn new(output: TxOutput, token_decimals: Option<u8>) -> Self {
        Self {
            output,
            token_decimals,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LockedUtxo {
    utxo: UtxoWithExtraInfo,
    lock: UtxoLock,
}

impl LockedUtxo {
    pub fn new_with_info(utxo: UtxoWithExtraInfo, lock: UtxoLock) -> Self {
        Self { utxo, lock }
    }

    pub fn new(output: TxOutput, token_decimals: Option<u8>, lock: UtxoLock) -> Self {
        Self {
            utxo: UtxoWithExtraInfo {
                output,
                token_decimals,
            },
            lock,
        }
    }

    pub fn utxo_with_extra_info(&self) -> &UtxoWithExtraInfo {
        &self.utxo
    }

    pub fn output(&self) -> &TxOutput {
        &self.utxo.output
    }

    pub fn into_output(self) -> TxOutput {
        self.utxo.output
    }

    pub fn lock(&self) -> UtxoLock {
        self.lock
    }
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct Utxo {
    utxo: UtxoWithExtraInfo,
    spent: bool,
}

impl Utxo {
    pub fn new_with_info(utxo: UtxoWithExtraInfo, spent: bool) -> Self {
        Self { utxo, spent }
    }

    pub fn new(output: TxOutput, token_decimals: Option<u8>, spent: bool) -> Self {
        Self {
            utxo: UtxoWithExtraInfo {
                output,
                token_decimals,
            },
            spent,
        }
    }

    pub fn utxo_with_extra_info(&self) -> &UtxoWithExtraInfo {
        &self.utxo
    }

    pub fn output(&self) -> &TxOutput {
        &self.utxo.output
    }

    pub fn into_output(self) -> TxOutput {
        self.utxo.output
    }

    pub fn spent(&self) -> bool {
        self.spent
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct FungibleTokenData {
    pub token_ticker: Vec<u8>,
    pub number_of_decimals: u8,
    pub metadata_uri: Vec<u8>,
    pub circulating_supply: Amount,
    pub total_supply: TokenTotalSupply,
    pub is_locked: bool,
    pub frozen: IsTokenFrozen,
    pub authority: Destination,
    pub next_nonce: AccountNonce,
}

impl FungibleTokenData {
    pub fn into_rpc_token_info(self, token_id: TokenId) -> RPCFungibleTokenInfo {
        RPCFungibleTokenInfo {
            token_id,
            token_ticker: self.token_ticker.into(),
            number_of_decimals: self.number_of_decimals,
            metadata_uri: self.metadata_uri.into(),
            circulating_supply: self.circulating_supply,
            total_supply: self.total_supply.into(),
            is_locked: self.is_locked,
            frozen: self.frozen.into(),
            authority: self.authority,
        }
    }

    pub fn mint_tokens(mut self, amount: Amount, nonce: AccountNonce) -> Self {
        self.circulating_supply = (self.circulating_supply + amount).expect("no overflow");
        self.next_nonce = nonce.increment().expect("no overflow");
        self
    }

    pub fn unmint_tokens(mut self, amount: Amount, nonce: AccountNonce) -> Self {
        self.circulating_supply = (self.circulating_supply - amount).expect("no underflow");
        self.next_nonce = nonce.increment().expect("no overflow");
        self
    }

    pub fn freeze(mut self, is_token_unfreezable: IsTokenUnfreezable, nonce: AccountNonce) -> Self {
        self.frozen = IsTokenFrozen::Yes(is_token_unfreezable);
        self.next_nonce = nonce.increment().expect("no overflow");
        self
    }

    pub fn unfreeze(mut self, nonce: AccountNonce) -> Self {
        self.frozen = IsTokenFrozen::No(IsTokenFreezable::Yes);
        self.next_nonce = nonce.increment().expect("no overflow");
        self
    }

    pub fn lock(mut self, nonce: AccountNonce) -> Self {
        self.is_locked = true;
        self.next_nonce = nonce.increment().expect("no overflow");
        self
    }

    pub fn change_authority(mut self, authority: Destination, nonce: AccountNonce) -> Self {
        self.authority = authority;
        self.next_nonce = nonce.increment().expect("no overflow");
        self
    }

    pub fn change_metadata_uri(mut self, metadata_uri: Vec<u8>, nonce: AccountNonce) -> Self {
        self.metadata_uri = metadata_uri;
        self.next_nonce = nonce.increment().expect("no overflow");
        self
    }
}

#[derive(Debug, Clone)]
pub struct NftWithOwner {
    pub nft: NftIssuance,
    pub owner: Option<Destination>,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct TxAdditionalInfo {
    pub fee: Amount,
    pub input_utxos: Vec<Option<TxOutput>>,
    pub token_decimals: BTreeMap<TokenId, u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct TransactionInfo {
    pub tx: SignedTransaction,
    pub additional_info: TxAdditionalInfo,
}

pub struct PoolBlockStats {
    pub block_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockInfo {
    pub block: BlockWithExtraData,
    pub height: Option<BlockHeight>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmountWithDecimals {
    pub amount: Amount,
    pub decimals: u8,
}

#[async_trait::async_trait]
pub trait ApiServerStorageRead: Sync {
    async fn is_initialized(&self) -> Result<bool, ApiServerStorageError>;

    async fn get_storage_version(&self) -> Result<Option<u32>, ApiServerStorageError>;

    async fn get_address_balance(
        &self,
        address: &str,
        coin_or_token_id: CoinOrTokenId,
    ) -> Result<Option<Amount>, ApiServerStorageError>;

    async fn get_address_balances(
        &self,
        address: &str,
    ) -> Result<BTreeMap<CoinOrTokenId, AmountWithDecimals>, ApiServerStorageError>;

    async fn get_address_locked_balance(
        &self,
        address: &str,
        coin_or_token_id: CoinOrTokenId,
    ) -> Result<Option<Amount>, ApiServerStorageError>;

    async fn get_address_transactions(
        &self,
        address: &str,
    ) -> Result<Vec<Id<Transaction>>, ApiServerStorageError>;

    async fn get_best_block(&self) -> Result<BlockAuxData, ApiServerStorageError>;

    async fn get_latest_blocktimestamps(
        &self,
    ) -> Result<Vec<BlockTimestamp>, ApiServerStorageError>;

    async fn get_block(
        &self,
        block_id: Id<Block>,
    ) -> Result<Option<BlockInfo>, ApiServerStorageError>;

    async fn get_block_aux_data(
        &self,
        block_id: Id<Block>,
    ) -> Result<Option<BlockAuxData>, ApiServerStorageError>;

    async fn get_block_range_from_time_range(
        &self,
        time_range: (BlockTimestamp, BlockTimestamp),
    ) -> Result<(BlockHeight, BlockHeight), ApiServerStorageError>;

    async fn get_delegation(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<Delegation>, ApiServerStorageError>;

    async fn get_pool_delegations(
        &self,
        pool_id: PoolId,
    ) -> Result<BTreeMap<DelegationId, Delegation>, ApiServerStorageError>;

    async fn get_main_chain_block_id(
        &self,
        block_height: BlockHeight,
    ) -> Result<Option<Id<Block>>, ApiServerStorageError>;

    async fn get_pool_data(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<PoolDataWithExtraInfo>, ApiServerStorageError>;

    async fn get_pool_block_stats(
        &self,
        pool_id: PoolId,
        block_range: (BlockHeight, BlockHeight),
    ) -> Result<Option<PoolBlockStats>, ApiServerStorageError>;

    async fn get_latest_pool_data(
        &self,
        len: u32,
        offset: u32,
    ) -> Result<Vec<(PoolId, PoolDataWithExtraInfo)>, ApiServerStorageError>;

    async fn get_pool_data_with_largest_staker_balance(
        &self,
        len: u32,
        offset: u32,
    ) -> Result<Vec<(PoolId, PoolDataWithExtraInfo)>, ApiServerStorageError>;

    #[allow(clippy::type_complexity)]
    async fn get_transaction_with_block(
        &self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<(Option<BlockAuxData>, TransactionInfo)>, ApiServerStorageError>;

    #[allow(clippy::type_complexity)]
    async fn get_transaction(
        &self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<(Id<Block>, TransactionInfo)>, ApiServerStorageError>;

    async fn get_transactions_with_block(
        &self,
        len: u32,
        offset: u32,
    ) -> Result<Vec<(BlockAuxData, TransactionInfo)>, ApiServerStorageError>;

    async fn get_utxo(&self, outpoint: UtxoOutPoint)
        -> Result<Option<Utxo>, ApiServerStorageError>;

    async fn get_address_available_utxos(
        &self,
        address: &str,
    ) -> Result<Vec<(UtxoOutPoint, UtxoWithExtraInfo)>, ApiServerStorageError>;

    async fn get_address_all_utxos(
        &self,
        address: &str,
    ) -> Result<Vec<(UtxoOutPoint, UtxoWithExtraInfo)>, ApiServerStorageError>;

    async fn get_locked_utxos_until_now(
        &self,
        block_height: BlockHeight,
        time_range: (BlockTimestamp, BlockTimestamp),
    ) -> Result<Vec<(UtxoOutPoint, UtxoWithExtraInfo)>, ApiServerStorageError>;

    async fn get_delegations_from_address(
        &self,
        address: &Destination,
    ) -> Result<Vec<(DelegationId, Delegation)>, ApiServerStorageError>;

    async fn get_fungible_tokens_by_authority(
        &self,
        authority: Destination,
    ) -> Result<Vec<TokenId>, ApiServerStorageError>;

    async fn get_fungible_token_issuance(
        &self,
        token_id: TokenId,
    ) -> Result<Option<FungibleTokenData>, ApiServerStorageError>;

    async fn get_nft_token_issuance(
        &self,
        token_id: TokenId,
    ) -> Result<Option<NftWithOwner>, ApiServerStorageError>;

    async fn get_token_num_decimals(
        &self,
        token_id: TokenId,
    ) -> Result<Option<u8>, ApiServerStorageError>;

    async fn get_token_ids(
        &self,
        len: u32,
        offset: u32,
    ) -> Result<Vec<TokenId>, ApiServerStorageError>;

    async fn get_token_ids_by_ticker(
        &self,
        len: u32,
        offset: u32,
        ticker: &[u8],
    ) -> Result<Vec<TokenId>, ApiServerStorageError>;

    async fn get_statistic(
        &self,
        statistic: CoinOrTokenStatistic,
        coin_or_token_id: CoinOrTokenId,
    ) -> Result<Option<Amount>, ApiServerStorageError>;

    async fn get_all_statistic(
        &self,
        coin_or_token_id: CoinOrTokenId,
    ) -> Result<BTreeMap<CoinOrTokenStatistic, Amount>, ApiServerStorageError>;

    async fn get_order(&self, order_id: OrderId) -> Result<Option<Order>, ApiServerStorageError>;

    async fn get_all_orders(
        &self,
        len: u32,
        offset: u32,
    ) -> Result<Vec<(OrderId, Order)>, ApiServerStorageError>;

    async fn get_orders_for_trading_pair(
        &self,
        pair: (CoinOrTokenId, CoinOrTokenId),
        len: u32,
        offset: u32,
    ) -> Result<Vec<(OrderId, Order)>, ApiServerStorageError>;
}

#[async_trait::async_trait]
pub trait ApiServerStorageWrite: ApiServerStorageRead {
    async fn reinitialize_storage(
        &mut self,
        chain_config: &ChainConfig,
    ) -> Result<(), ApiServerStorageError>;

    async fn del_address_balance_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;

    async fn del_address_locked_balance_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;

    async fn del_address_transactions_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;

    async fn set_address_balance_at_height(
        &mut self,
        address: &Address<Destination>,
        amount: Amount,
        coin_or_token_id: CoinOrTokenId,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;

    async fn set_address_locked_balance_at_height(
        &mut self,
        address: &Address<Destination>,
        amount: Amount,
        coin_or_token_id: CoinOrTokenId,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;

    async fn set_address_transactions_at_height(
        &mut self,
        address: &str,
        transaction_ids: BTreeSet<Id<Transaction>>,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;

    async fn set_mainchain_block(
        &mut self,
        block_id: Id<Block>,
        block_height: BlockHeight,
        block: &BlockWithExtraData,
    ) -> Result<(), ApiServerStorageError>;

    async fn set_delegation_at_height(
        &mut self,
        delegation_id: DelegationId,
        delegation: &Delegation,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;

    async fn set_transaction(
        &mut self,
        transaction_id: Id<Transaction>,
        owning_block: Id<Block>,
        transaction: &TransactionInfo,
    ) -> Result<(), ApiServerStorageError>;

    async fn set_block_aux_data(
        &mut self,
        block_id: Id<Block>,
        block_aux_data: &BlockAuxData,
    ) -> Result<(), ApiServerStorageError>;

    async fn del_main_chain_blocks_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;

    async fn set_pool_data_at_height(
        &mut self,
        pool_id: PoolId,
        pool_data: &PoolDataWithExtraInfo,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;

    async fn del_delegations_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;

    async fn del_pools_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;

    async fn set_utxo_at_height(
        &mut self,
        outpoint: UtxoOutPoint,
        utxo: Utxo,
        address: &str,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;

    async fn set_locked_utxo_at_height(
        &mut self,
        outpoint: UtxoOutPoint,
        utxo: LockedUtxo,
        address: &str,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;

    async fn del_utxo_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;

    async fn del_locked_utxo_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;

    async fn set_fungible_token_issuance(
        &mut self,
        token_id: TokenId,
        block_height: BlockHeight,
        issuance: FungibleTokenData,
    ) -> Result<(), ApiServerStorageError>;

    async fn set_fungible_token_data(
        &mut self,
        token_id: TokenId,
        block_height: BlockHeight,
        data: FungibleTokenData,
    ) -> Result<(), ApiServerStorageError>;

    async fn set_nft_token_issuance(
        &mut self,
        token_id: TokenId,
        block_height: BlockHeight,
        issuance: NftIssuance,
        owner: &Destination,
    ) -> Result<(), ApiServerStorageError>;

    async fn del_token_issuance_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;

    async fn del_nft_issuance_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;

    async fn del_coin_or_token_decimals_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;

    async fn set_statistic(
        &mut self,
        statistic: CoinOrTokenStatistic,
        coin_or_token_id: CoinOrTokenId,
        block_height: BlockHeight,
        amount: Amount,
    ) -> Result<(), ApiServerStorageError>;

    async fn del_statistics_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;

    async fn set_order_at_height(
        &mut self,
        order_id: OrderId,
        order: &Order,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;

    async fn del_orders_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;
}

#[async_trait::async_trait]
pub trait ApiServerTransactionRw: ApiServerStorageWrite + ApiServerStorageRead {
    async fn commit(self) -> Result<(), ApiServerStorageError>;
    async fn rollback(self) -> Result<(), ApiServerStorageError>;
}

#[async_trait::async_trait]
pub trait ApiServerTransactionRo: ApiServerStorageRead {
    async fn close(self) -> Result<(), ApiServerStorageError>;
}

#[async_trait::async_trait]
pub trait Transactional<'tx> {
    /// Associated read-only transaction type.
    type TransactionRo: ApiServerTransactionRo + Send + 'tx;

    /// Associated read-write transaction type.
    type TransactionRw: ApiServerTransactionRw + Send + 'tx;

    /// Start a read-only transaction.
    async fn transaction_ro<'db: 'tx>(
        &'db self,
    ) -> Result<Self::TransactionRo, ApiServerStorageError>;

    /// Start a read-write transaction.
    async fn transaction_rw<'db: 'tx>(
        &'db mut self,
    ) -> Result<Self::TransactionRw, ApiServerStorageError>;
}

pub trait ApiServerStorage: for<'tx> Transactional<'tx> + Send + Sync {}
