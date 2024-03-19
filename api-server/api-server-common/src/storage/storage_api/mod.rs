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

use std::collections::{BTreeMap, BTreeSet};

use common::{
    chain::{
        block::timestamp::BlockTimestamp,
        timelock::OutputTimeLock,
        tokens::{
            IsTokenFreezable, IsTokenFrozen, IsTokenUnfreezable, NftIssuance, TokenId,
            TokenTotalSupply,
        },
        AccountNonce, Block, ChainConfig, DelegationId, Destination, PoolId, SignedTransaction,
        Transaction, TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, CoinOrTokenId, Id},
};
use pos_accounting::PoolData;
use serialization::{Decode, Encode};

use self::block_aux_data::{BlockAuxData, BlockWithExtraData};

pub mod block_aux_data;

#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
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
    #[error("Block timestamp to high {0}")]
    TimestampToHigh(BlockTimestamp),
}

#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub struct Delegation {
    creation_time: BlockTimestamp,
    spend_destination: Destination,
    pool_id: PoolId,
    balance: Amount,
    next_nonce: AccountNonce,
}

impl Delegation {
    pub fn new(
        creation_time: BlockTimestamp,
        spend_destination: Destination,
        pool_id: PoolId,
        balance: Amount,
        next_nonce: AccountNonce,
    ) -> Self {
        Self {
            creation_time,
            spend_destination,
            pool_id,
            balance,
            next_nonce,
        }
    }

    pub fn creation_time(&self) -> BlockTimestamp {
        self.creation_time
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
            creation_time: self.creation_time,
        }
    }

    pub fn spend_share(self, amount: Amount, nonce: AccountNonce) -> Self {
        Self {
            spend_destination: self.spend_destination,
            pool_id: self.pool_id,
            balance: (self.balance - amount).expect("not underflow"),
            next_nonce: nonce.increment().expect("no overflow"),
            creation_time: self.creation_time,
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

#[derive(Debug, Clone)]
pub struct LockedUtxo {
    output: TxOutput,
    lock: UtxoLock,
}

impl LockedUtxo {
    pub fn new(output: TxOutput, lock: UtxoLock) -> Self {
        Self { output, lock }
    }

    pub fn output(&self) -> &TxOutput {
        &self.output
    }

    pub fn into_output(self) -> TxOutput {
        self.output
    }

    pub fn lock(&self) -> UtxoLock {
        self.lock
    }
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct Utxo {
    output: TxOutput,
    spent: bool,
}

impl Utxo {
    pub fn new(output: TxOutput, spent: bool) -> Self {
        Self { output, spent }
    }

    pub fn output(&self) -> &TxOutput {
        &self.output
    }

    pub fn into_output(self) -> TxOutput {
        self.output
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
}

impl FungibleTokenData {
    pub fn mint_tokens(mut self, amount: Amount) -> Self {
        self.circulating_supply = (self.circulating_supply + amount).expect("no overflow");
        self
    }

    pub fn unmint_tokens(mut self, amount: Amount) -> Self {
        self.circulating_supply = (self.circulating_supply - amount).expect("no underflow");
        self
    }

    pub fn freeze(mut self, is_token_unfreezable: IsTokenUnfreezable) -> Self {
        self.frozen = IsTokenFrozen::Yes(is_token_unfreezable);
        self
    }

    pub fn unfreeze(mut self) -> Self {
        self.frozen = IsTokenFrozen::No(IsTokenFreezable::Yes);
        self
    }

    pub fn lock(mut self) -> Self {
        self.is_locked = true;
        self
    }

    pub fn change_authority(mut self, authority: Destination) -> Self {
        self.authority = authority;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct TxAdditionalInfo {
    pub fee: Amount,
    pub input_utxos: Vec<Option<TxOutput>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct TransactionInfo {
    pub tx: SignedTransaction,
    pub additinal_info: TxAdditionalInfo,
}

pub struct PoolBlockStats {
    pub block_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockInfo {
    pub block: BlockWithExtraData,
    pub height: Option<BlockHeight>,
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
    ) -> Result<Option<PoolData>, ApiServerStorageError>;

    async fn get_pool_block_stats(
        &self,
        pool_id: PoolId,
        block_range: (BlockHeight, BlockHeight),
    ) -> Result<Option<PoolBlockStats>, ApiServerStorageError>;

    async fn get_latest_pool_data(
        &self,
        len: u32,
        offset: u32,
    ) -> Result<Vec<(PoolId, PoolData)>, ApiServerStorageError>;

    async fn get_pool_data_with_largest_staker_balance(
        &self,
        len: u32,
        offset: u32,
    ) -> Result<Vec<(PoolId, PoolData)>, ApiServerStorageError>;

    #[allow(clippy::type_complexity)]
    async fn get_transaction_with_block(
        &self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<(Option<BlockAuxData>, TransactionInfo)>, ApiServerStorageError>;

    #[allow(clippy::type_complexity)]
    async fn get_transaction(
        &self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<(Option<Id<Block>>, TransactionInfo)>, ApiServerStorageError>;

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
    ) -> Result<Vec<(UtxoOutPoint, TxOutput)>, ApiServerStorageError>;

    async fn get_address_all_utxos(
        &self,
        address: &str,
    ) -> Result<Vec<(UtxoOutPoint, TxOutput)>, ApiServerStorageError>;

    async fn get_locked_utxos_until_now(
        &self,
        block_height: BlockHeight,
        time_range: (BlockTimestamp, BlockTimestamp),
    ) -> Result<Vec<(UtxoOutPoint, TxOutput)>, ApiServerStorageError>;

    async fn get_delegations_from_address(
        &self,
        address: &Destination,
    ) -> Result<Vec<(DelegationId, Delegation)>, ApiServerStorageError>;

    async fn get_fungible_token_issuance(
        &self,
        token_id: TokenId,
    ) -> Result<Option<FungibleTokenData>, ApiServerStorageError>;

    async fn get_nft_token_issuance(
        &self,
        token_id: TokenId,
    ) -> Result<Option<NftIssuance>, ApiServerStorageError>;
}

#[async_trait::async_trait]
pub trait ApiServerStorageWrite: ApiServerStorageRead {
    async fn initialize_storage(
        &mut self,
        chain_config: &ChainConfig,
    ) -> Result<(), ApiServerStorageError>;

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
        address: &str,
        amount: Amount,
        coin_or_token_id: CoinOrTokenId,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;

    async fn set_address_locked_balance_at_height(
        &mut self,
        address: &str,
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
        owning_block: Option<Id<Block>>,
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
        pool_data: &PoolData,
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

    async fn set_nft_token_issuance(
        &mut self,
        token_id: TokenId,
        block_height: BlockHeight,
        issuance: NftIssuance,
    ) -> Result<(), ApiServerStorageError>;

    async fn del_token_issuance_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;

    async fn del_nft_issuance_above_height(
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
