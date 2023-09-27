// Copyright (c) 2022 RBB S.r.l
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

//! A mock version of the blockchain storage.

use std::collections::BTreeMap;

use chainstate_types::{BlockIndex, EpochData, EpochStorageRead, EpochStorageWrite};
use common::{
    chain::{
        block::{signed_block_header::SignedBlockHeader, BlockReward},
        config::EpochIndex,
        tokens::{TokenAuxiliaryData, TokenId},
        transaction::{OutPointSourceId, Transaction, TxMainChainIndex, TxMainChainPosition},
        AccountNonce, AccountType, Block, DelegationId, GenBlock, PoolId, SignedTransaction,
        UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, Id},
};
use pos_accounting::{
    AccountingBlockUndo, DelegationData, DeltaMergeUndo, PoSAccountingDeltaData, PoolData,
};
use tokens_accounting::{TokensAccountingStorageRead, TokensAccountingStorageWrite};
use utxo::{Utxo, UtxosBlockUndo, UtxosStorageRead, UtxosStorageWrite};

use super::mock_impl_accounting::{
    PoSAccountingStorageReadSealed, PoSAccountingStorageReadTip, PoSAccountingStorageWriteSealed,
    PoSAccountingStorageWriteTip,
};

use crate::ChainstateStorageVersion;

mockall::mock! {
    /// A mock object for blockchain storage
    pub Store {}

    impl crate::BlockchainStorageRead for Store {
        fn get_storage_version(&self) -> crate::Result<Option<ChainstateStorageVersion>>;
        fn get_magic_bytes(&self) -> crate::Result<Option<[u8; 4]>>;
        fn get_chain_type(&self) -> crate::Result<Option<String>>;
        fn get_best_block_id(&self) -> crate::Result<Option<Id<GenBlock>>>;
        fn get_block_index(&self, id: &Id<Block>) -> crate::Result<Option<BlockIndex>>;
        fn get_block(&self, id: Id<Block>) -> crate::Result<Option<Block>>;
        fn get_block_reward(&self, block_index: &BlockIndex) -> crate::Result<Option<BlockReward>>;
        fn get_block_header(&self, id: Id<Block>) -> crate::Result<Option<SignedBlockHeader>>;

        fn get_is_mainchain_tx_index_enabled(&self) -> crate::Result<Option<bool>>;
        fn get_min_height_with_allowed_reorg(&self) -> crate::Result<Option<BlockHeight>>;

        fn get_mainchain_tx_index(
            &self,
            tx_id: &OutPointSourceId,
        ) -> crate::Result<Option<TxMainChainIndex>>;

        fn get_mainchain_tx_by_position(
            &self,
            tx_index: &TxMainChainPosition,
        ) -> crate::Result<Option<SignedTransaction>>;

        fn get_block_id_by_height(
            &self,
            height: &BlockHeight,
        ) -> crate::Result<Option<Id<GenBlock>>>;

        fn get_token_aux_data(&self, token_id: &TokenId) -> crate::Result<Option<TokenAuxiliaryData>>;

        fn get_token_id(&self, tx_id: &Id<Transaction>) -> crate::Result<Option<TokenId>>;

        fn get_block_tree_by_height(
            &self,
            start_from: BlockHeight,
        ) -> crate::Result<BTreeMap<BlockHeight, Vec<Id<Block>>>>;

        fn get_accounting_undo(&self, id: Id<Block>) -> crate::Result<Option<AccountingBlockUndo>>;

        fn get_accounting_epoch_delta(
            &self,
            epoch_index: EpochIndex,
        ) -> crate::Result<Option<PoSAccountingDeltaData>>;

        fn get_accounting_epoch_undo_delta(
            &self,
            epoch_index: EpochIndex,
        ) -> crate::Result<Option<DeltaMergeUndo>>;

        fn get_account_nonce_count(&self, account: AccountType) -> crate::Result<Option<AccountNonce>>;
    }

    impl EpochStorageRead for Store {
        fn get_epoch_data(&self, epoch_index: u64) -> crate::Result<Option<EpochData>>;
    }

    impl UtxosStorageRead for Store {
        type Error = crate::Error;
        fn get_utxo(&self, outpoint: &UtxoOutPoint) -> crate::Result<Option<Utxo>>;
        fn get_best_block_for_utxos(&self) -> crate::Result<Id<GenBlock>>;
        fn get_undo_data(&self, id: Id<Block>) -> crate::Result<Option<UtxosBlockUndo>>;
    }

    impl PoSAccountingStorageReadTip for Store {
        fn get_pool_balance_tip(&self, pool_id: PoolId) -> crate::Result<Option<Amount>>;
        fn get_pool_data_tip(&self, pool_id: PoolId) -> crate::Result<Option<PoolData>>;
        fn get_delegation_balance_tip(
            &self,
            delegation_id: DelegationId,
        ) -> crate::Result<Option<Amount>>;
        fn get_delegation_data_tip(
            &self,
            delegation_id: DelegationId,
        ) -> crate::Result<Option<DelegationData>>;
        fn get_pool_delegations_shares_tip(
            &self,
            pool_id: PoolId,
        ) -> crate::Result<Option<BTreeMap<DelegationId, Amount>>>;
        fn get_pool_delegation_share_tip(
            &self,
            pool_id: PoolId,
            delegation_id: DelegationId,
        ) -> crate::Result<Option<Amount>>;
    }

    impl PoSAccountingStorageReadSealed for Store {
        fn get_pool_balance_sealed(&self, pool_id: PoolId) -> crate::Result<Option<Amount>>;
        fn get_pool_data_sealed(&self, pool_id: PoolId) -> crate::Result<Option<PoolData>>;
        fn get_delegation_balance_sealed(
            &self,
            delegation_id: DelegationId,
        ) -> crate::Result<Option<Amount>>;
        fn get_delegation_data_sealed(
            &self,
            delegation_id: DelegationId,
        ) -> crate::Result<Option<DelegationData>>;
        fn get_pool_delegations_shares_sealed(
            &self,
            pool_id: PoolId,
        ) -> crate::Result<Option<BTreeMap<DelegationId, Amount>>>;
        fn get_pool_delegation_share_sealed(
            &self,
            pool_id: PoolId,
            delegation_id: DelegationId,
        ) -> crate::Result<Option<Amount>>;
    }

    impl TokensAccountingStorageRead for Store {
        type Error = crate::Error;
        fn get_token_data(&self, id: &TokenId,) -> crate::Result<Option<tokens_accounting::TokenData>>;
        fn get_circulating_supply(&self, id: &TokenId,) -> crate::Result<Option<Amount> >;
    }

    impl crate::BlockchainStorageWrite for Store {
        fn set_storage_version(&mut self, version: ChainstateStorageVersion) -> crate::Result<()>;
        fn set_magic_bytes(&mut self, bytes: &[u8; 4]) -> crate::Result<()>;
        fn set_chain_type(&mut self, chain: &str) -> crate::Result<()>;
        fn set_best_block_id(&mut self, id: &Id<GenBlock>) -> crate::Result<()>;
        fn set_block_index(&mut self, block_index: &BlockIndex) -> crate::Result<()>;
        fn add_block(&mut self, block: &Block) -> crate::Result<()>;
        fn del_block(&mut self, id: Id<Block>) -> crate::Result<()>;

        fn set_is_mainchain_tx_index_enabled(&mut self, enabled: bool) -> crate::Result<()>;
        fn set_min_height_with_allowed_reorg(&mut self, height: BlockHeight) -> crate::Result<()>;

        fn set_mainchain_tx_index(
            &mut self,
            tx_id: &OutPointSourceId,
            tx_index: &TxMainChainIndex,
        ) -> crate::Result<()>;
        fn del_mainchain_tx_index(&mut self, tx_id: &OutPointSourceId) -> crate::Result<()>;

        fn set_block_id_at_height(
            &mut self,
            height: &BlockHeight,
            block_id: &Id<GenBlock>,
        ) -> crate::Result<()>;

        fn del_block_id_at_height(&mut self, height: &BlockHeight) -> crate::Result<()>;

        fn set_token_aux_data(&mut self, token_id: &TokenId, data: &TokenAuxiliaryData) -> crate::Result<()>;
        fn del_token_aux_data(&mut self, token_id: &TokenId) -> crate::Result<()>;
        fn set_token_id(&mut self, issuance_tx_id: &Id<Transaction>, token_id: &TokenId) -> crate::Result<()>;
        fn del_token_id(&mut self, issuance_tx_id: &Id<Transaction>) -> crate::Result<()>;

        fn set_accounting_undo_data(&mut self, id: Id<Block>, undo: &AccountingBlockUndo) -> crate::Result<()>;
        fn del_accounting_undo_data(&mut self, id: Id<Block>) -> crate::Result<()>;

        fn set_accounting_epoch_delta(
            &mut self,
            epoch_index: EpochIndex,
            delta: &PoSAccountingDeltaData,
        ) -> crate::Result<()>;
        fn del_accounting_epoch_delta(&mut self, epoch_index: EpochIndex) -> crate::Result<()>;

        fn set_accounting_epoch_undo_delta(
            &mut self,
            epoch_index: EpochIndex,
            undo: &DeltaMergeUndo,
        ) -> crate::Result<()>;
        fn del_accounting_epoch_undo_delta(&mut self, epoch_index: EpochIndex) -> crate::Result<()>;

        fn set_account_nonce_count(&mut self, account: AccountType, nonce: AccountNonce) -> crate::Result<()>;
        fn del_account_nonce_count(&mut self, account: AccountType) -> crate::Result<()>;
    }

    impl EpochStorageWrite for Store {
        fn set_epoch_data(&mut self, epoch_index: u64, epoch_data: &EpochData) -> crate::Result<()>;
        fn del_epoch_data(&mut self, epoch_index: u64) -> crate::Result<()>;
    }

    impl UtxosStorageWrite for Store {
        fn set_utxo(&mut self, outpoint: &UtxoOutPoint, entry: Utxo) -> crate::Result<()>;
        fn del_utxo(&mut self, outpoint: &UtxoOutPoint) -> crate::Result<()>;

        fn set_best_block_for_utxos(&mut self, block_id: &Id<GenBlock>) -> crate::Result<()>;

        fn set_undo_data(&mut self, id: Id<Block>, undo: &UtxosBlockUndo) -> crate::Result<()>;
        fn del_undo_data(&mut self, id: Id<Block>) -> crate::Result<()>;
    }

    impl PoSAccountingStorageWriteTip for Store {
        fn set_pool_balance_tip(&mut self, pool_id: PoolId, amount: Amount) -> crate::Result<()>;
        fn del_pool_balance_tip(&mut self, pool_id: PoolId) -> crate::Result<()>;

        fn set_pool_data_tip(&mut self, pool_id: PoolId, pool_data: &PoolData) -> crate::Result<()>;
        fn del_pool_data_tip(&mut self, pool_id: PoolId) -> crate::Result<()>;

        fn set_delegation_balance_tip(
            &mut self,
            delegation_target: DelegationId,
            amount: Amount,
        ) -> crate::Result<()>;
        fn del_delegation_balance_tip(&mut self, delegation_target: DelegationId) -> crate::Result<()>;

        fn set_delegation_data_tip(
            &mut self,
            delegation_id: DelegationId,
            delegation_data: &DelegationData,
        ) -> crate::Result<()>;
        fn del_delegation_data_tip(&mut self, delegation_id: DelegationId) -> crate::Result<()>;

        fn set_pool_delegation_share_tip(
            &mut self,
            pool_id: PoolId,
            delegation_id: DelegationId,
            amount: Amount,
        ) -> crate::Result<()>;
        fn del_pool_delegation_share_tip(
            &mut self,
            pool_id: PoolId,
            delegation_id: DelegationId,
        ) -> crate::Result<()>;
    }

    impl PoSAccountingStorageWriteSealed for Store {
        fn set_pool_balance_sealed(&mut self, pool_id: PoolId, amount: Amount) -> crate::Result<()>;
        fn del_pool_balance_sealed(&mut self, pool_id: PoolId) -> crate::Result<()>;

        fn set_pool_data_sealed(&mut self, pool_id: PoolId, pool_data: &PoolData) -> crate::Result<()>;
        fn del_pool_data_sealed(&mut self, pool_id: PoolId) -> crate::Result<()>;

        fn set_delegation_balance_sealed(
            &mut self,
            delegation_target: DelegationId,
            amount: Amount,
        ) -> crate::Result<()>;
        fn del_delegation_balance_sealed(
            &mut self,
            delegation_target: DelegationId,
        ) -> crate::Result<()>;

        fn set_delegation_data_sealed(
            &mut self,
            delegation_id: DelegationId,
            delegation_data: &DelegationData,
        ) -> crate::Result<()>;
        fn del_delegation_data_sealed(&mut self, delegation_id: DelegationId) -> crate::Result<()>;

        fn set_pool_delegation_share_sealed(
            &mut self,
            pool_id: PoolId,
            delegation_id: DelegationId,
            amount: Amount,
        ) -> crate::Result<()>;
        fn del_pool_delegation_share_sealed(
            &mut self,
            pool_id: PoolId,
            delegation_id: DelegationId,
        ) -> crate::Result<()>;
    }

    impl TokensAccountingStorageWrite for Store {
        fn set_token_data(&mut self, id: &TokenId, data: &tokens_accounting::TokenData) -> crate::Result<()>;
        fn del_token_data(&mut self, id: &TokenId) -> crate::Result<()>;

        fn set_circulating_supply(&mut self, id: &TokenId, supply: &Amount) -> crate::Result<() >;
        fn del_circulating_supply(&mut self, id: &TokenId) -> crate::Result<()>;
    }

    #[allow(clippy::extra_unused_lifetimes)]
    impl<'tx> crate::Transactional<'tx> for Store {
        type TransactionRo = MockStoreTxRo;
        type TransactionRw = MockStoreTxRw;
        fn transaction_ro<'st>(&'st self) -> crate::Result<MockStoreTxRo> where 'st: 'tx;
        fn transaction_rw<'st>(&'st self, size: Option<usize>) -> crate::Result<MockStoreTxRw> where 'st: 'tx;
    }

    impl crate::BlockchainStorage for Store {}
}

mockall::mock! {
    /// A mock object for blockchain storage transaction
    pub StoreTxRo {}

    impl crate::BlockchainStorageRead for StoreTxRo {
        fn get_storage_version(&self) -> crate::Result<Option<ChainstateStorageVersion>>;
        fn get_magic_bytes(&self) -> crate::Result<Option<[u8; 4]>>;
        fn get_chain_type(&self) -> crate::Result<Option<String>>;
        fn get_best_block_id(&self) -> crate::Result<Option<Id<GenBlock>>>;
        fn get_block_index(&self, id: &Id<Block>) -> crate::Result<Option<BlockIndex>>;
        fn get_block(&self, id: Id<Block>) -> crate::Result<Option<Block>>;
        fn get_block_reward(&self, block_index: &BlockIndex) -> crate::Result<Option<BlockReward>>;
        fn get_block_header(&self, id: Id<Block>) -> crate::Result<Option<SignedBlockHeader>>;

        fn get_is_mainchain_tx_index_enabled(&self) -> crate::Result<Option<bool>>;
        fn get_min_height_with_allowed_reorg(&self) -> crate::Result<Option<BlockHeight>>;

        fn get_mainchain_tx_index(
            &self,
            tx_id: &OutPointSourceId,
        ) -> crate::Result<Option<TxMainChainIndex>>;

        fn get_mainchain_tx_by_position(
            &self,
            tx_index: &TxMainChainPosition,
        ) -> crate::Result<Option<SignedTransaction>>;

        fn get_block_id_by_height(
            &self,
            height: &BlockHeight,
        ) -> crate::Result<Option<Id<GenBlock>>>;

        fn get_token_aux_data(&self, token_id: &TokenId) -> crate::Result<Option<TokenAuxiliaryData>>;
        fn get_token_id(&self, tx_id: &Id<Transaction>) -> crate::Result<Option<TokenId>>;
        fn get_block_tree_by_height(
            &self,
            start_from: BlockHeight,
        ) -> crate::Result<BTreeMap<BlockHeight, Vec<Id<Block>>>>;

        fn get_accounting_undo(&self, id: Id<Block>) -> crate::Result<Option<AccountingBlockUndo>>;

        fn get_accounting_epoch_delta(
            &self,
            epoch_index: EpochIndex,
        ) -> crate::Result<Option<PoSAccountingDeltaData>>;

        fn get_accounting_epoch_undo_delta(
            &self,
            epoch_index: EpochIndex,
        ) -> crate::Result<Option<DeltaMergeUndo>>;

        fn get_account_nonce_count(&self, account: AccountType) -> crate::Result<Option<AccountNonce>>;
    }

    impl EpochStorageRead for StoreTxRo {
        fn get_epoch_data(&self, epoch_index: u64) -> crate::Result<Option<EpochData>>;
    }

    impl crate::UtxosStorageRead for StoreTxRo {
        type Error = crate::Error;
        fn get_utxo(&self, outpoint: &UtxoOutPoint) -> crate::Result<Option<Utxo>>;
        fn get_best_block_for_utxos(&self) -> crate::Result<Id<GenBlock>>;
        fn get_undo_data(&self, id: Id<Block>) -> crate::Result<Option<UtxosBlockUndo>>;
    }

    impl PoSAccountingStorageReadTip for StoreTxRo {
        fn get_pool_balance_tip(&self, pool_id: PoolId) -> crate::Result<Option<Amount>>;
        fn get_pool_data_tip(&self, pool_id: PoolId) -> crate::Result<Option<PoolData>>;
        fn get_delegation_balance_tip(
            &self,
            delegation_id: DelegationId,
        ) -> crate::Result<Option<Amount>>;
        fn get_delegation_data_tip(
            &self,
            delegation_id: DelegationId,
        ) -> crate::Result<Option<DelegationData>>;
        fn get_pool_delegations_shares_tip(
            &self,
            pool_id: PoolId,
        ) -> crate::Result<Option<BTreeMap<DelegationId, Amount>>>;
        fn get_pool_delegation_share_tip(
            &self,
            pool_id: PoolId,
            delegation_id: DelegationId,
        ) -> crate::Result<Option<Amount>>;
    }

    impl PoSAccountingStorageReadSealed for StoreTxRo {
        fn get_pool_balance_sealed(&self, pool_id: PoolId) -> crate::Result<Option<Amount>>;
        fn get_pool_data_sealed(&self, pool_id: PoolId) -> crate::Result<Option<PoolData>>;
        fn get_delegation_balance_sealed(
            &self,
            delegation_id: DelegationId,
        ) -> crate::Result<Option<Amount>>;
        fn get_delegation_data_sealed(
            &self,
            delegation_id: DelegationId,
        ) -> crate::Result<Option<DelegationData>>;
        fn get_pool_delegations_shares_sealed(
            &self,
            pool_id: PoolId,
        ) -> crate::Result<Option<BTreeMap<DelegationId, Amount>>>;
        fn get_pool_delegation_share_sealed(
            &self,
            pool_id: PoolId,
            delegation_id: DelegationId,
        ) -> crate::Result<Option<Amount>>;
    }

    impl TokensAccountingStorageRead for StoreTxRo {
        type Error = crate::Error;
        fn get_token_data(&self, id: &TokenId,) -> crate::Result<Option<tokens_accounting::TokenData>>;
        fn get_circulating_supply(&self, id: &TokenId,) -> crate::Result<Option<Amount> >;
    }

    impl crate::TransactionRo for StoreTxRo {
        fn close(self);
    }

    impl crate::IsTransaction for StoreTxRo {}
}

mockall::mock! {
    /// A mock object for blockchain storage transaction
    pub StoreTxRw {}

    impl crate::BlockchainStorageRead for StoreTxRw {
        fn get_storage_version(&self) -> crate::Result<Option<ChainstateStorageVersion>>;
        fn get_magic_bytes(&self) -> crate::Result<Option<[u8; 4]>>;
        fn get_chain_type(&self) -> crate::Result<Option<String>>;
        fn get_best_block_id(&self) -> crate::Result<Option<Id<GenBlock>>>;
        fn get_block(&self, id: Id<Block>) -> crate::Result<Option<Block>>;
        fn get_block_index(&self, id: &Id<Block>) -> crate::Result<Option<BlockIndex>>;
        fn get_block_reward(&self, block_index: &BlockIndex) -> crate::Result<Option<BlockReward>>;
        fn get_block_header(&self, id: Id<Block>) -> crate::Result<Option<SignedBlockHeader>>;

        fn get_is_mainchain_tx_index_enabled(&self) -> crate::Result<Option<bool>>;
        fn get_min_height_with_allowed_reorg(&self) -> crate::Result<Option<BlockHeight>>;

        fn get_mainchain_tx_index(
            &self,
            tx_id: &OutPointSourceId,
        ) -> crate::Result<Option<TxMainChainIndex>>;

        fn get_mainchain_tx_by_position(
            &self,
            tx_index: &TxMainChainPosition,
        ) -> crate::Result<Option<SignedTransaction>>;

        fn get_block_id_by_height(
            &self,
            height: &BlockHeight,
        ) -> crate::Result<Option<Id<GenBlock>>>;

        fn get_token_aux_data(&self, token_id: &TokenId) -> crate::Result<Option<TokenAuxiliaryData>>;
        fn get_token_id(&self, tx_id: &Id<Transaction>) -> crate::Result<Option<TokenId>>;
        fn get_block_tree_by_height(
            &self,
            start_from: BlockHeight,
        ) -> crate::Result<BTreeMap<BlockHeight, Vec<Id<Block>>>>;

        fn get_accounting_undo(&self, id: Id<Block>) -> crate::Result<Option<AccountingBlockUndo>>;

        fn get_accounting_epoch_delta(
            &self,
            epoch_index: EpochIndex,
        ) -> crate::Result<Option<PoSAccountingDeltaData>>;

        fn get_accounting_epoch_undo_delta(
            &self,
            epoch_index: EpochIndex,
        ) -> crate::Result<Option<DeltaMergeUndo>>;

       fn get_account_nonce_count(&self, account: AccountType) -> crate::Result<Option<AccountNonce>>;
    }

    impl EpochStorageRead for StoreTxRw {
        fn get_epoch_data(&self, epoch_index: u64) -> crate::Result<Option<EpochData>>;
    }

    impl UtxosStorageRead for StoreTxRw {
        type Error = crate::Error;
        fn get_utxo(&self, outpoint: &UtxoOutPoint) -> crate::Result<Option<Utxo>>;
        fn get_best_block_for_utxos(&self) -> crate::Result<Id<GenBlock>>;
        fn get_undo_data(&self, id: Id<Block>) -> crate::Result<Option<UtxosBlockUndo>>;
    }

    impl PoSAccountingStorageReadTip for StoreTxRw {
        fn get_pool_balance_tip(&self, pool_id: PoolId) -> crate::Result<Option<Amount>>;
        fn get_pool_data_tip(&self, pool_id: PoolId) -> crate::Result<Option<PoolData>>;
        fn get_delegation_balance_tip(
            &self,
            delegation_id: DelegationId,
        ) -> crate::Result<Option<Amount>>;
        fn get_delegation_data_tip(
            &self,
            delegation_id: DelegationId,
        ) -> crate::Result<Option<DelegationData>>;
        fn get_pool_delegations_shares_tip(
            &self,
            pool_id: PoolId,
        ) -> crate::Result<Option<BTreeMap<DelegationId, Amount>>>;
        fn get_pool_delegation_share_tip(
            &self,
            pool_id: PoolId,
            delegation_id: DelegationId,
        ) -> crate::Result<Option<Amount>>;
    }

    impl PoSAccountingStorageReadSealed for StoreTxRw {
        fn get_pool_balance_sealed(&self, pool_id: PoolId) -> crate::Result<Option<Amount>>;
        fn get_pool_data_sealed(&self, pool_id: PoolId) -> crate::Result<Option<PoolData>>;
        fn get_delegation_balance_sealed(
            &self,
            delegation_id: DelegationId,
        ) -> crate::Result<Option<Amount>>;
        fn get_delegation_data_sealed(
            &self,
            delegation_id: DelegationId,
        ) -> crate::Result<Option<DelegationData>>;
        fn get_pool_delegations_shares_sealed(
            &self,
            pool_id: PoolId,
        ) -> crate::Result<Option<BTreeMap<DelegationId, Amount>>>;
        fn get_pool_delegation_share_sealed(
            &self,
            pool_id: PoolId,
            delegation_id: DelegationId,
        ) -> crate::Result<Option<Amount>>;
    }

    impl TokensAccountingStorageRead for StoreTxRw {
        type Error = crate::Error;
        fn get_token_data(&self, id: &TokenId,) -> crate::Result<Option<tokens_accounting::TokenData>>;
        fn get_circulating_supply(&self, id: &TokenId,) -> crate::Result<Option<Amount> >;
    }

    impl crate::BlockchainStorageWrite for StoreTxRw {
        fn set_storage_version(&mut self, version: ChainstateStorageVersion) -> crate::Result<()>;
        fn set_magic_bytes(&mut self, bytes: &[u8; 4]) -> crate::Result<()>;
        fn set_chain_type(&mut self, chain: &str) -> crate::Result<()>;
        fn set_best_block_id(&mut self, id: &Id<GenBlock>) -> crate::Result<()>;
        fn set_block_index(&mut self, block_index: &BlockIndex) -> crate::Result<()>;
        fn add_block(&mut self, block: &Block) -> crate::Result<()>;
        fn del_block(&mut self, id: Id<Block>) -> crate::Result<()>;

        fn set_is_mainchain_tx_index_enabled(&mut self, enabled: bool) -> crate::Result<()>;
        fn set_min_height_with_allowed_reorg(&mut self, height: BlockHeight) -> crate::Result<()>;

        fn set_mainchain_tx_index(
            &mut self,
            tx_id: &OutPointSourceId,
            tx_index: &TxMainChainIndex,
        ) -> crate::Result<()>;
        fn del_mainchain_tx_index(&mut self, tx_id: &OutPointSourceId) -> crate::Result<()>;

        fn set_block_id_at_height(
            &mut self,
            height: &BlockHeight,
            block_id: &Id<GenBlock>,
        ) -> crate::Result<()>;

        fn del_block_id_at_height(&mut self, height: &BlockHeight) -> crate::Result<()>;
        fn set_token_aux_data(&mut self, token_id: &TokenId, data: &TokenAuxiliaryData) -> crate::Result<()>;
        fn del_token_aux_data(&mut self, token_id: &TokenId) -> crate::Result<()>;

        fn set_token_id(&mut self, issuance_tx_id: &Id<Transaction>, token_id: &TokenId) -> crate::Result<()>;
        fn del_token_id(&mut self, issuance_tx_id: &Id<Transaction>) -> crate::Result<()>;

        fn set_accounting_undo_data(&mut self, id: Id<Block>, undo: &AccountingBlockUndo) -> crate::Result<()>;
        fn del_accounting_undo_data(&mut self, id: Id<Block>) -> crate::Result<()>;

        fn set_accounting_epoch_delta(
            &mut self,
            epoch_index: EpochIndex,
            delta: &PoSAccountingDeltaData,
        ) -> crate::Result<()>;
        fn del_accounting_epoch_delta(&mut self, epoch_index: EpochIndex) -> crate::Result<()>;

        fn set_accounting_epoch_undo_delta(
            &mut self,
            epoch_index: EpochIndex,
            undo: &DeltaMergeUndo,
        ) -> crate::Result<()>;
        fn del_accounting_epoch_undo_delta(&mut self, epoch_index: EpochIndex) -> crate::Result<()>;

        fn set_account_nonce_count(&mut self, account: AccountType, nonce: AccountNonce) -> crate::Result<()>;
        fn del_account_nonce_count(&mut self, account: AccountType) -> crate::Result<()>;
    }

    impl EpochStorageWrite for StoreTxRw {
        fn set_epoch_data(&mut self, epoch_index: u64, epoch_data: &EpochData) -> crate::Result<()>;
        fn del_epoch_data(&mut self, epoch_index: u64) -> crate::Result<()>;
    }

    impl UtxosStorageWrite for StoreTxRw {
        fn set_utxo(&mut self, outpoint: &UtxoOutPoint, entry: Utxo) -> crate::Result<()>;
        fn del_utxo(&mut self, outpoint: &UtxoOutPoint) -> crate::Result<()>;

        fn set_best_block_for_utxos(&mut self, block_id: &Id<GenBlock>) -> crate::Result<()>;

        fn set_undo_data(&mut self, id: Id<Block>, undo: &UtxosBlockUndo) -> crate::Result<()>;
        fn del_undo_data(&mut self, id: Id<Block>) -> crate::Result<()>;
    }

    impl PoSAccountingStorageWriteTip for StoreTxRw {
        fn set_pool_balance_tip(&mut self, pool_id: PoolId, amount: Amount) -> crate::Result<()>;
        fn del_pool_balance_tip(&mut self, pool_id: PoolId) -> crate::Result<()>;

        fn set_pool_data_tip(&mut self, pool_id: PoolId, pool_data: &PoolData) -> crate::Result<()>;
        fn del_pool_data_tip(&mut self, pool_id: PoolId) -> crate::Result<()>;

        fn set_delegation_balance_tip(
            &mut self,
            delegation_target: DelegationId,
            amount: Amount,
        ) -> crate::Result<()>;
        fn del_delegation_balance_tip(&mut self, delegation_target: DelegationId) -> crate::Result<()>;

        fn set_delegation_data_tip(
            &mut self,
            delegation_id: DelegationId,
            delegation_data: &DelegationData,
        ) -> crate::Result<()>;
        fn del_delegation_data_tip(&mut self, delegation_id: DelegationId) -> crate::Result<()>;

        fn set_pool_delegation_share_tip(
            &mut self,
            pool_id: PoolId,
            delegation_id: DelegationId,
            amount: Amount,
        ) -> crate::Result<()>;
        fn del_pool_delegation_share_tip(
            &mut self,
            pool_id: PoolId,
            delegation_id: DelegationId,
        ) -> crate::Result<()>;
    }

    impl PoSAccountingStorageWriteSealed for StoreTxRw {
        fn set_pool_balance_sealed(&mut self, pool_id: PoolId, amount: Amount) -> crate::Result<()>;
        fn del_pool_balance_sealed(&mut self, pool_id: PoolId) -> crate::Result<()>;

        fn set_pool_data_sealed(&mut self, pool_id: PoolId, pool_data: &PoolData) -> crate::Result<()>;
        fn del_pool_data_sealed(&mut self, pool_id: PoolId) -> crate::Result<()>;

        fn set_delegation_balance_sealed(
            &mut self,
            delegation_target: DelegationId,
            amount: Amount,
        ) -> crate::Result<()>;
        fn del_delegation_balance_sealed(
            &mut self,
            delegation_target: DelegationId,
        ) -> crate::Result<()>;

        fn set_delegation_data_sealed(
            &mut self,
            delegation_id: DelegationId,
            delegation_data: &DelegationData,
        ) -> crate::Result<()>;
        fn del_delegation_data_sealed(&mut self, delegation_id: DelegationId) -> crate::Result<()>;

        fn set_pool_delegation_share_sealed(
            &mut self,
            pool_id: PoolId,
            delegation_id: DelegationId,
            amount: Amount,
        ) -> crate::Result<()>;
        fn del_pool_delegation_share_sealed(
            &mut self,
            pool_id: PoolId,
            delegation_id: DelegationId,
        ) -> crate::Result<()>;
    }

    impl TokensAccountingStorageWrite for StoreTxRw {
        fn set_token_data(&mut self, id: &TokenId, data: &tokens_accounting::TokenData) -> crate::Result<()>;
        fn del_token_data(&mut self, id: &TokenId) -> crate::Result<()>;

        fn set_circulating_supply(&mut self, id: &TokenId, supply: &Amount) -> crate::Result<() >;
        fn del_circulating_supply(&mut self, id: &TokenId) -> crate::Result<()>;
    }

    impl crate::TransactionRw for StoreTxRw {
        fn abort(self);
        fn commit(self) -> crate::Result<()>;
    }

    impl crate::IsTransaction for StoreTxRw {}
}
