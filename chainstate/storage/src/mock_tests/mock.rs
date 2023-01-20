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

use chainstate_types::BlockIndex;
use common::chain::tokens::{TokenAuxiliaryData, TokenId};
use common::{
    chain::{
        block::BlockReward,
        transaction::{OutPointSourceId, Transaction, TxMainChainIndex, TxMainChainPosition},
        Block, GenBlock, OutPoint,
    },
    primitives::{Amount, BlockHeight, Id},
};
use pos_accounting::{
    AccountingBlockUndo, DelegationData, DelegationId, DeltaMergeUndo, PoSAccountingDeltaData,
    PoolData, PoolId,
};
use utxo::{Utxo, UtxosBlockUndo, UtxosStorageRead, UtxosStorageWrite};

use super::mock_accounting::{
    PoSAccountingStorageReadSealed, PoSAccountingStorageReadTip, PoSAccountingStorageWriteSealed,
    PoSAccountingStorageWriteTip,
};

mockall::mock! {
    /// A mock object for blockchain storage
    pub Store {}

    impl crate::BlockchainStorageRead for Store {
        fn get_storage_version(&self) -> crate::Result<u32>;
        fn get_best_block_id(&self) -> crate::Result<Option<Id<GenBlock>>>;
        fn get_block_index(&self, id: &Id<Block>) -> crate::Result<Option<BlockIndex>>;
        fn get_block(&self, id: Id<Block>) -> crate::Result<Option<Block>>;
        fn get_block_reward(&self, block_index: &BlockIndex) -> crate::Result<Option<BlockReward>>;

        fn get_is_mainchain_tx_index_enabled(&self) -> crate::Result<Option<bool>>;
        fn get_mainchain_tx_index(
            &self,
            tx_id: &OutPointSourceId,
        ) -> crate::Result<Option<TxMainChainIndex>>;


        fn get_mainchain_tx_by_position(
            &self,
            tx_index: &TxMainChainPosition,
        ) -> crate::Result<Option<Transaction>>;

        fn get_block_id_by_height(
            &self,
            height: &BlockHeight,
        ) -> crate::Result<Option<Id<GenBlock>>>;

        fn get_token_aux_data(&self, token_id: &TokenId) -> crate::Result<Option<TokenAuxiliaryData>>;

        fn get_token_id(&self, tx_id: &Id<Transaction>) -> crate::Result<Option<TokenId>>;

        fn get_block_tree_by_height(
            &self,
        ) -> crate::Result<BTreeMap<BlockHeight, Vec<Id<Block>>>>;

        fn get_accounting_undo(&self, id: Id<Block>) -> crate::Result<Option<AccountingBlockUndo>>;

        fn get_pre_seal_accounting_delta(
            &self,
            epoch_index: u64,
        ) -> crate::Result<Option<PoSAccountingDeltaData>>;

        fn get_pre_seal_accounting_delta_undo(
            &self,
            epoch_index: u64,
            id: Id<Block>,
        ) -> crate::Result<Option<DeltaMergeUndo>>;
    }

    impl UtxosStorageRead for Store {
        fn get_utxo(&self, outpoint: &OutPoint) -> crate::Result<Option<Utxo>>;
        fn get_best_block_for_utxos(&self) -> crate::Result<Option<Id<GenBlock>>>;
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

    impl crate::BlockchainStorageWrite for Store {
        fn set_storage_version(&mut self, version: u32) -> crate::Result<()>;
        fn set_best_block_id(&mut self, id: &Id<GenBlock>) -> crate::Result<()>;
        fn set_block_index(&mut self, block_index: &BlockIndex) -> crate::Result<()>;
        fn add_block(&mut self, block: &Block) -> crate::Result<()>;
        fn del_block(&mut self, id: Id<Block>) -> crate::Result<()>;
        fn set_is_mainchain_tx_index_enabled(&mut self, enabled: bool) -> crate::Result<()>;
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

        fn set_pre_seal_accounting_delta(
            &mut self,
            epoch_index: u64,
            delta: &PoSAccountingDeltaData,
        ) -> crate::Result<()>;
        fn del_pre_seal_accounting_delta(&mut self, epoch_index: u64) -> crate::Result<()>;

        fn set_pre_seal_accounting_delta_undo(
            &mut self,
            epoch_index: u64,
            id: Id<Block>,
            delta: &pos_accounting::DeltaMergeUndo,
        ) -> crate::Result<()>;
        fn del_pre_seal_accounting_delta_undo(&mut self,
            epoch_index: u64,
            id: Id<Block>
        ) -> crate::Result<()>;
        fn del_epoch_pre_seal_accounting_delta_undo(&mut self, epoch_index: u64) -> crate::Result<()>;
    }

    impl UtxosStorageWrite for Store {
        fn set_utxo(&mut self, outpoint: &OutPoint, entry: Utxo) -> crate::Result<()>;
        fn del_utxo(&mut self, outpoint: &OutPoint) -> crate::Result<()>;

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
        fn get_storage_version(&self) -> crate::Result<u32>;
        fn get_best_block_id(&self) -> crate::Result<Option<Id<GenBlock>>>;
        fn get_block_index(&self, id: &Id<Block>) -> crate::Result<Option<BlockIndex>>;
        fn get_block(&self, id: Id<Block>) -> crate::Result<Option<Block>>;
        fn get_block_reward(&self, block_index: &BlockIndex) -> crate::Result<Option<BlockReward>>;

        fn get_is_mainchain_tx_index_enabled(&self) -> crate::Result<Option<bool>>;
        fn get_mainchain_tx_index(
            &self,
            tx_id: &OutPointSourceId,
        ) -> crate::Result<Option<TxMainChainIndex>>;

        fn get_mainchain_tx_by_position(
            &self,
            tx_index: &TxMainChainPosition,
        ) -> crate::Result<Option<Transaction>>;

        fn get_block_id_by_height(
            &self,
            height: &BlockHeight,
        ) -> crate::Result<Option<Id<GenBlock>>>;

        fn get_token_aux_data(&self, token_id: &TokenId) -> crate::Result<Option<TokenAuxiliaryData>>;
        fn get_token_id(&self, tx_id: &Id<Transaction>) -> crate::Result<Option<TokenId>>;
        fn get_block_tree_by_height(
            &self,
        ) -> crate::Result<BTreeMap<BlockHeight, Vec<Id<Block>>>>;

        fn get_accounting_undo(&self, id: Id<Block>) -> crate::Result<Option<AccountingBlockUndo>>;

        fn get_pre_seal_accounting_delta(
            &self,
            epoch_index: u64,
        ) -> crate::Result<Option<PoSAccountingDeltaData>>;

        fn get_pre_seal_accounting_delta_undo(
            &self,
            epoch_index: u64,
            id: Id<Block>,
        ) -> crate::Result<Option<DeltaMergeUndo>>;
    }

    impl crate::UtxosStorageRead for StoreTxRo {
        fn get_utxo(&self, outpoint: &OutPoint) -> crate::Result<Option<Utxo>>;
        fn get_best_block_for_utxos(&self) -> crate::Result<Option<Id<GenBlock>>>;
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

    impl crate::TransactionRo for StoreTxRo {
        fn close(self);
    }

    impl crate::IsTransaction for StoreTxRo {}
}

mockall::mock! {
    /// A mock object for blockchain storage transaction
    pub StoreTxRw {}

    impl crate::BlockchainStorageRead for StoreTxRw {
        fn get_storage_version(&self) -> crate::Result<u32>;
        fn get_best_block_id(&self) -> crate::Result<Option<Id<GenBlock>>>;
        fn get_block(&self, id: Id<Block>) -> crate::Result<Option<Block>>;
        fn get_block_index(&self, id: &Id<Block>) -> crate::Result<Option<BlockIndex>>;
        fn get_block_reward(&self, block_index: &BlockIndex) -> crate::Result<Option<BlockReward>>;

        fn get_is_mainchain_tx_index_enabled(&self) -> crate::Result<Option<bool>>;

        fn get_mainchain_tx_index(
            &self,
            tx_id: &OutPointSourceId,
        ) -> crate::Result<Option<TxMainChainIndex>>;

        fn get_mainchain_tx_by_position(
            &self,
            tx_index: &TxMainChainPosition,
        ) -> crate::Result<Option<Transaction>>;

        fn get_block_id_by_height(
            &self,
            height: &BlockHeight,
        ) -> crate::Result<Option<Id<GenBlock>>>;

        fn get_token_aux_data(&self, token_id: &TokenId) -> crate::Result<Option<TokenAuxiliaryData>>;
        fn get_token_id(&self, tx_id: &Id<Transaction>) -> crate::Result<Option<TokenId>>;
        fn get_block_tree_by_height(
            &self,
        ) -> crate::Result<BTreeMap<BlockHeight, Vec<Id<Block>>>>;

        fn get_accounting_undo(&self, id: Id<Block>) -> crate::Result<Option<AccountingBlockUndo>>;

        fn get_pre_seal_accounting_delta(
            &self,
            epoch_index: u64,
        ) -> crate::Result<Option<PoSAccountingDeltaData>>;

        fn get_pre_seal_accounting_delta_undo(
            &self,
            epoch_index: u64,
            id: Id<Block>,
        ) -> crate::Result<Option<DeltaMergeUndo>>;
    }

    impl UtxosStorageRead for StoreTxRw {
        fn get_utxo(&self, outpoint: &OutPoint) -> crate::Result<Option<Utxo>>;
        fn get_best_block_for_utxos(&self) -> crate::Result<Option<Id<GenBlock>>>;
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

    impl crate::BlockchainStorageWrite for StoreTxRw {
        fn set_storage_version(&mut self, version: u32) -> crate::Result<()>;
        fn set_best_block_id(&mut self, id: &Id<GenBlock>) -> crate::Result<()>;
        fn set_block_index(&mut self, block_index: &BlockIndex) -> crate::Result<()>;
        fn add_block(&mut self, block: &Block) -> crate::Result<()>;
        fn del_block(&mut self, id: Id<Block>) -> crate::Result<()>;

        fn set_is_mainchain_tx_index_enabled(&mut self, enabled: bool) -> crate::Result<()>;
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

        fn set_pre_seal_accounting_delta(
            &mut self,
            epoch_index: u64,
            delta: &PoSAccountingDeltaData,
        ) -> crate::Result<()>;
        fn del_pre_seal_accounting_delta(&mut self, epoch_index: u64) -> crate::Result<()>;

        fn set_pre_seal_accounting_delta_undo(
            &mut self,
            epoch_index: u64,
            id: Id<Block>,
            delta: &pos_accounting::DeltaMergeUndo,
        ) -> crate::Result<()>;
        fn del_pre_seal_accounting_delta_undo(&mut self,
            epoch_index: u64,
            id: Id<Block>
        ) -> crate::Result<()>;
        fn del_epoch_pre_seal_accounting_delta_undo(&mut self, epoch_index: u64) -> crate::Result<()>;
    }

    impl UtxosStorageWrite for StoreTxRw {
        fn set_utxo(&mut self, outpoint: &OutPoint, entry: Utxo) -> crate::Result<()>;
        fn del_utxo(&mut self, outpoint: &OutPoint) -> crate::Result<()>;

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

    impl crate::TransactionRw for StoreTxRw {
        fn abort(self);
        fn commit(self) -> crate::Result<()>;
    }

    impl crate::IsTransaction for StoreTxRw {}
}
