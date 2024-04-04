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

use std::collections::BTreeMap;

use chainstate_storage::{BlockchainStorageRead, ChainstateStorageVersion};
use chainstate_types::{storage_result, BlockIndex, EpochData, EpochStorageRead};
use common::{
    chain::{
        block::signed_block_header::SignedBlockHeader,
        config::{EpochIndex, MagicBytes},
        tokens::TokenId,
        Block, DelegationId, GenBlock, PoolId, Transaction, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, Id},
};
use pos_accounting::PoSAccountingStorageRead;
use tokens_accounting::{TokenData, TokensAccountingStorageRead};
use utxo::UtxosStorageRead;

use super::{FailingStorage, FailingStorageTxRw};

impl<T: BlockchainStorageRead> BlockchainStorageRead for FailingStorageTxRw<'_, T> {
    fn get_storage_version(&self) -> chainstate_storage::Result<Option<ChainstateStorageVersion>> {
        self.inner.get_storage_version()
    }

    fn get_magic_bytes(&self) -> chainstate_storage::Result<Option<MagicBytes>> {
        self.inner.get_magic_bytes()
    }

    fn get_chain_type(&self) -> chainstate_storage::Result<Option<String>> {
        self.inner.get_chain_type()
    }

    fn get_best_block_id(&self) -> chainstate_storage::Result<Option<Id<GenBlock>>> {
        self.inner.get_best_block_id()
    }

    fn get_block_index(
        &self,
        block_id: &Id<Block>,
    ) -> chainstate_storage::Result<Option<BlockIndex>> {
        self.inner.get_block_index(block_id)
    }

    fn get_block_reward(
        &self,
        block_index: &BlockIndex,
    ) -> chainstate_storage::Result<Option<common::chain::block::BlockReward>> {
        self.inner.get_block_reward(block_index)
    }

    fn get_block(&self, id: Id<Block>) -> chainstate_storage::Result<Option<Block>> {
        self.inner.get_block(id)
    }

    fn get_block_header(
        &self,
        id: Id<Block>,
    ) -> chainstate_storage::Result<Option<SignedBlockHeader>> {
        self.inner.get_block_header(id)
    }

    fn get_min_height_with_allowed_reorg(&self) -> chainstate_storage::Result<Option<BlockHeight>> {
        self.inner.get_min_height_with_allowed_reorg()
    }

    fn get_block_id_by_height(
        &self,
        height: &BlockHeight,
    ) -> chainstate_storage::Result<Option<Id<GenBlock>>> {
        self.inner.get_block_id_by_height(height)
    }

    fn get_undo_data(
        &self,
        id: Id<Block>,
    ) -> chainstate_storage::Result<Option<utxo::UtxosBlockUndo>> {
        self.inner.get_undo_data(id)
    }

    fn get_token_aux_data(
        &self,
        token_id: &TokenId,
    ) -> chainstate_storage::Result<Option<common::chain::tokens::TokenAuxiliaryData>> {
        self.inner.get_token_aux_data(token_id)
    }

    fn get_token_id(&self, tx_id: &Id<Transaction>) -> chainstate_storage::Result<Option<TokenId>> {
        self.inner.get_token_id(tx_id)
    }

    fn get_block_tree_by_height(
        &self,
        start_from: BlockHeight,
    ) -> chainstate_storage::Result<BTreeMap<BlockHeight, Vec<Id<Block>>>> {
        self.inner.get_block_tree_by_height(start_from)
    }

    fn get_tokens_accounting_undo(
        &self,
        id: Id<Block>,
    ) -> chainstate_storage::Result<Option<tokens_accounting::BlockUndo>> {
        self.inner.get_tokens_accounting_undo(id)
    }

    fn get_pos_accounting_undo(
        &self,
        id: Id<Block>,
    ) -> chainstate_storage::Result<Option<pos_accounting::BlockUndo>> {
        self.inner.get_pos_accounting_undo(id)
    }

    fn get_accounting_epoch_delta(
        &self,
        epoch_index: EpochIndex,
    ) -> chainstate_storage::Result<Option<pos_accounting::PoSAccountingDeltaData>> {
        self.inner.get_accounting_epoch_delta(epoch_index)
    }

    fn get_accounting_epoch_undo_delta(
        &self,
        epoch_index: EpochIndex,
    ) -> chainstate_storage::Result<Option<pos_accounting::DeltaMergeUndo>> {
        self.inner.get_accounting_epoch_undo_delta(epoch_index)
    }

    fn get_account_nonce_count(
        &self,
        account: common::chain::AccountType,
    ) -> chainstate_storage::Result<Option<common::chain::AccountNonce>> {
        self.inner.get_account_nonce_count(account)
    }
}

impl<T: EpochStorageRead> EpochStorageRead for FailingStorageTxRw<'_, T> {
    fn get_epoch_data(&self, epoch_index: EpochIndex) -> storage_result::Result<Option<EpochData>> {
        self.inner.get_epoch_data(epoch_index)
    }
}

impl<T: TokensAccountingStorageRead> TokensAccountingStorageRead for FailingStorageTxRw<'_, T> {
    type Error = T::Error;

    fn get_token_data(&self, id: &TokenId) -> Result<Option<TokenData>, Self::Error> {
        self.inner.get_token_data(id)
    }

    fn get_circulating_supply(&self, id: &TokenId) -> Result<Option<Amount>, Self::Error> {
        self.inner.get_circulating_supply(id)
    }
}

impl<Tag, T> PoSAccountingStorageRead<Tag> for FailingStorageTxRw<'_, T>
where
    T: PoSAccountingStorageRead<Tag>,
    Tag: pos_accounting::StorageTag,
{
    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, storage_result::Error> {
        self.inner.get_pool_balance(pool_id)
    }

    fn get_pool_data(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<pos_accounting::PoolData>, storage_result::Error> {
        self.inner.get_pool_data(pool_id)
    }

    fn get_delegation_balance(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, storage_result::Error> {
        self.inner.get_delegation_balance(delegation_id)
    }

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<pos_accounting::DelegationData>, storage_result::Error> {
        self.inner.get_delegation_data(delegation_id)
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, storage_result::Error> {
        self.inner.get_pool_delegations_shares(pool_id)
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, storage_result::Error> {
        self.inner.get_pool_delegation_share(pool_id, delegation_id)
    }
}

impl<T: UtxosStorageRead> UtxosStorageRead for FailingStorageTxRw<'_, T> {
    type Error = T::Error;

    fn get_utxo(&self, outpoint: &UtxoOutPoint) -> Result<Option<utxo::Utxo>, Self::Error> {
        self.inner.get_utxo(outpoint)
    }

    fn get_best_block_for_utxos(&self) -> Result<Id<GenBlock>, Self::Error> {
        self.inner.get_best_block_for_utxos()
    }
}

impl<Tag, T> PoSAccountingStorageRead<Tag> for FailingStorage<T>
where
    T: PoSAccountingStorageRead<Tag>,
    Tag: pos_accounting::StorageTag,
{
    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, storage_result::Error> {
        self.inner.get_pool_balance(pool_id)
    }

    fn get_pool_data(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<pos_accounting::PoolData>, storage_result::Error> {
        self.inner.get_pool_data(pool_id)
    }

    fn get_delegation_balance(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, storage_result::Error> {
        self.inner.get_delegation_balance(delegation_id)
    }

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<pos_accounting::DelegationData>, storage_result::Error> {
        self.inner.get_delegation_data(delegation_id)
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, storage_result::Error> {
        self.inner.get_pool_delegations_shares(pool_id)
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, storage_result::Error> {
        self.inner.get_pool_delegation_share(pool_id, delegation_id)
    }
}
