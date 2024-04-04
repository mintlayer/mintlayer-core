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

use chainstate_storage::{BlockchainStorageWrite, ChainstateStorageVersion};
use chainstate_types::{storage_result, BlockIndex, EpochData, EpochStorageWrite};
use common::{
    chain::{
        config::{EpochIndex, MagicBytes},
        tokens::TokenId,
        Block, DelegationId, GenBlock, PoolId, Transaction, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, Id},
};
use pos_accounting::PoSAccountingStorageWrite;
use tokens_accounting::{TokenData, TokensAccountingStorageWrite};
use utxo::UtxosStorageWrite;

use super::{FailingStorage, FailingStorageTxRw};

impl<T: BlockchainStorageWrite> BlockchainStorageWrite for FailingStorageTxRw<'_, T> {
    fn set_storage_version(
        &mut self,
        version: ChainstateStorageVersion,
    ) -> chainstate_storage::Result<()> {
        self.inner.set_storage_version(version)
    }

    fn set_magic_bytes(&mut self, bytes: &MagicBytes) -> chainstate_storage::Result<()> {
        self.inner.set_magic_bytes(bytes)
    }

    fn set_chain_type(&mut self, chain: &str) -> chainstate_storage::Result<()> {
        self.inner.set_chain_type(chain)
    }

    fn set_best_block_id(&mut self, id: &Id<GenBlock>) -> chainstate_storage::Result<()> {
        self.inner.set_best_block_id(id)
    }

    fn set_block_index(&mut self, block_index: &BlockIndex) -> chainstate_storage::Result<()> {
        self.inner.set_block_index(block_index)
    }

    fn del_block_index(&mut self, block_id: Id<Block>) -> chainstate_storage::Result<()> {
        self.inner.del_block_index(block_id)
    }

    fn add_block(&mut self, block: &Block) -> chainstate_storage::Result<()> {
        self.spurious_map_full_failure()?;
        self.inner.add_block(block)
    }

    fn del_block(&mut self, id: Id<Block>) -> chainstate_storage::Result<()> {
        self.inner.del_block(id)
    }

    fn set_min_height_with_allowed_reorg(
        &mut self,
        height: BlockHeight,
    ) -> chainstate_storage::Result<()> {
        self.inner.set_min_height_with_allowed_reorg(height)
    }

    fn set_block_id_at_height(
        &mut self,
        height: &BlockHeight,
        block_id: &Id<GenBlock>,
    ) -> chainstate_storage::Result<()> {
        self.inner.set_block_id_at_height(height, block_id)
    }

    fn del_block_id_at_height(&mut self, height: &BlockHeight) -> chainstate_storage::Result<()> {
        self.inner.del_block_id_at_height(height)
    }

    fn set_undo_data(
        &mut self,
        id: Id<Block>,
        undo: &utxo::UtxosBlockUndo,
    ) -> chainstate_storage::Result<()> {
        self.inner.set_undo_data(id, undo)
    }

    fn del_undo_data(&mut self, id: Id<Block>) -> chainstate_storage::Result<()> {
        self.inner.del_undo_data(id)
    }

    fn set_token_aux_data(
        &mut self,
        token_id: &TokenId,
        data: &common::chain::tokens::TokenAuxiliaryData,
    ) -> chainstate_storage::Result<()> {
        self.inner.set_token_aux_data(token_id, data)
    }

    fn del_token_aux_data(&mut self, token_id: &TokenId) -> chainstate_storage::Result<()> {
        self.inner.del_token_aux_data(token_id)
    }

    fn set_token_id(
        &mut self,
        issuance_tx_id: &Id<Transaction>,
        token_id: &TokenId,
    ) -> chainstate_storage::Result<()> {
        self.inner.set_token_id(issuance_tx_id, token_id)
    }

    fn del_token_id(&mut self, issuance_tx_id: &Id<Transaction>) -> chainstate_storage::Result<()> {
        self.inner.del_token_id(issuance_tx_id)
    }

    fn set_tokens_accounting_undo_data(
        &mut self,
        id: Id<Block>,
        undo: &tokens_accounting::BlockUndo,
    ) -> chainstate_storage::Result<()> {
        self.inner.set_tokens_accounting_undo_data(id, undo)
    }

    fn del_tokens_accounting_undo_data(&mut self, id: Id<Block>) -> chainstate_storage::Result<()> {
        self.inner.del_tokens_accounting_undo_data(id)
    }

    fn set_pos_accounting_undo_data(
        &mut self,
        id: Id<Block>,
        undo: &pos_accounting::BlockUndo,
    ) -> chainstate_storage::Result<()> {
        self.inner.set_pos_accounting_undo_data(id, undo)
    }

    fn del_pos_accounting_undo_data(&mut self, id: Id<Block>) -> chainstate_storage::Result<()> {
        self.inner.del_pos_accounting_undo_data(id)
    }

    fn set_accounting_epoch_delta(
        &mut self,
        epoch_index: EpochIndex,
        delta: &pos_accounting::PoSAccountingDeltaData,
    ) -> chainstate_storage::Result<()> {
        self.inner.set_accounting_epoch_delta(epoch_index, delta)
    }

    fn del_accounting_epoch_delta(
        &mut self,
        epoch_index: EpochIndex,
    ) -> chainstate_storage::Result<()> {
        self.inner.del_accounting_epoch_delta(epoch_index)
    }

    fn set_accounting_epoch_undo_delta(
        &mut self,
        epoch_index: EpochIndex,
        undo: &pos_accounting::DeltaMergeUndo,
    ) -> chainstate_storage::Result<()> {
        self.inner.set_accounting_epoch_undo_delta(epoch_index, undo)
    }

    fn del_accounting_epoch_undo_delta(
        &mut self,
        epoch_index: EpochIndex,
    ) -> chainstate_storage::Result<()> {
        self.inner.del_accounting_epoch_undo_delta(epoch_index)
    }

    fn set_account_nonce_count(
        &mut self,
        account: common::chain::AccountType,
        nonce: common::chain::AccountNonce,
    ) -> chainstate_storage::Result<()> {
        self.inner.set_account_nonce_count(account, nonce)
    }

    fn del_account_nonce_count(
        &mut self,
        account: common::chain::AccountType,
    ) -> chainstate_storage::Result<()> {
        self.inner.del_account_nonce_count(account)
    }
}

impl<T: EpochStorageWrite> EpochStorageWrite for FailingStorageTxRw<'_, T> {
    fn set_epoch_data(
        &mut self,
        epoch_index: EpochIndex,
        epoch_data: &EpochData,
    ) -> storage_result::Result<()> {
        self.inner.set_epoch_data(epoch_index, epoch_data)
    }

    fn del_epoch_data(&mut self, epoch_index: EpochIndex) -> storage_result::Result<()> {
        self.inner.del_epoch_data(epoch_index)
    }
}

impl<T: TokensAccountingStorageWrite> TokensAccountingStorageWrite for FailingStorageTxRw<'_, T> {
    fn set_token_data(&mut self, id: &TokenId, data: &TokenData) -> Result<(), Self::Error> {
        self.inner.set_token_data(id, data)
    }

    fn del_token_data(&mut self, id: &TokenId) -> Result<(), Self::Error> {
        self.inner.del_token_data(id)
    }

    fn set_circulating_supply(&mut self, id: &TokenId, supply: &Amount) -> Result<(), Self::Error> {
        self.inner.set_circulating_supply(id, supply)
    }

    fn del_circulating_supply(&mut self, id: &TokenId) -> Result<(), Self::Error> {
        self.inner.del_circulating_supply(id)
    }
}

impl<Tag, T> PoSAccountingStorageWrite<Tag> for FailingStorageTxRw<'_, T>
where
    T: PoSAccountingStorageWrite<Tag>,
    Tag: pos_accounting::StorageTag,
{
    fn set_pool_balance(
        &mut self,
        pool_id: PoolId,
        amount: Amount,
    ) -> Result<(), storage_result::Error> {
        self.inner.set_pool_balance(pool_id, amount)
    }

    fn del_pool_balance(&mut self, pool_id: PoolId) -> Result<(), storage_result::Error> {
        self.inner.del_pool_balance(pool_id)
    }

    fn set_pool_data(
        &mut self,
        pool_id: PoolId,
        pool_data: &pos_accounting::PoolData,
    ) -> Result<(), storage_result::Error> {
        self.inner.set_pool_data(pool_id, pool_data)
    }

    fn del_pool_data(&mut self, pool_id: PoolId) -> Result<(), storage_result::Error> {
        self.inner.del_pool_data(pool_id)
    }

    fn set_delegation_balance(
        &mut self,
        delegation_target: DelegationId,
        amount: Amount,
    ) -> Result<(), storage_result::Error> {
        self.inner.set_delegation_balance(delegation_target, amount)
    }

    fn del_delegation_balance(
        &mut self,
        delegation_target: DelegationId,
    ) -> Result<(), storage_result::Error> {
        self.inner.del_delegation_balance(delegation_target)
    }

    fn set_delegation_data(
        &mut self,
        delegation_id: DelegationId,
        delegation_data: &pos_accounting::DelegationData,
    ) -> Result<(), storage_result::Error> {
        self.inner.set_delegation_data(delegation_id, delegation_data)
    }

    fn del_delegation_data(
        &mut self,
        delegation_id: DelegationId,
    ) -> Result<(), storage_result::Error> {
        self.inner.del_delegation_data(delegation_id)
    }

    fn set_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
        amount: Amount,
    ) -> Result<(), storage_result::Error> {
        self.inner.set_pool_delegation_share(pool_id, delegation_id, amount)
    }

    fn del_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<(), storage_result::Error> {
        self.inner.del_pool_delegation_share(pool_id, delegation_id)
    }
}

impl<T: UtxosStorageWrite> UtxosStorageWrite for FailingStorageTxRw<'_, T> {
    fn set_utxo(&mut self, outpoint: &UtxoOutPoint, entry: utxo::Utxo) -> Result<(), Self::Error> {
        self.inner.set_utxo(outpoint, entry)
    }

    fn del_utxo(&mut self, outpoint: &UtxoOutPoint) -> Result<(), Self::Error> {
        self.inner.del_utxo(outpoint)
    }

    fn set_best_block_for_utxos(&mut self, block_id: &Id<GenBlock>) -> Result<(), Self::Error> {
        self.inner.set_best_block_for_utxos(block_id)
    }
}

impl<Tag, T> PoSAccountingStorageWrite<Tag> for FailingStorage<T>
where
    T: PoSAccountingStorageWrite<Tag>,
    Tag: pos_accounting::StorageTag,
{
    fn set_pool_balance(
        &mut self,
        pool_id: PoolId,
        amount: Amount,
    ) -> Result<(), storage_result::Error> {
        self.inner.set_pool_balance(pool_id, amount)
    }

    fn del_pool_balance(&mut self, pool_id: PoolId) -> Result<(), storage_result::Error> {
        self.inner.del_pool_balance(pool_id)
    }

    fn set_pool_data(
        &mut self,
        pool_id: PoolId,
        pool_data: &pos_accounting::PoolData,
    ) -> Result<(), storage_result::Error> {
        self.inner.set_pool_data(pool_id, pool_data)
    }

    fn del_pool_data(&mut self, pool_id: PoolId) -> Result<(), storage_result::Error> {
        self.inner.del_pool_data(pool_id)
    }

    fn set_delegation_balance(
        &mut self,
        delegation_target: DelegationId,
        amount: Amount,
    ) -> Result<(), storage_result::Error> {
        self.inner.set_delegation_balance(delegation_target, amount)
    }

    fn del_delegation_balance(
        &mut self,
        delegation_target: DelegationId,
    ) -> Result<(), storage_result::Error> {
        self.inner.del_delegation_balance(delegation_target)
    }

    fn set_delegation_data(
        &mut self,
        delegation_id: DelegationId,
        delegation_data: &pos_accounting::DelegationData,
    ) -> Result<(), storage_result::Error> {
        self.inner.set_delegation_data(delegation_id, delegation_data)
    }

    fn del_delegation_data(
        &mut self,
        delegation_id: DelegationId,
    ) -> Result<(), storage_result::Error> {
        self.inner.del_delegation_data(delegation_id)
    }

    fn set_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
        amount: Amount,
    ) -> Result<(), storage_result::Error> {
        self.inner.set_pool_delegation_share(pool_id, delegation_id, amount)
    }

    fn del_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<(), storage_result::Error> {
        self.inner.del_pool_delegation_share(pool_id, delegation_id)
    }
}
