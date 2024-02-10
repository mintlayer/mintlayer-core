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

use super::{well_known, StoreTxRw};
use crate::{BlockchainStorageWrite, ChainstateStorageVersion, SealedStorageTag, TipStorageTag};
use chainstate_types::{BlockIndex, EpochData, EpochStorageWrite};
use common::{
    chain::{
        config::EpochIndex,
        tokens::{TokenAuxiliaryData, TokenId},
        AccountNonce, AccountType, Block, DelegationId, GenBlock, PoolId, Transaction,
        UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, Id, Idable},
};
use pos_accounting::{
    AccountingBlockUndo, DelegationData, DeltaMergeUndo, PoSAccountingDeltaData,
    PoSAccountingStorageWrite, PoolData,
};
use tokens_accounting::TokensAccountingStorageWrite;
use utxo::{Utxo, UtxosBlockUndo, UtxosStorageWrite};

use super::db;

impl<'st, B: storage::Backend> BlockchainStorageWrite for StoreTxRw<'st, B> {
    fn set_storage_version(&mut self, version: ChainstateStorageVersion) -> crate::Result<()> {
        self.write_value::<well_known::StoreVersion>(&version)
    }

    fn set_magic_bytes(&mut self, bytes: &[u8; 4]) -> crate::Result<()> {
        self.write_value::<well_known::MagicBytes>(bytes)
    }

    fn set_chain_type(&mut self, chain: &str) -> crate::Result<()> {
        self.write_value::<well_known::ChainType>(&chain.to_owned())
    }

    fn set_best_block_id(&mut self, id: &Id<GenBlock>) -> crate::Result<()> {
        self.write_value::<well_known::BestBlockId>(id)
    }

    fn add_block(&mut self, block: &Block) -> crate::Result<()> {
        self.write::<db::DBBlock, _, _, _>(block.get_id(), block)
    }

    fn del_block(&mut self, id: Id<Block>) -> crate::Result<()> {
        self.0.get_mut::<db::DBBlock, _>().del(id).map_err(Into::into)
    }

    fn set_block_index(&mut self, block_index: &BlockIndex) -> crate::Result<()> {
        self.write::<db::DBBlockIndex, _, _, _>(block_index.block_id(), block_index)
    }

    fn set_min_height_with_allowed_reorg(&mut self, height: BlockHeight) -> crate::Result<()> {
        self.write_value::<well_known::MinHeightForReorg>(&height)
    }

    fn set_block_id_at_height(
        &mut self,
        height: &BlockHeight,
        block_id: &Id<GenBlock>,
    ) -> crate::Result<()> {
        self.write::<db::DBBlockByHeight, _, _, _>(height, block_id)
    }

    fn del_block_id_at_height(&mut self, height: &BlockHeight) -> crate::Result<()> {
        self.0.get_mut::<db::DBBlockByHeight, _>().del(height).map_err(Into::into)
    }

    fn set_undo_data(&mut self, id: Id<Block>, undo: &UtxosBlockUndo) -> crate::Result<()> {
        self.write::<db::DBUtxosBlockUndo, _, _, _>(id, undo)
    }

    fn del_undo_data(&mut self, id: Id<Block>) -> crate::Result<()> {
        self.0.get_mut::<db::DBUtxosBlockUndo, _>().del(id).map_err(Into::into)
    }

    fn set_token_aux_data(
        &mut self,
        token_id: &TokenId,
        data: &TokenAuxiliaryData,
    ) -> crate::Result<()> {
        self.write::<db::DBTokensAuxData, _, _, _>(token_id, &data)
    }

    fn del_token_aux_data(&mut self, token_id: &TokenId) -> crate::Result<()> {
        self.0.get_mut::<db::DBTokensAuxData, _>().del(&token_id).map_err(Into::into)
    }

    fn set_token_id(
        &mut self,
        issuance_tx_id: &Id<Transaction>,
        token_id: &TokenId,
    ) -> crate::Result<()> {
        self.write::<db::DBIssuanceTxVsTokenId, _, _, _>(issuance_tx_id, token_id)
    }

    fn del_token_id(&mut self, issuance_tx_id: &Id<Transaction>) -> crate::Result<()> {
        self.0
            .get_mut::<db::DBIssuanceTxVsTokenId, _>()
            .del(&issuance_tx_id)
            .map_err(Into::into)
    }

    fn set_tokens_accounting_undo_data(
        &mut self,
        id: Id<Block>,
        undo: &tokens_accounting::BlockUndo,
    ) -> crate::Result<()> {
        self.write::<db::DBTokensAccountingBlockUndo, _, _, _>(id, undo)
    }

    fn del_tokens_accounting_undo_data(&mut self, id: Id<Block>) -> crate::Result<()> {
        self.0
            .get_mut::<db::DBTokensAccountingBlockUndo, _>()
            .del(id)
            .map_err(Into::into)
    }

    fn set_accounting_undo_data(
        &mut self,
        id: Id<Block>,
        undo: &AccountingBlockUndo,
    ) -> crate::Result<()> {
        self.write::<db::DBAccountingBlockUndo, _, _, _>(id, undo)
    }

    fn del_accounting_undo_data(&mut self, id: Id<Block>) -> crate::Result<()> {
        self.0.get_mut::<db::DBAccountingBlockUndo, _>().del(id).map_err(Into::into)
    }

    fn set_accounting_epoch_delta(
        &mut self,
        epoch_index: EpochIndex,
        delta: &PoSAccountingDeltaData,
    ) -> crate::Result<()> {
        self.write::<db::DBAccountingEpochDelta, _, _, _>(epoch_index, delta)
    }

    fn del_accounting_epoch_delta(&mut self, epoch_index: EpochIndex) -> crate::Result<()> {
        self.0
            .get_mut::<db::DBAccountingEpochDelta, _>()
            .del(epoch_index)
            .map_err(Into::into)
    }

    fn set_accounting_epoch_undo_delta(
        &mut self,
        epoch_index: EpochIndex,
        undo: &DeltaMergeUndo,
    ) -> crate::Result<()> {
        self.write::<db::DBAccountingEpochDeltaUndo, _, _, _>(epoch_index, undo)
    }

    fn del_accounting_epoch_undo_delta(&mut self, epoch_index: EpochIndex) -> crate::Result<()> {
        self.0
            .get_mut::<db::DBAccountingEpochDeltaUndo, _>()
            .del(epoch_index)
            .map_err(Into::into)
    }

    fn set_account_nonce_count(
        &mut self,
        account: AccountType,
        nonce: AccountNonce,
    ) -> crate::Result<()> {
        self.write::<db::DBAccountNonceCount, _, _, _>(account, nonce)
    }

    fn del_account_nonce_count(&mut self, account: AccountType) -> crate::Result<()> {
        self.0.get_mut::<db::DBAccountNonceCount, _>().del(account).map_err(Into::into)
    }
}

impl<'st, B: storage::Backend> EpochStorageWrite for StoreTxRw<'st, B> {
    fn set_epoch_data(&mut self, epoch_index: u64, epoch_data: &EpochData) -> crate::Result<()> {
        self.write::<db::DBEpochData, _, _, _>(epoch_index, epoch_data)
    }

    fn del_epoch_data(&mut self, epoch_index: u64) -> crate::Result<()> {
        self.0.get_mut::<db::DBEpochData, _>().del(epoch_index).map_err(Into::into)
    }
}

impl<'st, B: storage::Backend> UtxosStorageWrite for StoreTxRw<'st, B> {
    fn set_utxo(&mut self, outpoint: &UtxoOutPoint, entry: Utxo) -> crate::Result<()> {
        self.write::<db::DBUtxo, _, _, _>(outpoint, entry)
    }

    fn del_utxo(&mut self, outpoint: &UtxoOutPoint) -> crate::Result<()> {
        self.0.get_mut::<db::DBUtxo, _>().del(outpoint).map_err(Into::into)
    }

    fn set_best_block_for_utxos(&mut self, block_id: &Id<GenBlock>) -> crate::Result<()> {
        self.write_value::<well_known::UtxosBestBlockId>(block_id)
    }
}

impl<'st, B: storage::Backend> PoSAccountingStorageWrite<TipStorageTag> for StoreTxRw<'st, B> {
    fn set_pool_balance(&mut self, pool_id: PoolId, amount: Amount) -> crate::Result<()> {
        self.write::<db::DBAccountingPoolBalancesTip, _, _, _>(pool_id, amount)
    }

    fn del_pool_balance(&mut self, pool_id: PoolId) -> crate::Result<()> {
        self.0
            .get_mut::<db::DBAccountingPoolBalancesTip, _>()
            .del(pool_id)
            .map_err(Into::into)
    }

    fn set_pool_data(&mut self, pool_id: PoolId, pool_data: &PoolData) -> crate::Result<()> {
        self.write::<db::DBAccountingPoolDataTip, _, _, _>(pool_id, pool_data)
    }

    fn del_pool_data(&mut self, pool_id: PoolId) -> crate::Result<()> {
        self.0
            .get_mut::<db::DBAccountingPoolDataTip, _>()
            .del(pool_id)
            .map_err(Into::into)
    }

    fn set_delegation_balance(
        &mut self,
        delegation_target: DelegationId,
        amount: Amount,
    ) -> crate::Result<()> {
        self.write::<db::DBAccountingDelegationBalancesTip, _, _, _>(delegation_target, amount)
    }

    fn del_delegation_balance(&mut self, delegation_target: DelegationId) -> crate::Result<()> {
        self.0
            .get_mut::<db::DBAccountingDelegationBalancesTip, _>()
            .del(delegation_target)
            .map_err(Into::into)
    }

    fn set_delegation_data(
        &mut self,
        delegation_id: DelegationId,
        delegation_data: &DelegationData,
    ) -> crate::Result<()> {
        self.write::<db::DBAccountingDelegationDataTip, _, _, _>(delegation_id, delegation_data)
    }

    fn del_delegation_data(&mut self, delegation_id: DelegationId) -> crate::Result<()> {
        self.0
            .get_mut::<db::DBAccountingDelegationDataTip, _>()
            .del(delegation_id)
            .map_err(Into::into)
    }

    fn set_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
        amount: Amount,
    ) -> crate::Result<()> {
        self.write::<db::DBAccountingPoolDelegationSharesTip, _, _, _>(
            (pool_id, delegation_id),
            amount,
        )
    }

    fn del_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> crate::Result<()> {
        self.0
            .get_mut::<db::DBAccountingPoolDelegationSharesTip, _>()
            .del((pool_id, delegation_id))
            .map_err(Into::into)
    }
}

impl<'st, B: storage::Backend> PoSAccountingStorageWrite<SealedStorageTag> for StoreTxRw<'st, B> {
    fn set_pool_balance(&mut self, pool_id: PoolId, amount: Amount) -> crate::Result<()> {
        self.write::<db::DBAccountingPoolBalancesSealed, _, _, _>(pool_id, amount)
    }

    fn del_pool_balance(&mut self, pool_id: PoolId) -> crate::Result<()> {
        self.0
            .get_mut::<db::DBAccountingPoolBalancesSealed, _>()
            .del(pool_id)
            .map_err(Into::into)
    }

    fn set_pool_data(&mut self, pool_id: PoolId, pool_data: &PoolData) -> crate::Result<()> {
        self.write::<db::DBAccountingPoolDataSealed, _, _, _>(pool_id, pool_data)
    }

    fn del_pool_data(&mut self, pool_id: PoolId) -> crate::Result<()> {
        self.0
            .get_mut::<db::DBAccountingPoolDataSealed, _>()
            .del(pool_id)
            .map_err(Into::into)
    }

    fn set_delegation_balance(
        &mut self,
        delegation_target: DelegationId,
        amount: Amount,
    ) -> crate::Result<()> {
        self.write::<db::DBAccountingDelegationBalancesSealed, _, _, _>(delegation_target, amount)
    }

    fn del_delegation_balance(&mut self, delegation_target: DelegationId) -> crate::Result<()> {
        self.0
            .get_mut::<db::DBAccountingDelegationBalancesSealed, _>()
            .del(delegation_target)
            .map_err(Into::into)
    }

    fn set_delegation_data(
        &mut self,
        delegation_id: DelegationId,
        delegation_data: &DelegationData,
    ) -> crate::Result<()> {
        self.write::<db::DBAccountingDelegationDataSealed, _, _, _>(delegation_id, delegation_data)
    }

    fn del_delegation_data(&mut self, delegation_id: DelegationId) -> crate::Result<()> {
        self.0
            .get_mut::<db::DBAccountingDelegationDataSealed, _>()
            .del(delegation_id)
            .map_err(Into::into)
    }

    fn set_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
        amount: Amount,
    ) -> crate::Result<()> {
        self.write::<db::DBAccountingPoolDelegationSharesSealed, _, _, _>(
            (pool_id, delegation_id),
            amount,
        )
    }

    fn del_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> crate::Result<()> {
        self.0
            .get_mut::<db::DBAccountingPoolDelegationSharesSealed, _>()
            .del((pool_id, delegation_id))
            .map_err(Into::into)
    }
}

impl<'st, B: storage::Backend> TokensAccountingStorageWrite for StoreTxRw<'st, B> {
    fn set_token_data(
        &mut self,
        id: &TokenId,
        data: &tokens_accounting::TokenData,
    ) -> crate::Result<()> {
        self.write::<db::DBTokensData, _, _, _>(id, data)
    }

    fn del_token_data(&mut self, id: &TokenId) -> crate::Result<()> {
        self.0.get_mut::<db::DBTokensData, _>().del(id).map_err(Into::into)
    }

    fn set_circulating_supply(&mut self, id: &TokenId, supply: &Amount) -> crate::Result<()> {
        self.write::<db::DBTokensCirculatingSupply, _, _, _>(id, supply)
    }

    fn del_circulating_supply(&mut self, id: &TokenId) -> crate::Result<()> {
        self.0.get_mut::<db::DBTokensCirculatingSupply, _>().del(id).map_err(Into::into)
    }
}
