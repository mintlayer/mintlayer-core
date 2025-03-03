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
        config::{EpochIndex, MagicBytes},
        tokens::{TokenAuxiliaryData, TokenId},
        AccountNonce, AccountType, Block, DelegationId, GenBlock, OrderId, PoolId, Transaction,
        UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, Id, Idable},
};
use orders_accounting::{OrderData, OrdersAccountingStorageWrite, OrdersAccountingUndo};
use pos_accounting::{
    DelegationData, DeltaMergeUndo, PoSAccountingDeltaData, PoSAccountingStorageWrite,
    PoSAccountingUndo, PoolData,
};
use tokens_accounting::{TokenAccountingUndo, TokensAccountingStorageWrite};
use utils::log_error;
use utxo::{Utxo, UtxosBlockUndo, UtxosStorageWrite};

use super::db;

impl<B: storage::Backend> BlockchainStorageWrite for StoreTxRw<'_, B> {
    #[log_error]
    fn set_storage_version(&mut self, version: ChainstateStorageVersion) -> crate::Result<()> {
        self.write_value::<well_known::StoreVersion>(&version)
    }

    #[log_error]
    fn set_magic_bytes(&mut self, bytes: &MagicBytes) -> crate::Result<()> {
        self.write_value::<well_known::MagicBytes>(bytes)
    }

    #[log_error]
    fn set_chain_type(&mut self, chain: &str) -> crate::Result<()> {
        self.write_value::<well_known::ChainType>(&chain.to_owned())
    }

    #[log_error]
    fn set_best_block_id(&mut self, id: &Id<GenBlock>) -> crate::Result<()> {
        self.write_value::<well_known::BestBlockId>(id)
    }

    #[log_error]
    fn add_block(&mut self, block: &Block) -> crate::Result<()> {
        self.write::<db::DBBlock, _, _, _>(block.get_id(), block)
    }

    #[log_error]
    fn del_block(&mut self, id: Id<Block>) -> crate::Result<()> {
        self.del::<db::DBBlock, _, _>(id)
    }

    #[log_error]
    fn set_block_index(&mut self, block_index: &BlockIndex) -> crate::Result<()> {
        self.write::<db::DBBlockIndex, _, _, _>(block_index.block_id(), block_index)
    }

    #[log_error]
    fn del_block_index(&mut self, block_id: Id<Block>) -> crate::Result<()> {
        self.del::<db::DBBlockIndex, _, _>(block_id)
    }

    #[log_error]
    fn set_min_height_with_allowed_reorg(&mut self, height: BlockHeight) -> crate::Result<()> {
        self.write_value::<well_known::MinHeightForReorg>(&height)
    }

    #[log_error]
    fn set_block_id_at_height(
        &mut self,
        height: &BlockHeight,
        block_id: &Id<GenBlock>,
    ) -> crate::Result<()> {
        self.write::<db::DBBlockByHeight, _, _, _>(height, block_id)
    }

    #[log_error]
    fn del_block_id_at_height(&mut self, height: &BlockHeight) -> crate::Result<()> {
        self.del::<db::DBBlockByHeight, _, _>(height)
    }

    #[log_error]
    fn set_undo_data(&mut self, id: Id<Block>, undo: &UtxosBlockUndo) -> crate::Result<()> {
        self.write::<db::DBUtxosBlockUndo, _, _, _>(id, undo)
    }

    #[log_error]
    fn del_undo_data(&mut self, id: Id<Block>) -> crate::Result<()> {
        self.del::<db::DBUtxosBlockUndo, _, _>(id)
    }

    #[log_error]
    fn set_token_aux_data(
        &mut self,
        token_id: &TokenId,
        data: &TokenAuxiliaryData,
    ) -> crate::Result<()> {
        self.write::<db::DBTokensAuxData, _, _, _>(token_id, &data)
    }

    #[log_error]
    fn del_token_aux_data(&mut self, token_id: &TokenId) -> crate::Result<()> {
        self.del::<db::DBTokensAuxData, _, _>(token_id)
    }

    #[log_error]
    fn set_token_id(
        &mut self,
        issuance_tx_id: &Id<Transaction>,
        token_id: &TokenId,
    ) -> crate::Result<()> {
        self.write::<db::DBIssuanceTxVsTokenId, _, _, _>(issuance_tx_id, token_id)
    }

    #[log_error]
    fn del_token_id(&mut self, issuance_tx_id: &Id<Transaction>) -> crate::Result<()> {
        self.del::<db::DBIssuanceTxVsTokenId, _, _>(issuance_tx_id)
    }

    #[log_error]
    fn set_tokens_accounting_undo_data(
        &mut self,
        id: Id<Block>,
        undo: &accounting::BlockUndo<TokenAccountingUndo>,
    ) -> crate::Result<()> {
        self.write::<db::DBTokensAccountingBlockUndo, _, _, _>(id, undo)
    }

    #[log_error]
    fn del_tokens_accounting_undo_data(&mut self, id: Id<Block>) -> crate::Result<()> {
        self.del::<db::DBTokensAccountingBlockUndo, _, _>(id)
    }

    #[log_error]
    fn set_orders_accounting_undo_data(
        &mut self,
        id: Id<Block>,
        undo: &accounting::BlockUndo<OrdersAccountingUndo>,
    ) -> crate::Result<()> {
        self.write::<db::DBOrdersAccountingBlockUndo, _, _, _>(id, undo)
    }

    #[log_error]
    fn del_orders_accounting_undo_data(&mut self, id: Id<Block>) -> crate::Result<()> {
        self.del::<db::DBOrdersAccountingBlockUndo, _, _>(id)
    }

    #[log_error]
    fn set_pos_accounting_undo_data(
        &mut self,
        id: Id<Block>,
        undo: &accounting::BlockUndo<PoSAccountingUndo>,
    ) -> crate::Result<()> {
        self.write::<db::DBAccountingBlockUndo, _, _, _>(id, undo)
    }

    #[log_error]
    fn del_pos_accounting_undo_data(&mut self, id: Id<Block>) -> crate::Result<()> {
        self.del::<db::DBAccountingBlockUndo, _, _>(id)
    }

    #[log_error]
    fn set_accounting_epoch_delta(
        &mut self,
        epoch_index: EpochIndex,
        delta: &PoSAccountingDeltaData,
    ) -> crate::Result<()> {
        self.write::<db::DBAccountingEpochDelta, _, _, _>(epoch_index, delta)
    }

    #[log_error]
    fn del_accounting_epoch_delta(&mut self, epoch_index: EpochIndex) -> crate::Result<()> {
        self.del::<db::DBAccountingEpochDelta, _, _>(epoch_index)
    }

    #[log_error]
    fn set_accounting_epoch_undo_delta(
        &mut self,
        epoch_index: EpochIndex,
        undo: &DeltaMergeUndo,
    ) -> crate::Result<()> {
        self.write::<db::DBAccountingEpochDeltaUndo, _, _, _>(epoch_index, undo)
    }

    #[log_error]
    fn del_accounting_epoch_undo_delta(&mut self, epoch_index: EpochIndex) -> crate::Result<()> {
        self.del::<db::DBAccountingEpochDeltaUndo, _, _>(epoch_index)
    }

    #[log_error]
    fn set_account_nonce_count(
        &mut self,
        account: AccountType,
        nonce: AccountNonce,
    ) -> crate::Result<()> {
        self.write::<db::DBAccountNonceCount, _, _, _>(account, nonce)
    }

    #[log_error]
    fn del_account_nonce_count(&mut self, account: AccountType) -> crate::Result<()> {
        self.del::<db::DBAccountNonceCount, _, _>(account)
    }
}

impl<B: storage::Backend> EpochStorageWrite for StoreTxRw<'_, B> {
    #[log_error]
    fn set_epoch_data(&mut self, epoch_index: u64, epoch_data: &EpochData) -> crate::Result<()> {
        self.write::<db::DBEpochData, _, _, _>(epoch_index, epoch_data)
    }

    #[log_error]
    fn del_epoch_data(&mut self, epoch_index: u64) -> crate::Result<()> {
        self.del::<db::DBEpochData, _, _>(epoch_index)
    }
}

impl<B: storage::Backend> UtxosStorageWrite for StoreTxRw<'_, B> {
    #[log_error]
    fn set_utxo(&mut self, outpoint: &UtxoOutPoint, entry: Utxo) -> crate::Result<()> {
        self.write::<db::DBUtxo, _, _, _>(outpoint, entry)
    }

    #[log_error]
    fn del_utxo(&mut self, outpoint: &UtxoOutPoint) -> crate::Result<()> {
        self.del::<db::DBUtxo, _, _>(outpoint)
    }

    #[log_error]
    fn set_best_block_for_utxos(&mut self, block_id: &Id<GenBlock>) -> crate::Result<()> {
        self.write_value::<well_known::UtxosBestBlockId>(block_id)
    }
}

impl<B: storage::Backend> PoSAccountingStorageWrite<TipStorageTag> for StoreTxRw<'_, B> {
    #[log_error]
    fn set_pool_balance(&mut self, pool_id: PoolId, amount: Amount) -> crate::Result<()> {
        self.write::<db::DBAccountingPoolBalancesTip, _, _, _>(pool_id, amount)
    }

    #[log_error]
    fn del_pool_balance(&mut self, pool_id: PoolId) -> crate::Result<()> {
        self.del::<db::DBAccountingPoolBalancesTip, _, _>(pool_id)
    }

    #[log_error]
    fn set_pool_data(&mut self, pool_id: PoolId, pool_data: &PoolData) -> crate::Result<()> {
        self.write::<db::DBAccountingPoolDataTip, _, _, _>(pool_id, pool_data)
    }

    #[log_error]
    fn del_pool_data(&mut self, pool_id: PoolId) -> crate::Result<()> {
        self.del::<db::DBAccountingPoolDataTip, _, _>(pool_id)
    }

    #[log_error]
    fn set_delegation_balance(
        &mut self,
        delegation_target: DelegationId,
        amount: Amount,
    ) -> crate::Result<()> {
        self.write::<db::DBAccountingDelegationBalancesTip, _, _, _>(delegation_target, amount)
    }

    #[log_error]
    fn del_delegation_balance(&mut self, delegation_target: DelegationId) -> crate::Result<()> {
        self.del::<db::DBAccountingDelegationBalancesTip, _, _>(delegation_target)
    }

    #[log_error]
    fn set_delegation_data(
        &mut self,
        delegation_id: DelegationId,
        delegation_data: &DelegationData,
    ) -> crate::Result<()> {
        self.write::<db::DBAccountingDelegationDataTip, _, _, _>(delegation_id, delegation_data)
    }

    #[log_error]
    fn del_delegation_data(&mut self, delegation_id: DelegationId) -> crate::Result<()> {
        self.del::<db::DBAccountingDelegationDataTip, _, _>(delegation_id)
    }

    #[log_error]
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

    #[log_error]
    fn del_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> crate::Result<()> {
        self.del::<db::DBAccountingPoolDelegationSharesTip, _, _>((pool_id, delegation_id))
    }
}

impl<B: storage::Backend> PoSAccountingStorageWrite<SealedStorageTag> for StoreTxRw<'_, B> {
    #[log_error]
    fn set_pool_balance(&mut self, pool_id: PoolId, amount: Amount) -> crate::Result<()> {
        self.write::<db::DBAccountingPoolBalancesSealed, _, _, _>(pool_id, amount)
    }

    #[log_error]
    fn del_pool_balance(&mut self, pool_id: PoolId) -> crate::Result<()> {
        self.del::<db::DBAccountingPoolBalancesSealed, _, _>(pool_id)
    }

    #[log_error]
    fn set_pool_data(&mut self, pool_id: PoolId, pool_data: &PoolData) -> crate::Result<()> {
        self.write::<db::DBAccountingPoolDataSealed, _, _, _>(pool_id, pool_data)
    }

    #[log_error]
    fn del_pool_data(&mut self, pool_id: PoolId) -> crate::Result<()> {
        self.del::<db::DBAccountingPoolDataSealed, _, _>(pool_id)
    }

    #[log_error]
    fn set_delegation_balance(
        &mut self,
        delegation_target: DelegationId,
        amount: Amount,
    ) -> crate::Result<()> {
        self.write::<db::DBAccountingDelegationBalancesSealed, _, _, _>(delegation_target, amount)
    }

    #[log_error]
    fn del_delegation_balance(&mut self, delegation_target: DelegationId) -> crate::Result<()> {
        self.del::<db::DBAccountingDelegationBalancesSealed, _, _>(delegation_target)
    }

    #[log_error]
    fn set_delegation_data(
        &mut self,
        delegation_id: DelegationId,
        delegation_data: &DelegationData,
    ) -> crate::Result<()> {
        self.write::<db::DBAccountingDelegationDataSealed, _, _, _>(delegation_id, delegation_data)
    }

    #[log_error]
    fn del_delegation_data(&mut self, delegation_id: DelegationId) -> crate::Result<()> {
        self.del::<db::DBAccountingDelegationDataSealed, _, _>(delegation_id)
    }

    #[log_error]
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

    #[log_error]
    fn del_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> crate::Result<()> {
        self.del::<db::DBAccountingPoolDelegationSharesSealed, _, _>((pool_id, delegation_id))
    }
}

impl<B: storage::Backend> TokensAccountingStorageWrite for StoreTxRw<'_, B> {
    #[log_error]
    fn set_token_data(
        &mut self,
        id: &TokenId,
        data: &tokens_accounting::TokenData,
    ) -> crate::Result<()> {
        self.write::<db::DBTokensData, _, _, _>(id, data)
    }

    #[log_error]
    fn del_token_data(&mut self, id: &TokenId) -> crate::Result<()> {
        self.del::<db::DBTokensData, _, _>(id)
    }

    #[log_error]
    fn set_circulating_supply(&mut self, id: &TokenId, supply: &Amount) -> crate::Result<()> {
        self.write::<db::DBTokensCirculatingSupply, _, _, _>(id, supply)
    }

    #[log_error]
    fn del_circulating_supply(&mut self, id: &TokenId) -> crate::Result<()> {
        self.del::<db::DBTokensCirculatingSupply, _, _>(id)
    }
}

impl<B: storage::Backend> OrdersAccountingStorageWrite for StoreTxRw<'_, B> {
    #[log_error]
    fn set_order_data(&mut self, id: &OrderId, data: &OrderData) -> crate::Result<()> {
        self.write::<db::DBOrdersData, _, _, _>(id, data)
    }

    #[log_error]
    fn del_order_data(&mut self, id: &OrderId) -> crate::Result<()> {
        self.del::<db::DBOrdersData, _, _>(id)
    }

    #[log_error]
    fn set_ask_balance(&mut self, id: &OrderId, balance: &Amount) -> crate::Result<()> {
        self.write::<db::DBOrdersAskBalances, _, _, _>(id, balance)
    }

    #[log_error]
    fn del_ask_balance(&mut self, id: &OrderId) -> crate::Result<()> {
        self.del::<db::DBOrdersAskBalances, _, _>(id)
    }

    #[log_error]
    fn set_give_balance(&mut self, id: &OrderId, balance: &Amount) -> crate::Result<()> {
        self.write::<db::DBOrdersGiveBalances, _, _, _>(id, balance)
    }

    #[log_error]
    fn del_give_balance(&mut self, id: &OrderId) -> crate::Result<()> {
        self.del::<db::DBOrdersGiveBalances, _, _>(id)
    }
}
