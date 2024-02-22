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

use std::collections::BTreeMap;

use super::db;
use chainstate_types::{BlockIndex, EpochData, EpochStorageRead};
use common::{
    chain::{
        block::{signed_block_header::SignedBlockHeader, BlockReward},
        config::EpochIndex,
        tokens::{TokenAuxiliaryData, TokenId},
        AccountNonce, AccountType, Block, DelegationId, GenBlock, PoolId, Transaction,
        UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, Id, H256},
};
use pos_accounting::{
    DelegationData, DeltaMergeUndo, PoSAccountingDeltaData, PoSAccountingStorageRead, PoolData,
};
use serialization::{Decode, Encode};
use storage::MakeMapRef;
use tokens_accounting::TokensAccountingStorageRead;
use utxo::{Utxo, UtxosBlockUndo, UtxosStorageRead};

use crate::{BlockchainStorageRead, ChainstateStorageVersion, SealedStorageTag, TipStorageTag};

use super::well_known;

mod private {
    use super::*;
    use serialization::encoded::Encoded;
    use std::borrow::Cow;

    pub fn block_index_to_block_reward(
        block_index: &BlockIndex,
        block_read_result: storage::Result<Option<Encoded<Cow<'_, [u8]>, Block>>>,
    ) -> crate::Result<Option<BlockReward>> {
        match block_read_result {
            Err(e) => Err(e.into()),
            Ok(None) => Ok(None),
            Ok(Some(block)) => {
                let block = block.bytes();
                let begin = block_index.block_header().encoded_size();
                let encoded_block_reward_begin =
                    block.get(begin..).expect("Block reward outside of block range");
                let block_reward = BlockReward::decode(&mut &*encoded_block_reward_begin)
                    .expect("Invalid block reward encoding in DB");
                Ok(Some(block_reward))
            }
        }
    }

    pub fn filter_delegation_shares_for_poolid(
        pool_id: PoolId,
        iter: impl Iterator<Item = ((PoolId, DelegationId), Amount)>,
    ) -> crate::Result<Option<BTreeMap<DelegationId, Amount>>> {
        let range_start = (pool_id, DelegationId::new(H256::zero()));
        let range_end = (pool_id, DelegationId::new(H256::repeat_byte(0xFF)));
        let range = range_start..=range_end;

        let shares = iter.filter(|(k, _)| range.contains(k));

        let result = shares.map(|((_pool_id, del_id), v)| (del_id, v)).collect::<BTreeMap<_, _>>();
        if result.is_empty() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }
}

/// Blockchain data storage transaction
impl<'st, B: storage::Backend> BlockchainStorageRead for super::StoreTxRo<'st, B> {
    fn get_storage_version(&self) -> crate::Result<Option<ChainstateStorageVersion>> {
        self.read_value::<well_known::StoreVersion>()
    }

    fn get_magic_bytes(&self) -> crate::Result<Option<[u8; 4]>> {
        self.read_value::<well_known::MagicBytes>()
    }

    fn get_chain_type(&self) -> crate::Result<Option<String>> {
        self.read_value::<well_known::ChainType>()
    }

    fn get_block_index(&self, id: &Id<Block>) -> crate::Result<Option<BlockIndex>> {
        self.read::<db::DBBlockIndex, _, _>(id)
    }

    /// Get the hash of the best block
    fn get_best_block_id(&self) -> crate::Result<Option<Id<GenBlock>>> {
        self.read_value::<well_known::BestBlockId>()
    }

    fn get_block(&self, id: Id<Block>) -> crate::Result<Option<Block>> {
        self.read::<db::DBBlock, _, _>(id)
    }

    fn get_block_header(&self, id: Id<Block>) -> crate::Result<Option<SignedBlockHeader>> {
        let block_index = self.read::<db::DBBlockIndex, _, _>(id)?;
        Ok(block_index.map(|block_index| block_index.into_block_header()))
    }

    fn get_block_reward(&self, block_index: &BlockIndex) -> crate::Result<Option<BlockReward>> {
        let store = self.0.get::<db::DBBlock, _>();
        let encoded_block = store.get(block_index.block_id());
        private::block_index_to_block_reward(block_index, encoded_block)
    }

    fn get_min_height_with_allowed_reorg(&self) -> crate::Result<Option<BlockHeight>> {
        self.read_value::<well_known::MinHeightForReorg>()
    }

    fn get_block_id_by_height(&self, height: &BlockHeight) -> crate::Result<Option<Id<GenBlock>>> {
        self.read::<db::DBBlockByHeight, _, _>(height)
    }

    fn get_undo_data(&self, id: Id<Block>) -> crate::Result<Option<UtxosBlockUndo>> {
        self.read::<db::DBUtxosBlockUndo, _, _>(id)
    }

    fn get_token_aux_data(&self, token_id: &TokenId) -> crate::Result<Option<TokenAuxiliaryData>> {
        self.read::<db::DBTokensAuxData, _, _>(&token_id)
    }

    fn get_token_id(&self, issuance_tx_id: &Id<Transaction>) -> crate::Result<Option<TokenId>> {
        self.read::<db::DBIssuanceTxVsTokenId, _, _>(&issuance_tx_id)
    }

    fn get_tokens_accounting_undo(
        &self,
        id: Id<Block>,
    ) -> crate::Result<Option<tokens_accounting::BlockUndo>> {
        self.read::<db::DBTokensAccountingBlockUndo, _, _>(&id)
    }

    fn get_block_tree_by_height(
        &self,
        start_from: BlockHeight,
    ) -> crate::Result<BTreeMap<BlockHeight, Vec<Id<Block>>>> {
        let map = self.0.get::<db::DBBlockIndex, _>();
        let items = map.prefix_iter_decoded(&())?;

        let mut result = BTreeMap::<BlockHeight, Vec<Id<Block>>>::new();
        for (_, bi) in items {
            if bi.block_height() >= start_from {
                result.entry(bi.block_height()).or_default().push(*bi.block_id());
            }
        }

        Ok(result)
    }

    fn get_pos_accounting_undo(
        &self,
        id: Id<Block>,
    ) -> crate::Result<Option<pos_accounting::BlockUndo>> {
        self.read::<db::DBAccountingBlockUndo, _, _>(id)
    }

    fn get_accounting_epoch_delta(
        &self,
        epoch_index: EpochIndex,
    ) -> crate::Result<Option<PoSAccountingDeltaData>> {
        self.read::<db::DBAccountingEpochDelta, _, _>(epoch_index)
    }

    fn get_accounting_epoch_undo_delta(
        &self,
        epoch_index: EpochIndex,
    ) -> crate::Result<Option<DeltaMergeUndo>> {
        self.read::<db::DBAccountingEpochDeltaUndo, _, _>(epoch_index)
    }

    fn get_account_nonce_count(&self, account: AccountType) -> crate::Result<Option<AccountNonce>> {
        self.read::<db::DBAccountNonceCount, _, _>(account)
    }
}

impl<'st, B: storage::Backend> EpochStorageRead for super::StoreTxRo<'st, B> {
    fn get_epoch_data(&self, epoch_index: u64) -> crate::Result<Option<EpochData>> {
        self.read::<db::DBEpochData, _, _>(epoch_index)
    }
}

impl<'st, B: storage::Backend> UtxosStorageRead for super::StoreTxRo<'st, B> {
    type Error = crate::Error;

    fn get_utxo(&self, outpoint: &UtxoOutPoint) -> crate::Result<Option<Utxo>> {
        self.read::<db::DBUtxo, _, _>(outpoint)
    }

    fn get_best_block_for_utxos(&self) -> crate::Result<Id<GenBlock>> {
        self.read_value::<well_known::UtxosBestBlockId>()
            .map(|id| id.expect("Best block for UTXOs to be present"))
    }
}

impl<'st, B: storage::Backend> PoSAccountingStorageRead<TipStorageTag>
    for super::StoreTxRo<'st, B>
{
    fn get_pool_balance(&self, pool_id: PoolId) -> crate::Result<Option<Amount>> {
        self.read::<db::DBAccountingPoolBalancesTip, _, _>(pool_id)
    }

    fn get_pool_data(&self, pool_id: PoolId) -> crate::Result<Option<PoolData>> {
        self.read::<db::DBAccountingPoolDataTip, _, _>(pool_id)
    }

    fn get_delegation_balance(&self, delegation_id: DelegationId) -> crate::Result<Option<Amount>> {
        self.read::<db::DBAccountingDelegationBalancesTip, _, _>(delegation_id)
    }

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> crate::Result<Option<DelegationData>> {
        self.read::<db::DBAccountingDelegationDataTip, _, _>(delegation_id)
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> crate::Result<Option<BTreeMap<DelegationId, Amount>>> {
        let db_map = self.0.get::<db::DBAccountingPoolDelegationSharesTip, _>();
        let shares_iter = db_map.prefix_iter_decoded(&())?;
        private::filter_delegation_shares_for_poolid(pool_id, shares_iter)
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> crate::Result<Option<Amount>> {
        self.read::<db::DBAccountingPoolDelegationSharesTip, _, _>((pool_id, delegation_id))
    }
}

impl<'st, B: storage::Backend> PoSAccountingStorageRead<SealedStorageTag>
    for super::StoreTxRo<'st, B>
{
    fn get_pool_balance(&self, pool_id: PoolId) -> crate::Result<Option<Amount>> {
        self.read::<db::DBAccountingPoolBalancesSealed, _, _>(pool_id)
    }

    fn get_pool_data(&self, pool_id: PoolId) -> crate::Result<Option<PoolData>> {
        self.read::<db::DBAccountingPoolDataSealed, _, _>(pool_id)
    }

    fn get_delegation_balance(&self, delegation_id: DelegationId) -> crate::Result<Option<Amount>> {
        self.read::<db::DBAccountingDelegationBalancesSealed, _, _>(delegation_id)
    }

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> crate::Result<Option<DelegationData>> {
        self.read::<db::DBAccountingDelegationDataSealed, _, _>(delegation_id)
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> crate::Result<Option<BTreeMap<DelegationId, Amount>>> {
        let db_map = self.0.get::<db::DBAccountingPoolDelegationSharesSealed, _>();
        let shares_iter = db_map.prefix_iter_decoded(&())?;
        private::filter_delegation_shares_for_poolid(pool_id, shares_iter)
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> crate::Result<Option<Amount>> {
        self.read::<db::DBAccountingPoolDelegationSharesSealed, _, _>((pool_id, delegation_id))
    }
}

impl<'st, B: storage::Backend> TokensAccountingStorageRead for super::StoreTxRo<'st, B> {
    type Error = crate::Error;

    fn get_token_data(&self, id: &TokenId) -> crate::Result<Option<tokens_accounting::TokenData>> {
        self.read::<db::DBTokensData, _, _>(id)
    }

    fn get_circulating_supply(&self, id: &TokenId) -> crate::Result<Option<Amount>> {
        self.read::<db::DBTokensCirculatingSupply, _, _>(id)
    }
}

/// Blockchain data storage transaction
impl<'st, B: storage::Backend> BlockchainStorageRead for super::StoreTxRw<'st, B> {
    fn get_storage_version(&self) -> crate::Result<Option<ChainstateStorageVersion>> {
        self.read_value::<well_known::StoreVersion>()
    }

    fn get_magic_bytes(&self) -> crate::Result<Option<[u8; 4]>> {
        self.read_value::<well_known::MagicBytes>()
    }

    fn get_chain_type(&self) -> crate::Result<Option<String>> {
        self.read_value::<well_known::ChainType>()
    }

    fn get_block_index(&self, id: &Id<Block>) -> crate::Result<Option<BlockIndex>> {
        self.read::<db::DBBlockIndex, _, _>(id)
    }

    /// Get the hash of the best block
    fn get_best_block_id(&self) -> crate::Result<Option<Id<GenBlock>>> {
        self.read_value::<well_known::BestBlockId>()
    }

    fn get_block(&self, id: Id<Block>) -> crate::Result<Option<Block>> {
        self.read::<db::DBBlock, _, _>(id)
    }

    fn get_block_header(&self, id: Id<Block>) -> crate::Result<Option<SignedBlockHeader>> {
        let block_index = self.read::<db::DBBlockIndex, _, _>(id)?;
        Ok(block_index.map(|block_index| block_index.into_block_header()))
    }

    fn get_block_reward(&self, block_index: &BlockIndex) -> crate::Result<Option<BlockReward>> {
        let store = self.0.get::<db::DBBlock, _>();
        let encoded_block = store.get(block_index.block_id());
        private::block_index_to_block_reward(block_index, encoded_block)
    }

    fn get_min_height_with_allowed_reorg(&self) -> crate::Result<Option<BlockHeight>> {
        self.read_value::<well_known::MinHeightForReorg>()
    }

    fn get_block_id_by_height(&self, height: &BlockHeight) -> crate::Result<Option<Id<GenBlock>>> {
        self.read::<db::DBBlockByHeight, _, _>(height)
    }

    fn get_undo_data(&self, id: Id<Block>) -> crate::Result<Option<UtxosBlockUndo>> {
        self.read::<db::DBUtxosBlockUndo, _, _>(id)
    }

    fn get_token_aux_data(&self, token_id: &TokenId) -> crate::Result<Option<TokenAuxiliaryData>> {
        self.read::<db::DBTokensAuxData, _, _>(&token_id)
    }

    fn get_token_id(&self, issuance_tx_id: &Id<Transaction>) -> crate::Result<Option<TokenId>> {
        self.read::<db::DBIssuanceTxVsTokenId, _, _>(&issuance_tx_id)
    }

    fn get_tokens_accounting_undo(
        &self,
        id: Id<Block>,
    ) -> crate::Result<Option<tokens_accounting::BlockUndo>> {
        self.read::<db::DBTokensAccountingBlockUndo, _, _>(&id)
    }

    fn get_block_tree_by_height(
        &self,
        start_from: BlockHeight,
    ) -> crate::Result<BTreeMap<BlockHeight, Vec<Id<Block>>>> {
        let map = self.0.get::<db::DBBlockIndex, _>();
        let items = map.prefix_iter_decoded(&())?;

        let mut result = BTreeMap::<BlockHeight, Vec<Id<Block>>>::new();
        for (_, bi) in items {
            if bi.block_height() >= start_from {
                result.entry(bi.block_height()).or_default().push(*bi.block_id());
            }
        }

        Ok(result)
    }

    fn get_pos_accounting_undo(
        &self,
        id: Id<Block>,
    ) -> crate::Result<Option<pos_accounting::BlockUndo>> {
        self.read::<db::DBAccountingBlockUndo, _, _>(id)
    }

    fn get_accounting_epoch_delta(
        &self,
        epoch_index: EpochIndex,
    ) -> crate::Result<Option<PoSAccountingDeltaData>> {
        self.read::<db::DBAccountingEpochDelta, _, _>(epoch_index)
    }

    fn get_accounting_epoch_undo_delta(
        &self,
        epoch_index: EpochIndex,
    ) -> crate::Result<Option<DeltaMergeUndo>> {
        self.read::<db::DBAccountingEpochDeltaUndo, _, _>(epoch_index)
    }

    fn get_account_nonce_count(&self, account: AccountType) -> crate::Result<Option<AccountNonce>> {
        self.read::<db::DBAccountNonceCount, _, _>(account)
    }
}

impl<'st, B: storage::Backend> EpochStorageRead for super::StoreTxRw<'st, B> {
    fn get_epoch_data(&self, epoch_index: u64) -> crate::Result<Option<EpochData>> {
        self.read::<db::DBEpochData, _, _>(epoch_index)
    }
}

impl<'st, B: storage::Backend> UtxosStorageRead for super::StoreTxRw<'st, B> {
    type Error = crate::Error;

    fn get_utxo(&self, outpoint: &UtxoOutPoint) -> crate::Result<Option<Utxo>> {
        self.read::<db::DBUtxo, _, _>(outpoint)
    }

    fn get_best_block_for_utxos(&self) -> crate::Result<Id<GenBlock>> {
        self.read_value::<well_known::UtxosBestBlockId>()
            .map(|id| id.expect("Best block for UTXOs to be present"))
    }
}

impl<'st, B: storage::Backend> PoSAccountingStorageRead<TipStorageTag>
    for super::StoreTxRw<'st, B>
{
    fn get_pool_balance(&self, pool_id: PoolId) -> crate::Result<Option<Amount>> {
        self.read::<db::DBAccountingPoolBalancesTip, _, _>(pool_id)
    }

    fn get_pool_data(&self, pool_id: PoolId) -> crate::Result<Option<PoolData>> {
        self.read::<db::DBAccountingPoolDataTip, _, _>(pool_id)
    }

    fn get_delegation_balance(&self, delegation_id: DelegationId) -> crate::Result<Option<Amount>> {
        self.read::<db::DBAccountingDelegationBalancesTip, _, _>(delegation_id)
    }

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> crate::Result<Option<DelegationData>> {
        self.read::<db::DBAccountingDelegationDataTip, _, _>(delegation_id)
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> crate::Result<Option<BTreeMap<DelegationId, Amount>>> {
        let db_map = self.0.get::<db::DBAccountingPoolDelegationSharesTip, _>();
        let shares_iter = db_map.prefix_iter_decoded(&())?;
        private::filter_delegation_shares_for_poolid(pool_id, shares_iter)
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> crate::Result<Option<Amount>> {
        self.read::<db::DBAccountingPoolDelegationSharesTip, _, _>((pool_id, delegation_id))
    }
}

impl<'st, B: storage::Backend> PoSAccountingStorageRead<SealedStorageTag>
    for super::StoreTxRw<'st, B>
{
    fn get_pool_balance(&self, pool_id: PoolId) -> crate::Result<Option<Amount>> {
        self.read::<db::DBAccountingPoolBalancesSealed, _, _>(pool_id)
    }

    fn get_pool_data(&self, pool_id: PoolId) -> crate::Result<Option<PoolData>> {
        self.read::<db::DBAccountingPoolDataSealed, _, _>(pool_id)
    }

    fn get_delegation_balance(&self, delegation_id: DelegationId) -> crate::Result<Option<Amount>> {
        self.read::<db::DBAccountingDelegationBalancesSealed, _, _>(delegation_id)
    }

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> crate::Result<Option<DelegationData>> {
        self.read::<db::DBAccountingDelegationDataSealed, _, _>(delegation_id)
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> crate::Result<Option<BTreeMap<DelegationId, Amount>>> {
        let db_map = self.0.get::<db::DBAccountingPoolDelegationSharesSealed, _>();
        let shares_iter = db_map.prefix_iter_decoded(&())?;
        private::filter_delegation_shares_for_poolid(pool_id, shares_iter)
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> crate::Result<Option<Amount>> {
        self.read::<db::DBAccountingPoolDelegationSharesSealed, _, _>((pool_id, delegation_id))
    }
}

impl<'st, B: storage::Backend> TokensAccountingStorageRead for super::StoreTxRw<'st, B> {
    type Error = crate::Error;

    fn get_token_data(&self, id: &TokenId) -> crate::Result<Option<tokens_accounting::TokenData>> {
        self.read::<db::DBTokensData, _, _>(id)
    }

    fn get_circulating_supply(&self, id: &TokenId) -> crate::Result<Option<Amount>> {
        self.read::<db::DBTokensCirculatingSupply, _, _>(id)
    }
}
