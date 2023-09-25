use std::collections::BTreeMap;

use super::db;
use chainstate_types::{BlockIndex, EpochData, EpochStorageRead};
use common::{
    chain::{
        block::{signed_block_header::SignedBlockHeader, BlockReward},
        config::EpochIndex,
        tokens::{TokenAuxiliaryData, TokenId},
        AccountNonce, AccountType, Block, DelegationId, GenBlock, OutPointSourceId, PoolId,
        SignedTransaction, Transaction, TxMainChainIndex, TxMainChainPosition, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, Id, H256},
};
use parity_scale_codec::{Decode, Encode};
use pos_accounting::{
    AccountingBlockUndo, DelegationData, DeltaMergeUndo, PoSAccountingDeltaData,
    PoSAccountingStorageRead, PoolData,
};
use utxo::{Utxo, UtxosBlockUndo, UtxosStorageRead};

use crate::{BlockchainStorageRead, ChainstateStorageVersion, SealedStorageTag, TipStorageTag};

use super::well_known;

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
        match self.0.get::<db::DBBlock, _>().get(block_index.block_id()) {
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

    fn get_is_mainchain_tx_index_enabled(&self) -> crate::Result<Option<bool>> {
        self.read_value::<well_known::TxIndexEnabled>()
    }

    fn get_min_height_with_allowed_reorg(&self) -> crate::Result<Option<BlockHeight>> {
        self.read_value::<well_known::MinHeightForReorg>()
    }

    fn get_mainchain_tx_index(
        &self,
        tx_id: &OutPointSourceId,
    ) -> crate::Result<Option<TxMainChainIndex>> {
        self.read::<db::DBTxIndex, _, _>(tx_id)
    }

    fn get_mainchain_tx_by_position(
        &self,
        tx_index: &TxMainChainPosition,
    ) -> crate::Result<Option<SignedTransaction>> {
        let block_id = tx_index.block_id();
        match self.0.get::<db::DBBlock, _>().get(block_id) {
            Err(e) => Err(e.into()),
            Ok(None) => Ok(None),
            Ok(Some(block)) => {
                let block = block.bytes();
                let begin = tx_index.byte_offset_in_block() as usize;
                let encoded_tx = block.get(begin..).expect("Transaction outside of block range");
                let tx = SignedTransaction::decode(&mut &*encoded_tx)
                    .expect("Invalid tx encoding in DB");
                Ok(Some(tx))
            }
        }
    }

    fn get_block_id_by_height(&self, height: &BlockHeight) -> crate::Result<Option<Id<GenBlock>>> {
        self.read::<db::DBBlockByHeight, _, _>(height)
    }

    fn get_token_aux_data(&self, token_id: &TokenId) -> crate::Result<Option<TokenAuxiliaryData>> {
        self.read::<db::DBTokensAuxData, _, _>(&token_id)
    }

    fn get_token_id(&self, issuance_tx_id: &Id<Transaction>) -> crate::Result<Option<TokenId>> {
        self.read::<db::DBIssuanceTxVsTokenId, _, _>(&issuance_tx_id)
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

    fn get_accounting_undo(&self, id: Id<Block>) -> crate::Result<Option<AccountingBlockUndo>> {
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

    fn get_undo_data(&self, id: Id<Block>) -> crate::Result<Option<UtxosBlockUndo>> {
        self.read::<db::DBUtxosBlockUndo, _, _>(id)
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
        let all_shares = self
            .0
            .get::<db::DBAccountingPoolDelegationSharesTip, _>()
            .prefix_iter_decoded(&())?
            .collect::<BTreeMap<(PoolId, DelegationId), Amount>>();

        let range_start = (pool_id, DelegationId::new(H256::zero()));
        let range_end = (pool_id, DelegationId::new(H256::repeat_byte(0xFF)));
        let range = all_shares.range(range_start..=range_end);
        let result = range.map(|((_pool_id, del_id), v)| (*del_id, *v)).collect::<BTreeMap<_, _>>();
        if result.is_empty() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
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
        let all_shares = self
            .0
            .get::<db::DBAccountingPoolDelegationSharesSealed, _>()
            .prefix_iter(&())?
            .map(|(k, v)| crate::Result::<((PoolId, DelegationId), Amount)>::Ok((k, v.decode())))
            .collect::<Result<BTreeMap<(PoolId, DelegationId), Amount>, _>>()?;

        let range_start = (pool_id, DelegationId::new(H256::zero()));
        let range_end = (pool_id, DelegationId::new(H256::repeat_byte(0xFF)));
        let range = all_shares.range(range_start..=range_end);
        let result = range.map(|((_pool_id, del_id), v)| (*del_id, *v)).collect::<BTreeMap<_, _>>();
        if result.is_empty() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> crate::Result<Option<Amount>> {
        self.read::<db::DBAccountingPoolDelegationSharesSealed, _, _>((pool_id, delegation_id))
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
        match self.0.get::<db::DBBlock, _>().get(block_index.block_id()) {
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

    fn get_is_mainchain_tx_index_enabled(&self) -> crate::Result<Option<bool>> {
        self.read_value::<well_known::TxIndexEnabled>()
    }

    fn get_min_height_with_allowed_reorg(&self) -> crate::Result<Option<BlockHeight>> {
        self.read_value::<well_known::MinHeightForReorg>()
    }

    fn get_mainchain_tx_index(
        &self,
        tx_id: &OutPointSourceId,
    ) -> crate::Result<Option<TxMainChainIndex>> {
        self.read::<db::DBTxIndex, _, _>(tx_id)
    }

    fn get_mainchain_tx_by_position(
        &self,
        tx_index: &TxMainChainPosition,
    ) -> crate::Result<Option<SignedTransaction>> {
        let block_id = tx_index.block_id();
        match self.0.get::<db::DBBlock, _>().get(block_id) {
            Err(e) => Err(e.into()),
            Ok(None) => Ok(None),
            Ok(Some(block)) => {
                let block = block.bytes();
                let begin = tx_index.byte_offset_in_block() as usize;
                let encoded_tx = block.get(begin..).expect("Transaction outside of block range");
                let tx = SignedTransaction::decode(&mut &*encoded_tx)
                    .expect("Invalid tx encoding in DB");
                Ok(Some(tx))
            }
        }
    }

    fn get_block_id_by_height(&self, height: &BlockHeight) -> crate::Result<Option<Id<GenBlock>>> {
        self.read::<db::DBBlockByHeight, _, _>(height)
    }

    fn get_token_aux_data(&self, token_id: &TokenId) -> crate::Result<Option<TokenAuxiliaryData>> {
        self.read::<db::DBTokensAuxData, _, _>(&token_id)
    }

    fn get_token_id(&self, issuance_tx_id: &Id<Transaction>) -> crate::Result<Option<TokenId>> {
        self.read::<db::DBIssuanceTxVsTokenId, _, _>(&issuance_tx_id)
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

    fn get_accounting_undo(&self, id: Id<Block>) -> crate::Result<Option<AccountingBlockUndo>> {
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

    fn get_undo_data(&self, id: Id<Block>) -> crate::Result<Option<UtxosBlockUndo>> {
        self.read::<db::DBUtxosBlockUndo, _, _>(id)
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
        let all_shares = self
            .0
            .get::<db::DBAccountingPoolDelegationSharesTip, _>()
            .prefix_iter_decoded(&())?
            .collect::<BTreeMap<(PoolId, DelegationId), Amount>>();

        let range_start = (pool_id, DelegationId::new(H256::zero()));
        let range_end = (pool_id, DelegationId::new(H256::repeat_byte(0xFF)));
        let range = all_shares.range(range_start..=range_end);
        let result = range.map(|((_pool_id, del_id), v)| (*del_id, *v)).collect::<BTreeMap<_, _>>();
        if result.is_empty() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
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
        let all_shares = self
            .0
            .get::<db::DBAccountingPoolDelegationSharesSealed, _>()
            .prefix_iter(&())?
            .map(|(k, v)| crate::Result::<((PoolId, DelegationId), Amount)>::Ok((k, v.decode())))
            .collect::<Result<BTreeMap<(PoolId, DelegationId), Amount>, _>>()?;

        let range_start = (pool_id, DelegationId::new(H256::zero()));
        let range_end = (pool_id, DelegationId::new(H256::repeat_byte(0xFF)));
        let range = all_shares.range(range_start..=range_end);
        let result = range.map(|((_pool_id, del_id), v)| (*del_id, *v)).collect::<BTreeMap<_, _>>();
        if result.is_empty() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> crate::Result<Option<Amount>> {
        self.read::<db::DBAccountingPoolDelegationSharesSealed, _, _>((pool_id, delegation_id))
    }
}
