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

use std::collections::BTreeMap;

use chainstate_types::BlockIndex;
use common::{
    chain::{
        block::BlockReward,
        config::EpochIndex,
        tokens::{TokenAuxiliaryData, TokenId},
        transaction::{Transaction, TxMainChainIndex, TxMainChainPosition},
        Block, GenBlock, OutPoint, OutPointSourceId,
    },
    primitives::{Amount, BlockHeight, Id},
};
use pos_accounting::{
    AccountingBlockUndo, DelegationData, DelegationId, DeltaMergeUndo, PoSAccountingDeltaData,
    PoSAccountingStorageRead, PoSAccountingStorageWrite, PoolData, PoolId,
};
use utxo::{Utxo, UtxosBlockUndo, UtxosStorageRead, UtxosStorageWrite};

use crate::{
    schema::{self as db, Schema},
    BlockchainStorage, BlockchainStorageRead, BlockchainStorageWrite, SealedStorageTag,
    TipStorageTag, TransactionRw, Transactional,
};

mod store_tx;
pub use store_tx::{StoreTxRo, StoreTxRw};

/// Store for blockchain data, parametrized over the backend B
pub struct Store<B: storage::Backend>(storage::Storage<B, Schema>);

impl<B: storage::Backend> Store<B> {
    /// Create a new chainstate storage
    pub fn new(backend: B) -> crate::Result<Self> {
        let mut storage = Self(storage::Storage::new(backend).map_err(crate::Error::from)?);
        storage.set_storage_version(1)?;
        Ok(storage)
    }

    /// Dump raw database contents
    pub fn dump_raw(&self) -> crate::Result<storage::raw::StorageContents<Schema>> {
        self.0.dump_raw().map_err(crate::Error::from)
    }

    /// Collect and return all utxos from the storage
    #[allow(clippy::let_and_return)]
    pub fn read_utxo_set(&self) -> crate::Result<BTreeMap<OutPoint, Utxo>> {
        let db = self.transaction_ro()?;
        let map = db.0.get::<db::DBUtxo, _>();
        let res = map.prefix_iter_decoded(&())?.collect::<BTreeMap<_, _>>();

        Ok(res)
    }

    /// Collect and return all tip accounting data from storage
    pub fn read_accounting_data_tip(&self) -> crate::Result<pos_accounting::PoSAccountingData> {
        let db = self.transaction_ro()?;

        let pool_data =
            db.0.get::<db::DBAccountingPoolDataTip, _>()
                .prefix_iter_decoded(&())?
                .collect::<BTreeMap<_, _>>();

        let pool_balances =
            db.0.get::<db::DBAccountingPoolBalancesTip, _>()
                .prefix_iter_decoded(&())?
                .collect::<BTreeMap<_, _>>();

        let delegation_data =
            db.0.get::<db::DBAccountingDelegationDataTip, _>()
                .prefix_iter_decoded(&())?
                .collect::<BTreeMap<_, _>>();

        let delegation_balances =
            db.0.get::<db::DBAccountingDelegationBalancesTip, _>()
                .prefix_iter_decoded(&())?
                .collect::<BTreeMap<_, _>>();

        let pool_delegation_shares =
            db.0.get::<db::DBAccountingPoolDelegationSharesTip, _>()
                .prefix_iter_decoded(&())?
                .collect::<BTreeMap<_, _>>();

        Ok(pos_accounting::PoSAccountingData {
            pool_data,
            pool_balances,
            pool_delegation_shares,
            delegation_balances,
            delegation_data,
        })
    }

    /// Collect and return all sealed accounting data from storage
    pub fn read_accounting_data_sealed(&self) -> crate::Result<pos_accounting::PoSAccountingData> {
        let db = self.transaction_ro()?;

        let pool_data =
            db.0.get::<db::DBAccountingPoolDataSealed, _>()
                .prefix_iter_decoded(&())?
                .collect::<BTreeMap<_, _>>();

        let pool_balances =
            db.0.get::<db::DBAccountingPoolBalancesSealed, _>()
                .prefix_iter_decoded(&())?
                .collect::<BTreeMap<_, _>>();

        let delegation_data =
            db.0.get::<db::DBAccountingDelegationDataSealed, _>()
                .prefix_iter_decoded(&())?
                .collect::<BTreeMap<_, _>>();

        let delegation_balances =
            db.0.get::<db::DBAccountingDelegationBalancesSealed, _>()
                .prefix_iter_decoded(&())?
                .collect::<BTreeMap<_, _>>();

        let pool_delegation_shares =
            db.0.get::<db::DBAccountingPoolDelegationSharesSealed, _>()
                .prefix_iter_decoded(&())?
                .collect::<BTreeMap<_, _>>();

        Ok(pos_accounting::PoSAccountingData {
            pool_data,
            pool_balances,
            pool_delegation_shares,
            delegation_balances,
            delegation_data,
        })
    }
}

impl<B: Default + storage::Backend> Store<B> {
    /// Create a default storage (mostly for testing, may want to remove this later)
    pub fn new_empty() -> crate::Result<Self> {
        Self::new(B::default())
    }
}

impl<B: storage::Backend> Clone for Store<B>
where
    B::Impl: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<'tx, B: storage::Backend + 'tx> Transactional<'tx> for Store<B> {
    type TransactionRo = store_tx::StoreTxRo<'tx, B>;
    type TransactionRw = store_tx::StoreTxRw<'tx, B>;

    fn transaction_ro<'st: 'tx>(&'st self) -> crate::Result<Self::TransactionRo> {
        self.0.transaction_ro().map_err(crate::Error::from).map(store_tx::StoreTxRo)
    }

    fn transaction_rw<'st: 'tx>(
        &'st self,
        size: Option<usize>,
    ) -> crate::Result<Self::TransactionRw> {
        self.0.transaction_rw(size).map_err(crate::Error::from).map(StoreTxRw)
    }
}

impl<B: storage::Backend + 'static> BlockchainStorage for Store<B> {}

macro_rules! delegate_to_transaction {
    ($($(#[size=$s:expr])? fn $func:ident $args:tt -> $ret:ty;)*) => {
        $(delegate_to_transaction!(@FN $(#[size = $s])? $func $args -> $ret);)*
    };
    (@FN $f:ident(&self $(, $arg:ident: $aty:ty)* $(,)?) -> $ret:ty) => {
        fn $f(&self $(, $arg: $aty)*) -> $ret {
            self.transaction_ro().and_then(|tx| tx.$f($($arg),*))
        }
    };
    (@FN $(#[size=$s:expr])? $f:ident(&mut self $(, $arg:ident: $aty:ty)* $(,)?) -> $ret:ty) => {
        fn $f(&mut self $(, $arg: $aty)*) -> $ret {
            let size = delegate_to_transaction!(@SIZE $($s)?);
            let mut tx = self.transaction_rw(size)?;
            let val = tx.$f($($arg),*)?;
            tx.commit()?;
            Ok(val)
        }
    };
    (@SIZE) => { None };
    (@SIZE $s:literal) => { Some($s) };
}

impl<B: storage::Backend> BlockchainStorageRead for Store<B> {
    delegate_to_transaction! {
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

        fn get_accounting_undo(
            &self,
            id: Id<Block>,
        ) -> crate::Result<Option<AccountingBlockUndo>>;

        fn get_accounting_delta(
            &self,
            id: Id<Block>,
        ) -> crate::Result<Option<PoSAccountingDeltaData>>;

        fn get_accounting_epoch_undo_delta(
            &self,
            epoch_index: EpochIndex,
        ) -> crate::Result<Option<DeltaMergeUndo>>;
    }
}

impl<B: storage::Backend> UtxosStorageRead for Store<B> {
    delegate_to_transaction! {
        fn get_utxo(&self, outpoint: &OutPoint) -> crate::Result<Option<Utxo>>;
        fn get_best_block_for_utxos(&self) -> crate::Result<Option<Id<GenBlock>>>;
        fn get_undo_data(&self, id: Id<Block>) -> crate::Result<Option<UtxosBlockUndo>>;
    }
}

impl<B: storage::Backend> PoSAccountingStorageRead<TipStorageTag> for Store<B> {
    fn get_pool_balance(&self, pool_id: PoolId) -> crate::Result<Option<Amount>> {
        let tx = self.transaction_ro()?;
        PoSAccountingStorageRead::<TipStorageTag>::get_pool_balance(&tx, pool_id)
    }
    fn get_pool_data(&self, pool_id: PoolId) -> crate::Result<Option<PoolData>> {
        let tx = self.transaction_ro()?;
        PoSAccountingStorageRead::<TipStorageTag>::get_pool_data(&tx, pool_id)
    }
    fn get_delegation_balance(&self, delegation_id: DelegationId) -> crate::Result<Option<Amount>> {
        let tx = self.transaction_ro()?;
        PoSAccountingStorageRead::<TipStorageTag>::get_delegation_balance(&tx, delegation_id)
    }
    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> crate::Result<Option<DelegationData>> {
        let tx = self.transaction_ro()?;
        PoSAccountingStorageRead::<TipStorageTag>::get_delegation_data(&tx, delegation_id)
    }
    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> crate::Result<Option<BTreeMap<DelegationId, Amount>>> {
        let tx = self.transaction_ro()?;
        PoSAccountingStorageRead::<TipStorageTag>::get_pool_delegations_shares(&tx, pool_id)
    }
    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> crate::Result<Option<Amount>> {
        let tx = self.transaction_ro()?;
        PoSAccountingStorageRead::<TipStorageTag>::get_pool_delegation_share(
            &tx,
            pool_id,
            delegation_id,
        )
    }
}

impl<B: storage::Backend> PoSAccountingStorageRead<SealedStorageTag> for Store<B> {
    fn get_pool_balance(&self, pool_id: PoolId) -> crate::Result<Option<Amount>> {
        let tx = self.transaction_ro()?;
        PoSAccountingStorageRead::<SealedStorageTag>::get_pool_balance(&tx, pool_id)
    }
    fn get_pool_data(&self, pool_id: PoolId) -> crate::Result<Option<PoolData>> {
        let tx = self.transaction_ro()?;
        PoSAccountingStorageRead::<SealedStorageTag>::get_pool_data(&tx, pool_id)
    }
    fn get_delegation_balance(&self, delegation_id: DelegationId) -> crate::Result<Option<Amount>> {
        let tx = self.transaction_ro()?;
        PoSAccountingStorageRead::<SealedStorageTag>::get_delegation_balance(&tx, delegation_id)
    }
    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> crate::Result<Option<DelegationData>> {
        let tx = self.transaction_ro()?;
        PoSAccountingStorageRead::<SealedStorageTag>::get_delegation_data(&tx, delegation_id)
    }
    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> crate::Result<Option<BTreeMap<DelegationId, Amount>>> {
        let tx = self.transaction_ro()?;
        PoSAccountingStorageRead::<SealedStorageTag>::get_pool_delegations_shares(&tx, pool_id)
    }
    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> crate::Result<Option<Amount>> {
        let tx = self.transaction_ro()?;
        PoSAccountingStorageRead::<SealedStorageTag>::get_pool_delegation_share(
            &tx,
            pool_id,
            delegation_id,
        )
    }
}

impl<B: storage::Backend> BlockchainStorageWrite for Store<B> {
    delegate_to_transaction! {
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

        fn set_accounting_undo_data(
            &mut self,
            id: Id<Block>,
            undo: &AccountingBlockUndo,
        ) -> crate::Result<()>;
        fn del_accounting_undo_data(&mut self, id: Id<Block>) -> crate::Result<()>;

        fn apply_accounting_delta(
            &mut self,
            id: Id<Block>,
            delta: &PoSAccountingDeltaData,
        ) -> crate::Result<()>;

        fn del_accounting_delta(&mut self, id: Id<Block>) -> crate::Result<()>;

        fn set_accounting_epoch_undo_delta(
            &mut self,
            epoch_index: EpochIndex,
            undo: &DeltaMergeUndo,
        ) -> crate::Result<()>;

        fn del_accounting_epoch_undo_delta(&mut self, epoch_index: EpochIndex) -> crate::Result<()>;
    }
}

impl<B: storage::Backend> UtxosStorageWrite for Store<B> {
    delegate_to_transaction! {
        fn set_utxo(&mut self, outpoint: &OutPoint, entry: Utxo) -> crate::Result<()>;
        fn del_utxo(&mut self, outpoint: &OutPoint) -> crate::Result<()>;
        fn set_best_block_for_utxos(&mut self, block_id: &Id<GenBlock>) -> crate::Result<()>;
        fn set_undo_data(&mut self, id: Id<Block>, undo: &UtxosBlockUndo) -> crate::Result<()>;
        fn del_undo_data(&mut self, id: Id<Block>) -> crate::Result<()>;
    }
}

impl<B: storage::Backend> PoSAccountingStorageWrite<TipStorageTag> for Store<B> {
    fn set_pool_balance(&mut self, pool_id: PoolId, amount: Amount) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<TipStorageTag>::set_pool_balance(&mut tx, pool_id, amount)?;
        tx.commit()
    }
    fn del_pool_balance(&mut self, pool_id: PoolId) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<TipStorageTag>::del_pool_balance(&mut tx, pool_id)?;
        tx.commit()
    }

    fn set_pool_data(&mut self, pool_id: PoolId, pool_data: &PoolData) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<TipStorageTag>::set_pool_data(&mut tx, pool_id, pool_data)?;
        tx.commit()
    }

    fn del_pool_data(&mut self, pool_id: PoolId) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<TipStorageTag>::del_pool_data(&mut tx, pool_id)?;
        tx.commit()
    }

    fn set_delegation_balance(
        &mut self,
        delegation_target: DelegationId,
        amount: Amount,
    ) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<TipStorageTag>::set_delegation_balance(
            &mut tx,
            delegation_target,
            amount,
        )?;
        tx.commit()
    }

    fn del_delegation_balance(&mut self, delegation_target: DelegationId) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<TipStorageTag>::del_delegation_balance(
            &mut tx,
            delegation_target,
        )?;
        tx.commit()
    }

    fn set_delegation_data(
        &mut self,
        delegation_target: DelegationId,
        delegation_data: &DelegationData,
    ) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<TipStorageTag>::set_delegation_data(
            &mut tx,
            delegation_target,
            delegation_data,
        )?;
        tx.commit()
    }

    fn del_delegation_data(
        &mut self,
        delegation_id: DelegationId,
    ) -> Result<(), chainstate_types::storage_result::Error> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<TipStorageTag>::del_delegation_data(&mut tx, delegation_id)?;
        tx.commit()
    }

    fn set_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
        amount: Amount,
    ) -> Result<(), chainstate_types::storage_result::Error> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<TipStorageTag>::set_pool_delegation_share(
            &mut tx,
            pool_id,
            delegation_id,
            amount,
        )?;
        tx.commit()
    }

    fn del_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<(), chainstate_types::storage_result::Error> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<TipStorageTag>::del_pool_delegation_share(
            &mut tx,
            pool_id,
            delegation_id,
        )?;
        tx.commit()
    }
}

impl<B: storage::Backend> PoSAccountingStorageWrite<SealedStorageTag> for Store<B> {
    fn set_pool_balance(&mut self, pool_id: PoolId, amount: Amount) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<SealedStorageTag>::set_pool_balance(&mut tx, pool_id, amount)?;
        tx.commit()
    }
    fn del_pool_balance(&mut self, pool_id: PoolId) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<SealedStorageTag>::del_pool_balance(&mut tx, pool_id)?;
        tx.commit()
    }

    fn set_pool_data(&mut self, pool_id: PoolId, pool_data: &PoolData) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<SealedStorageTag>::set_pool_data(&mut tx, pool_id, pool_data)?;
        tx.commit()
    }

    fn del_pool_data(&mut self, pool_id: PoolId) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<SealedStorageTag>::del_pool_data(&mut tx, pool_id)?;
        tx.commit()
    }

    fn del_delegation_balance(&mut self, delegation_target: DelegationId) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<SealedStorageTag>::del_delegation_balance(
            &mut tx,
            delegation_target,
        )?;
        tx.commit()
    }

    fn set_delegation_balance(
        &mut self,
        delegation_target: DelegationId,
        amount: Amount,
    ) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<SealedStorageTag>::set_delegation_balance(
            &mut tx,
            delegation_target,
            amount,
        )?;
        tx.commit()
    }

    fn set_delegation_data(
        &mut self,
        delegation_target: DelegationId,
        delegation_data: &DelegationData,
    ) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<SealedStorageTag>::set_delegation_data(
            &mut tx,
            delegation_target,
            delegation_data,
        )?;
        tx.commit()
    }

    fn del_delegation_data(
        &mut self,
        delegation_id: DelegationId,
    ) -> Result<(), chainstate_types::storage_result::Error> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<SealedStorageTag>::del_delegation_data(&mut tx, delegation_id)?;
        tx.commit()
    }

    fn set_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
        amount: Amount,
    ) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<SealedStorageTag>::set_pool_delegation_share(
            &mut tx,
            pool_id,
            delegation_id,
            amount,
        )?;
        tx.commit()
    }

    fn del_pool_delegation_share(
        &mut self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> crate::Result<()> {
        let mut tx = self.transaction_rw(None)?;
        PoSAccountingStorageWrite::<SealedStorageTag>::del_pool_delegation_share(
            &mut tx,
            pool_id,
            delegation_id,
        )?;
        tx.commit()
    }
}

#[cfg(test)]
mod test;
