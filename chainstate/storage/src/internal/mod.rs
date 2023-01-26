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

pub mod utxo_db;

use chainstate_types::BlockIndex;
use common::{
    chain::{
        block::BlockReward,
        tokens::{TokenAuxiliaryData, TokenId},
        transaction::{Transaction, TxMainChainIndex, TxMainChainPosition},
        Block, GenBlock, OutPoint, OutPointSourceId,
    },
    primitives::{Amount, BlockHeight, Id, Idable, H256},
};
use pos_accounting::{
    AccountingBlockUndo, DelegationData, DelegationId, PoSAccountingDeltaData,
    PoSAccountingStorageRead, PoSAccountingStorageWrite, PoolData, PoolId,
};
use serialization::{Codec, Decode, DecodeAll, Encode, EncodeLike};
use std::collections::BTreeMap;
use storage::schema;
use utxo::{Utxo, UtxosBlockUndo, UtxosStorageRead, UtxosStorageWrite};

use crate::{
    schema::{self as db, Schema},
    BlockchainStorage, BlockchainStorageRead, BlockchainStorageWrite, SealedStorageTag,
    TipStorageTag, TransactionRw, Transactional,
};

mod well_known {
    use super::{Codec, GenBlock, Id};

    /// Pre-defined database keys
    pub trait Entry {
        /// Key for this entry
        const KEY: &'static [u8];
        /// Value type for this entry
        type Value: Codec;
    }

    macro_rules! declare_entry {
        ($name:ident: $type:ty) => {
            pub struct $name;
            impl Entry for $name {
                const KEY: &'static [u8] = stringify!($name).as_bytes();
                type Value = $type;
            }
        };
    }

    declare_entry!(StoreVersion: u32);
    declare_entry!(BestBlockId: Id<GenBlock>);
    declare_entry!(UtxosBestBlockId: Id<GenBlock>);
    declare_entry!(TxIndexEnabled: bool);
}

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
    type TransactionRo = StoreTxRo<'tx, B>;
    type TransactionRw = StoreTxRw<'tx, B>;

    fn transaction_ro<'st: 'tx>(&'st self) -> crate::Result<Self::TransactionRo> {
        self.0.transaction_ro().map_err(crate::Error::from).map(StoreTxRo)
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

        fn set_accounting_delta(
            &mut self,
            id: Id<Block>,
            delta: &PoSAccountingDeltaData,
        ) -> crate::Result<()>;

        fn del_accounting_delta(&mut self, id: Id<Block>) -> crate::Result<()>;
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

/// Read-only chainstate storage transaction
pub struct StoreTxRo<'st, B: storage::Backend>(storage::TransactionRo<'st, B, Schema>);

/// Read-write chainstate storage transaction
pub struct StoreTxRw<'st, B: storage::Backend>(storage::TransactionRw<'st, B, Schema>);

macro_rules! impl_read_ops {
    ($TxType:ident) => {
        /// Blockchain data storage transaction
        impl<'st, B: storage::Backend> BlockchainStorageRead for $TxType<'st, B> {
            fn get_storage_version(&self) -> crate::Result<u32> {
                self.read_value::<well_known::StoreVersion>().map(|v| v.unwrap_or_default())
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

            fn get_block_reward(
                &self,
                block_index: &BlockIndex,
            ) -> crate::Result<Option<BlockReward>> {
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

            fn get_mainchain_tx_index(
                &self,
                tx_id: &OutPointSourceId,
            ) -> crate::Result<Option<TxMainChainIndex>> {
                self.read::<db::DBTxIndex, _, _>(tx_id)
            }

            fn get_mainchain_tx_by_position(
                &self,
                tx_index: &TxMainChainPosition,
            ) -> crate::Result<Option<Transaction>> {
                let block_id = tx_index.block_id();
                match self.0.get::<db::DBBlock, _>().get(block_id) {
                    Err(e) => Err(e.into()),
                    Ok(None) => Ok(None),
                    Ok(Some(block)) => {
                        let block = block.bytes();
                        let begin = tx_index.byte_offset_in_block() as usize;
                        let encoded_tx =
                            block.get(begin..).expect("Transaction outside of block range");
                        let tx = Transaction::decode(&mut &*encoded_tx)
                            .expect("Invalid tx encoding in DB");
                        Ok(Some(tx))
                    }
                }
            }

            fn get_block_id_by_height(
                &self,
                height: &BlockHeight,
            ) -> crate::Result<Option<Id<GenBlock>>> {
                self.read::<db::DBBlockByHeight, _, _>(height)
            }

            fn get_token_aux_data(
                &self,
                token_id: &TokenId,
            ) -> crate::Result<Option<TokenAuxiliaryData>> {
                self.read::<db::DBTokensAuxData, _, _>(&token_id)
            }

            fn get_token_id(
                &self,
                issuance_tx_id: &Id<Transaction>,
            ) -> crate::Result<Option<TokenId>> {
                self.read::<db::DBIssuanceTxVsTokenId, _, _>(&issuance_tx_id)
            }

            fn get_block_tree_by_height(
                &self,
            ) -> crate::Result<BTreeMap<BlockHeight, Vec<Id<Block>>>> {
                let map = self.0.get::<db::DBBlockIndex, _>();
                let items = map.prefix_iter_decoded(&())?;

                let mut result = BTreeMap::<BlockHeight, Vec<Id<Block>>>::new();
                for (_, bi) in items {
                    result.entry(bi.block_height()).or_default().push(*bi.block_id());
                }

                Ok(result)
            }

            fn get_accounting_undo(
                &self,
                id: Id<Block>,
            ) -> crate::Result<Option<AccountingBlockUndo>> {
                self.read::<db::DBAccountingBlockUndo, _, _>(id)
            }

            fn get_accounting_delta(
                &self,
                id: Id<Block>,
            ) -> crate::Result<Option<PoSAccountingDeltaData>> {
                self.read::<db::DBAccountingBlockDelta, _, _>(id)
            }
        }

        impl<'st, B: storage::Backend> UtxosStorageRead for $TxType<'st, B> {
            fn get_utxo(&self, outpoint: &OutPoint) -> crate::Result<Option<Utxo>> {
                self.read::<db::DBUtxo, _, _>(outpoint)
            }

            fn get_best_block_for_utxos(&self) -> crate::Result<Option<Id<GenBlock>>> {
                self.read_value::<well_known::UtxosBestBlockId>()
            }

            fn get_undo_data(&self, id: Id<Block>) -> crate::Result<Option<UtxosBlockUndo>> {
                self.read::<db::DBUtxosBlockUndo, _, _>(id)
            }
        }

        impl<'st, B: storage::Backend> PoSAccountingStorageRead<TipStorageTag> for $TxType<'st, B> {
            fn get_pool_balance(&self, pool_id: PoolId) -> crate::Result<Option<Amount>> {
                self.read::<db::DBAccountingPoolBalancesTip, _, _>(pool_id)
            }

            fn get_pool_data(&self, pool_id: PoolId) -> crate::Result<Option<PoolData>> {
                self.read::<db::DBAccountingPoolDataTip, _, _>(pool_id)
            }

            fn get_delegation_balance(
                &self,
                delegation_id: DelegationId,
            ) -> crate::Result<Option<Amount>> {
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
                let result =
                    range.map(|((_pool_id, del_id), v)| (*del_id, *v)).collect::<BTreeMap<_, _>>();
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
            for $TxType<'st, B>
        {
            fn get_pool_balance(&self, pool_id: PoolId) -> crate::Result<Option<Amount>> {
                self.read::<db::DBAccountingPoolBalancesSealed, _, _>(pool_id)
            }

            fn get_pool_data(&self, pool_id: PoolId) -> crate::Result<Option<PoolData>> {
                self.read::<db::DBAccountingPoolDataSealed, _, _>(pool_id)
            }

            fn get_delegation_balance(
                &self,
                delegation_id: DelegationId,
            ) -> crate::Result<Option<Amount>> {
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
                    .map(|(k, v)| {
                        crate::Result::<((PoolId, DelegationId), Amount)>::Ok((k, v.decode()))
                    })
                    .collect::<Result<BTreeMap<(PoolId, DelegationId), Amount>, _>>()?;

                let range_start = (pool_id, DelegationId::new(H256::zero()));
                let range_end = (pool_id, DelegationId::new(H256::repeat_byte(0xFF)));
                let range = all_shares.range(range_start..=range_end);
                let result =
                    range.map(|((_pool_id, del_id), v)| (*del_id, *v)).collect::<BTreeMap<_, _>>();
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
                self.read::<db::DBAccountingPoolDelegationSharesSealed, _, _>((
                    pool_id,
                    delegation_id,
                ))
            }
        }

        impl<'st, B: storage::Backend> $TxType<'st, B> {
            // Read a value from the database and decode it
            fn read<DbMap, I, K>(&self, key: K) -> crate::Result<Option<DbMap::Value>>
            where
                DbMap: schema::DbMap,
                Schema: schema::HasDbMap<DbMap, I>,
                K: EncodeLike<DbMap::Key>,
            {
                let map = self.0.get::<DbMap, I>();
                map.get(key).map_err(crate::Error::from).map(|x| x.map(|x| x.decode()))
            }

            // Read a value for a well-known entry
            fn read_value<E: well_known::Entry>(&self) -> crate::Result<Option<E::Value>> {
                self.read::<db::DBValue, _, _>(E::KEY).map(|x| {
                    x.map(|x| {
                        E::Value::decode_all(&mut x.as_ref())
                            .expect("db values to be encoded correctly")
                    })
                })
            }
        }
    };
}

impl_read_ops!(StoreTxRo);
impl_read_ops!(StoreTxRw);

impl<'st, B: storage::Backend> BlockchainStorageWrite for StoreTxRw<'st, B> {
    fn set_storage_version(&mut self, version: u32) -> crate::Result<()> {
        self.write_value::<well_known::StoreVersion>(&version)
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

    fn set_is_mainchain_tx_index_enabled(&mut self, enabled: bool) -> crate::Result<()> {
        self.write_value::<well_known::TxIndexEnabled>(&enabled)
    }

    fn set_mainchain_tx_index(
        &mut self,
        tx_id: &OutPointSourceId,
        tx_index: &TxMainChainIndex,
    ) -> crate::Result<()> {
        self.write::<db::DBTxIndex, _, _, _>(tx_id, tx_index)
    }

    fn del_mainchain_tx_index(&mut self, tx_id: &OutPointSourceId) -> crate::Result<()> {
        self.0.get_mut::<db::DBTxIndex, _>().del(tx_id).map_err(Into::into)
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

    fn set_accounting_delta(
        &mut self,
        id: Id<Block>,
        delta: &PoSAccountingDeltaData,
    ) -> crate::Result<()> {
        self.write::<db::DBAccountingBlockDelta, _, _, _>(id, delta)
    }

    fn del_accounting_delta(&mut self, id: Id<Block>) -> crate::Result<()> {
        self.0.get_mut::<db::DBAccountingBlockDelta, _>().del(id).map_err(Into::into)
    }

    // collect is needed to obey borrow checker rules
    //#[allow(clippy::needless_collect)]
    //fn del_pre_seal_accounting_delta_undo_for_epoch(
    //    &mut self,
    //    epoch_index: u64,
    //) -> crate::Result<()> {
    //    let epoch_deltas = self
    //        .0
    //        .get::<db::DBAccountingPreSealDataUndo, _>()
    //        .prefix_iter(&(epoch_index,))?
    //        .map(|(k, _)| k)
    //        .collect::<Vec<_>>();
    //    epoch_deltas.into_iter().try_for_each(|k| {
    //        self.0
    //            .get_mut::<db::DBAccountingPreSealDataUndo, _>()
    //            .del(k)
    //            .map_err(Into::into)
    //    })
    //}
}

impl<'st, B: storage::Backend> UtxosStorageWrite for StoreTxRw<'st, B> {
    fn set_utxo(&mut self, outpoint: &OutPoint, entry: Utxo) -> crate::Result<()> {
        self.write::<db::DBUtxo, _, _, _>(outpoint, entry)
    }

    fn del_utxo(&mut self, outpoint: &OutPoint) -> crate::Result<()> {
        self.0.get_mut::<db::DBUtxo, _>().del(outpoint).map_err(Into::into)
    }

    fn set_best_block_for_utxos(&mut self, block_id: &Id<GenBlock>) -> crate::Result<()> {
        self.write_value::<well_known::UtxosBestBlockId>(block_id)
    }

    fn set_undo_data(&mut self, id: Id<Block>, undo: &UtxosBlockUndo) -> crate::Result<()> {
        self.write::<db::DBUtxosBlockUndo, _, _, _>(id, undo)
    }

    fn del_undo_data(&mut self, id: Id<Block>) -> crate::Result<()> {
        self.0.get_mut::<db::DBUtxosBlockUndo, _>().del(id).map_err(Into::into)
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

impl<'st, B: storage::Backend> StoreTxRw<'st, B> {
    // Encode a value and write it to the database
    fn write<DbMap, I, K, V>(&mut self, key: K, value: V) -> crate::Result<()>
    where
        DbMap: schema::DbMap,
        Schema: schema::HasDbMap<DbMap, I>,
        K: EncodeLike<<DbMap as schema::DbMap>::Key>,
        V: EncodeLike<<DbMap as schema::DbMap>::Value>,
    {
        self.0.get_mut::<DbMap, I>().put(key, value).map_err(Into::into)
    }

    // Write a value for a well-known entry
    fn write_value<E: well_known::Entry>(&mut self, val: &E::Value) -> crate::Result<()> {
        self.write::<db::DBValue, _, _, _>(E::KEY, val.encode())
    }
}

impl<'st, B: storage::Backend> crate::TransactionRo for StoreTxRo<'st, B> {
    fn close(self) {
        self.0.close()
    }
}

impl<'st, B: storage::Backend> crate::TransactionRw for StoreTxRw<'st, B> {
    fn commit(self) -> crate::Result<()> {
        self.0.commit().map_err(Into::into)
    }

    fn abort(self) {
        self.0.abort()
    }
}

impl<'st, B: storage::Backend> crate::IsTransaction for StoreTxRo<'st, B> {}
impl<'st, B: storage::Backend> crate::IsTransaction for StoreTxRw<'st, B> {}

#[cfg(test)]
mod test;
