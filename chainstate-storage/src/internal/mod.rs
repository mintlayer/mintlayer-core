// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub mod utxo_db;

use chainstate_types::block_index::BlockIndex;
use chainstate_types::epoch_data::EpochData;
use common::chain::transaction::{Transaction, TxMainChainIndex, TxMainChainPosition};
use common::chain::{Block, GenBlock, OutPoint, OutPointSourceId};
use common::primitives::{BlockHeight, Id, Idable};
use serialization::{Codec, Decode, DecodeAll, Encode};
use storage::traits::{self, MapMut, MapRef, TransactionRo, TransactionRw};
use utxo::utxo_storage::{UtxosStorageRead, UtxosStorageWrite};
use utxo::{BlockUndo, Utxo};

use crate::{BlockchainStorage, BlockchainStorageRead, BlockchainStorageWrite, Transactional};

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
}

storage::decl_schema! {
    // Database schema for blockchain storage
    pub(crate) Schema {
        // Storage for individual values.
        pub DBValue: Single,
        // Storage for blocks.
        pub DBBlock: Single,
        // Store tag for blocks indexes.
        pub DBBlockIndex: Single,
        // Storage for transaction indices.
        pub DBTxIndex: Single,
        // Storage for block IDs indexed by block height.
        pub DBBlockByHeight: Single,
        // Store for Utxo Entries
        pub DBUtxo: Single,
        // Store for BlockUndo
        pub DBBlockUndo: Single,
        // Store for EpochData
        pub DBEpochData: Single
    }
}

type RoTxImpl<'tx, B> = <B as traits::Transactional<'tx, Schema>>::TransactionRo;
type RwTxImpl<'tx, B> = <B as traits::Transactional<'tx, Schema>>::TransactionRw;

/// Store for blockchain data, parametrized over the backend B
#[derive(Clone)]
pub struct Store<B>(B);

/// Store for blockchain data
impl<B: Default + for<'tx> traits::Transactional<'tx, Schema>> Store<B> {
    /// New empty storage
    pub fn new_empty() -> crate::Result<Self> {
        let mut store = Self(B::default());
        store.set_storage_version(1)?;
        Ok(store)
    }
}

impl<'tx, B: traits::Transactional<'tx, Schema>> crate::Transactional<'tx> for Store<B> {
    type TransactionRo = StoreTx<RoTxImpl<'tx, B>>;
    type TransactionRw = StoreTx<RwTxImpl<'tx, B>>;

    fn transaction_ro<'st: 'tx>(&'st self) -> Self::TransactionRo {
        StoreTx(traits::Transactional::transaction_ro(&self.0))
    }

    fn transaction_rw<'st: 'tx>(&'st self) -> Self::TransactionRw {
        StoreTx(traits::Transactional::transaction_rw(&self.0))
    }
}

impl<B: for<'tx> traits::Transactional<'tx, Schema>> BlockchainStorage for Store<B> {}

macro_rules! delegate_to_transaction {
    ($(fn $f:ident $args:tt -> $ret:ty;)*) => {
        $(delegate_to_transaction!(@SELF [$f ($ret)] $args);)*
    };
    (@SELF $done:tt (&self $(, $($rest:tt)*)?)) => {
        delegate_to_transaction!(
            @BODY transaction_ro (Ok) $done ($($($rest)*)?)
        );
    };
    (@SELF $done:tt (&mut self $(, $($rest:tt)*)?)) => {
        delegate_to_transaction!(
            @BODY transaction_rw (storage::commit) mut $done ($($($rest)*)?)
        );
    };
    (@BODY $txfunc:ident ($commit:path) $($mut:ident)?
        [$f:ident ($ret:ty)]
        ($($arg:ident: $aty:ty),* $(,)?)
    ) => {
        fn $f(&$($mut)? self $(, $arg: $aty)*) -> $ret {
            #[allow(clippy::needless_question_mark)]
            self.$txfunc().run(|tx| $commit(tx.$f($($arg),*)?))
        }
    };
}

impl<B: for<'tx> traits::Transactional<'tx, Schema>> BlockchainStorageRead for Store<B> {
    delegate_to_transaction! {
            fn get_storage_version(&self) -> crate::Result<u32>;
            fn get_best_block_id(&self) -> crate::Result<Option<Id<GenBlock>>>;
            fn get_block_index(&self, id: &Id<Block>) -> crate::Result<Option<BlockIndex>>;
            fn get_block(&self, id: Id<Block>) -> crate::Result<Option<Block>>;

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

            fn get_epoch_data(&self, epoch_index: u64) -> crate::Result<Option<EpochData>>;
    }
}

impl<B: for<'tx> traits::Transactional<'tx, Schema>> UtxosStorageRead for Store<B> {
    delegate_to_transaction! {
        fn get_utxo(&self, outpoint: &OutPoint) -> crate::Result<Option<Utxo>>;
        fn get_best_block_for_utxos(&self) -> crate::Result<Option<Id<GenBlock>>>;
        fn get_undo_data(&self, id: Id<Block>) -> crate::Result<Option<BlockUndo>>;
    }
}

impl<B: for<'tx> traits::Transactional<'tx, Schema>> BlockchainStorageWrite for Store<B> {
    delegate_to_transaction! {
        fn set_storage_version(&mut self, version: u32) -> crate::Result<()>;
        fn set_best_block_id(&mut self, id: &Id<GenBlock>) -> crate::Result<()>;
        fn set_block_index(&mut self, block_index: &BlockIndex) -> crate::Result<()>;
        fn add_block(&mut self, block: &Block) -> crate::Result<()>;
        fn del_block(&mut self, id: Id<Block>) -> crate::Result<()>;

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

        fn set_epoch_data(&mut self, epoch_index: u64, epoch_data: &EpochData) -> crate::Result<()>;

        fn del_epoch_data(&mut self, epoch_index: u64) -> crate::Result<()>;
    }
}

impl<B: for<'tx> traits::Transactional<'tx, Schema>> UtxosStorageWrite for Store<B> {
    delegate_to_transaction! {
        fn set_utxo(&mut self, outpoint: &OutPoint, entry: Utxo) -> crate::Result<()>;
        fn del_utxo(&mut self, outpoint: &OutPoint) -> crate::Result<()>;
        fn set_best_block_for_utxos(&mut self, block_id: &Id<GenBlock>) -> crate::Result<()>;
        fn set_undo_data(&mut self, id: Id<Block>, undo: &BlockUndo) -> crate::Result<()>;
        fn del_undo_data(&mut self, id: Id<Block>) -> crate::Result<()>;
    }
}

/// A wrapper around a storage transaction type
pub struct StoreTx<T>(T);

/// Blockchain data storage transaction
impl<Tx: for<'a> traits::GetMapRef<'a, Schema>> BlockchainStorageRead for StoreTx<Tx> {
    fn get_storage_version(&self) -> crate::Result<u32> {
        self.read_value::<well_known::StoreVersion>().map(|v| v.unwrap_or_default())
    }

    fn get_block_index(&self, id: &Id<Block>) -> crate::Result<Option<BlockIndex>> {
        self.read::<DBBlockIndex, _, _>(id.as_ref())
    }

    /// Get the hash of the best block
    fn get_best_block_id(&self) -> crate::Result<Option<Id<GenBlock>>> {
        self.read_value::<well_known::BestBlockId>()
    }

    fn get_block(&self, id: Id<Block>) -> crate::Result<Option<Block>> {
        self.read::<DBBlock, _, _>(id.as_ref())
    }

    fn get_mainchain_tx_index(
        &self,
        tx_id: &OutPointSourceId,
    ) -> crate::Result<Option<TxMainChainIndex>> {
        self.read::<DBTxIndex, _, _>(&tx_id.encode())
    }

    fn get_mainchain_tx_by_position(
        &self,
        tx_index: &TxMainChainPosition,
    ) -> crate::Result<Option<Transaction>> {
        let block_id = tx_index.block_id();
        match self.0.get::<DBBlock, _>().get(block_id.as_ref()) {
            Err(e) => Err(e.into()),
            Ok(None) => Ok(None),
            Ok(Some(block)) => {
                let begin = tx_index.byte_offset_in_block() as usize;
                let end = begin + tx_index.serialized_size() as usize;
                let encoded_tx = block.get(begin..end).expect("Transaction outside of block range");
                let tx =
                    Transaction::decode_all(&mut &*encoded_tx).expect("Invalid tx encoding in DB");
                Ok(Some(tx))
            }
        }
    }

    fn get_block_id_by_height(&self, height: &BlockHeight) -> crate::Result<Option<Id<GenBlock>>> {
        self.read::<DBBlockByHeight, _, _>(&height.encode())
    }

    fn get_epoch_data(&self, epoch_index: u64) -> crate::Result<Option<EpochData>> {
        self.read::<DBEpochData, _, _>(&epoch_index.encode())
    }
}

impl<Tx: for<'a> traits::GetMapRef<'a, Schema>> UtxosStorageRead for StoreTx<Tx> {
    fn get_utxo(&self, outpoint: &OutPoint) -> crate::Result<Option<Utxo>> {
        self.read::<DBUtxo, _, _>(&outpoint.encode())
    }

    fn get_best_block_for_utxos(&self) -> crate::Result<Option<Id<GenBlock>>> {
        self.read_value::<well_known::UtxosBestBlockId>()
    }

    fn get_undo_data(&self, id: Id<Block>) -> crate::Result<Option<BlockUndo>> {
        self.read::<DBBlockUndo, _, _>(id.as_ref())
    }
}

impl<Tx: for<'a> traits::GetMapMut<'a, Schema>> BlockchainStorageWrite for StoreTx<Tx> {
    fn set_storage_version(&mut self, version: u32) -> crate::Result<()> {
        self.write_value::<well_known::StoreVersion>(&version)
    }

    fn set_best_block_id(&mut self, id: &Id<GenBlock>) -> crate::Result<()> {
        self.write_value::<well_known::BestBlockId>(id)
    }

    fn add_block(&mut self, block: &Block) -> crate::Result<()> {
        self.write::<DBBlock, _, _>(block.get_id().encode(), block)
    }

    fn del_block(&mut self, id: Id<Block>) -> crate::Result<()> {
        self.0.get_mut::<DBBlock, _>().del(id.as_ref()).map_err(Into::into)
    }

    fn set_block_index(&mut self, block_index: &BlockIndex) -> crate::Result<()> {
        self.write::<DBBlockIndex, _, _>(block_index.block_id().encode(), block_index)
    }

    fn set_mainchain_tx_index(
        &mut self,
        tx_id: &OutPointSourceId,
        tx_index: &TxMainChainIndex,
    ) -> crate::Result<()> {
        self.write::<DBTxIndex, _, _>(tx_id.encode(), tx_index)
    }

    fn del_mainchain_tx_index(&mut self, tx_id: &OutPointSourceId) -> crate::Result<()> {
        self.0.get_mut::<DBTxIndex, _>().del(&tx_id.encode()).map_err(Into::into)
    }

    fn set_block_id_at_height(
        &mut self,
        height: &BlockHeight,
        block_id: &Id<GenBlock>,
    ) -> crate::Result<()> {
        self.write::<DBBlockByHeight, _, _>(height.encode(), block_id)
    }

    fn del_block_id_at_height(&mut self, height: &BlockHeight) -> crate::Result<()> {
        self.0.get_mut::<DBBlockByHeight, _>().del(&height.encode()).map_err(Into::into)
    }

    fn set_epoch_data(&mut self, epoch_index: u64, epoch_data: &EpochData) -> crate::Result<()> {
        self.write::<DBEpochData, _, _>(epoch_index.encode(), &epoch_data)
    }

    fn del_epoch_data(&mut self, epoch_index: u64) -> crate::Result<()> {
        self.0
            .get_mut::<DBEpochData, _>()
            .del(&epoch_index.encode())
            .map_err(Into::into)
    }
}

impl<Tx: for<'a> traits::GetMapMut<'a, Schema>> UtxosStorageWrite for StoreTx<Tx> {
    fn set_utxo(&mut self, outpoint: &OutPoint, entry: Utxo) -> crate::Result<()> {
        let key = outpoint.encode();
        self.write::<DBUtxo, _, _>(key, &entry)
    }

    fn del_utxo(&mut self, outpoint: &OutPoint) -> crate::Result<()> {
        let key = outpoint.encode();
        self.0.get_mut::<DBUtxo, _>().del(&key).map_err(Into::into)
    }

    fn set_best_block_for_utxos(&mut self, block_id: &Id<GenBlock>) -> crate::Result<()> {
        self.write_value::<well_known::UtxosBestBlockId>(block_id)
    }

    fn set_undo_data(&mut self, id: Id<Block>, undo: &BlockUndo) -> crate::Result<()> {
        self.write::<DBBlockUndo, _, _>(id.encode(), undo)
    }

    fn del_undo_data(&mut self, id: Id<Block>) -> crate::Result<()> {
        self.0.get_mut::<DBBlockUndo, _>().del(id.as_ref()).map_err(Into::into)
    }
}

impl<'a, Tx: traits::GetMapRef<'a, Schema>> StoreTx<Tx> {
    // Read a value from the database and decode it
    fn read<DBIdx, I, T>(&'a self, key: &[u8]) -> crate::Result<Option<T>>
    where
        DBIdx: storage::schema::DBIndex<Kind = storage::schema::Single>,
        Schema: storage::schema::HasDBIndex<DBIdx, I>,
        T: Decode,
    {
        let col = self.0.get::<DBIdx, I>();
        let data = col.get(key).map_err(crate::Error::from)?;
        Ok(data.map(|d| T::decode_all(&mut &*d).expect("Cannot decode a database value")))
    }

    // Read a value for a well-known entry
    fn read_value<E: well_known::Entry>(&'a self) -> crate::Result<Option<E::Value>> {
        self.read::<DBValue, _, _>(E::KEY)
    }
}

impl<'a, Tx: traits::GetMapMut<'a, Schema>> StoreTx<Tx> {
    // Encode a value and write it to the database
    fn write<DBIdx, I, T>(&'a mut self, key: Vec<u8>, value: &T) -> crate::Result<()>
    where
        DBIdx: storage::schema::DBIndex<Kind = storage::schema::Single>,
        Schema: storage::schema::HasDBIndex<DBIdx, I>,
        T: Encode,
    {
        self.0.get_mut::<DBIdx, I>().put(key, value.encode()).map_err(Into::into)
    }

    // Write a value for a well-known entry
    fn write_value<E: well_known::Entry>(&'a mut self, val: &E::Value) -> crate::Result<()> {
        self.write::<DBValue, _, _>(E::KEY.to_vec(), val)
    }
}

impl<T: traits::TransactionRw<Error = storage::Error>> traits::TransactionRw for StoreTx<T> {
    type Error = crate::Error;

    fn commit(self) -> crate::Result<()> {
        self.0.commit().map_err(Into::into)
    }

    fn abort(self) -> crate::Result<()> {
        self.0.abort().map_err(Into::into)
    }
}

impl<T: traits::TransactionRo<Error = storage::Error>> traits::TransactionRo for StoreTx<T> {
    type Error = crate::Error;

    fn finalize(self) -> crate::Result<()> {
        self.0.finalize().map_err(Into::into)
    }
}

#[cfg(test)]
mod test;
