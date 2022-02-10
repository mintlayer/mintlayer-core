use common::chain::block::Block;
use common::chain::transaction::{Transaction, TxMainChainIndex, TxMainChainPosition};
use common::primitives::{BlockHeight, Id, Idable};
use parity_scale_codec::{Codec, Decode, DecodeAll, Encode};
use storage::traits::*;

use crate::BlockchainStorage;

mod well_known {
    use super::{Block, Codec, Id};

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
    declare_entry!(BestBlockId: Id<Block>);
}

// Type-level tags for individual key-value stores:
// Store tag for individual values.
struct DBValues;
// Store tag for blocks.
struct DBBlocks;
// Store tag for transaction indices.
struct DBTxIndices;
// Store for block IDs indexed by block height.
struct DBBlockByHeight;

impl storage::schema::Column for DBValues {
    const NAME: &'static str = "ValuesV0";
    type Kind = storage::schema::Single;
}

impl storage::schema::Column for DBBlocks {
    const NAME: &'static str = "BlocksV0";
    type Kind = storage::schema::Single;
}

impl storage::schema::Column for DBTxIndices {
    const NAME: &'static str = "TxIndicesV0";
    type Kind = storage::schema::Single;
}

impl storage::schema::Column for DBBlockByHeight {
    const NAME: &'static str = "BlkByHgtV0";
    type Kind = storage::schema::Single;
}

// Complete database schema
type Schema = (DBValues, (DBBlocks, (DBTxIndices, (DBBlockByHeight, ()))));

/// Persistent store for blockchain data
#[derive(Clone)]
pub struct Store(storage::Store<Schema>);

/// Store for blockchain data
impl Store {
    /// New empty storage
    pub fn new_empty() -> crate::Result<Self> {
        let mut store = Self(storage::Store::default());
        store.set_storage_version(1)?;
        Ok(store)
    }
}

impl<'st> Transactional<'st> for Store {
    type TransactionRo = StoreTxRw<'st>;
    type TransactionRw = StoreTxRw<'st>;

    fn start_transaction_ro(&'st self) -> Self::TransactionRo {
        StoreTxRw(self.0.start_transaction_rw())
    }

    fn start_transaction_rw(&'st self) -> Self::TransactionRw {
        StoreTxRw(self.0.start_transaction_rw())
    }
}

macro_rules! delegate_to_transaction {
    ($(fn $f:ident $args:tt -> $ret:ty;)*) => {
        $(delegate_to_transaction!(@SELF [$f ($ret)] $args);)*
    };
    (@SELF $done:tt (&self $(, $($rest:tt)*)?)) => {
        delegate_to_transaction!(@BODY transaction_ro (Ok) $done ($($($rest)*)?));
    };
    (@SELF $done:tt (&mut self $(, $($rest:tt)*)?)) => {
        delegate_to_transaction!(@BODY transaction_rw (storage::commit) mut $done ($($($rest)*)?));
    };
    (@BODY $txfunc:ident ($commit:path) $($mut:ident)?
        [$f:ident ($ret:ty)]
        ($($arg:ident: $aty:ty),* $(,)?)
    ) => {
        fn $f(&$($mut)? self $(, $arg: $aty)*) -> $ret {
            #[allow(clippy::needless_question_mark)]
            self.$txfunc(
                |tx| $commit(<Self as Transactional>::TransactionRw::$f(tx $(, $arg)*)?)
            )
        }
    };
}

impl BlockchainStorage for Store {
    delegate_to_transaction! {
        fn get_storage_version(&self) -> crate::Result<u32>;
        fn set_storage_version(&mut self, version: u32) -> crate::Result<()>;
        fn get_best_block_id(&self) -> crate::Result<Option<Id<Block>>>;
        fn set_best_block_id(&mut self, id: &Id<Block>) -> crate::Result<()>;
        fn get_block(&self, id: Id<Block>) -> crate::Result<Option<Block>>;
        fn add_block(&mut self, block: &Block) -> crate::Result<()>;
        fn del_block(&mut self, id: Id<Block>) -> crate::Result<()>;

        fn set_mainchain_tx_index(
            &mut self,
            tx_id: &Id<Transaction>,
            tx_index: &TxMainChainIndex,
        ) -> crate::Result<()>;

        fn get_mainchain_tx_index(
            &self,
            tx_id: &Id<Transaction>,
        ) -> crate::Result<Option<TxMainChainIndex>>;

        fn del_mainchain_tx_index(&mut self, tx_id: &Id<Transaction>) -> crate::Result<()>;

        fn get_mainchain_tx_by_position(
            &self,
            tx_index: &TxMainChainPosition,
        ) -> crate::Result<Option<Transaction>>;

        fn get_mainchain_tx(&self, tx: &Id<Transaction>) -> crate::Result<Option<Transaction>>;

        fn get_block_id_by_height(
            &self,
            height: &BlockHeight,
        ) -> crate::Result<Option<Id<Block>>>;

        fn set_block_id_at_height(
            &mut self,
            height: &BlockHeight,
            block_id: &Id<Block>,
        ) -> crate::Result<()>;

        fn del_block_id_at_height(&mut self, height: &BlockHeight) -> crate::Result<()>;
    }
}

/// Transaction over blockchain data store
pub struct StoreTxRw<'st>(<storage::Store<Schema> as Transactional<'st>>::TransactionRw);

/// Blockchain data storage transaction
impl BlockchainStorage for StoreTxRw<'_> {
    /// Get storage version
    fn get_storage_version(&self) -> crate::Result<u32> {
        self.read_value::<well_known::StoreVersion>().map(|v| v.unwrap_or_default())
    }

    /// Set storage version
    fn set_storage_version(&mut self, version: u32) -> crate::Result<()> {
        self.write_value::<well_known::StoreVersion>(&version)
    }

    /// Get the hash of the best block
    fn get_best_block_id(&self) -> crate::Result<Option<Id<Block>>> {
        self.read_value::<well_known::BestBlockId>()
    }

    /// Set the hash of the best block
    fn set_best_block_id(&mut self, id: &Id<Block>) -> crate::Result<()> {
        self.write_value::<well_known::BestBlockId>(id)
    }

    /// Get block by its hash
    fn get_block(&self, id: Id<Block>) -> crate::Result<Option<Block>> {
        self.read::<DBBlocks, _, _>(id.as_ref())
    }

    /// Add a new block into the database
    fn add_block(&mut self, block: &Block) -> crate::Result<()> {
        self.write::<DBBlocks, _, _>(block.get_id().encode(), block)
    }

    /// Remove block from the database
    fn del_block(&mut self, id: Id<Block>) -> crate::Result<()> {
        self.0.get_mut::<DBBlocks, _>().del(id.as_ref()).map_err(Into::into)
    }

    /// Set state of the outputs of given transaction
    fn set_mainchain_tx_index(
        &mut self,
        tx_id: &Id<Transaction>,
        tx_index: &TxMainChainIndex,
    ) -> crate::Result<()> {
        self.write::<DBTxIndices, _, _>(tx_id.encode(), tx_index)
    }

    /// Get outputs state for given transaction in the mainchain
    fn get_mainchain_tx_index(
        &self,
        tx_id: &Id<Transaction>,
    ) -> crate::Result<Option<TxMainChainIndex>> {
        self.read::<DBTxIndices, _, _>(tx_id.as_ref())
    }

    /// Delete outputs state index associated with given transaction
    fn del_mainchain_tx_index(&mut self, tx_id: &Id<Transaction>) -> crate::Result<()> {
        self.0.get_mut::<DBTxIndices, _>().del(tx_id.as_ref()).map_err(Into::into)
    }

    /// Get transaction
    fn get_mainchain_tx_by_position(
        &self,
        tx_index: &TxMainChainPosition,
    ) -> crate::Result<Option<Transaction>> {
        let block_id = tx_index.get_block_id();
        match self.0.get::<DBBlocks, _>().get(block_id.as_ref()) {
            Err(e) => Err(e.into()),
            Ok(None) => Ok(None),
            Ok(Some(block)) => {
                let begin = tx_index.get_byte_offset_in_block() as usize;
                let end = begin + tx_index.get_serialized_size() as usize;
                let tx = block.get(begin..end).expect("Transaction outside of block range");
                let tx = Transaction::decode_all(tx).expect("Invalid tx encoding in DB");
                Ok(Some(tx))
            }
        }
    }

    fn get_mainchain_tx(&self, txid: &Id<Transaction>) -> crate::Result<Option<Transaction>> {
        self.get_mainchain_tx_index(txid)?.map_or(Ok(None), |i| {
            self.get_mainchain_tx_by_position(i.get_tx_position())
        })
    }

    /// Get mainchain block by its height
    fn get_block_id_by_height(&self, height: &BlockHeight) -> crate::Result<Option<Id<Block>>> {
        self.read::<DBBlockByHeight, _, _>(&height.encode())
    }

    /// Set the mainchain block at given height to be given block.
    fn set_block_id_at_height(
        &mut self,
        height: &BlockHeight,
        block_id: &Id<Block>,
    ) -> crate::Result<()> {
        self.write::<DBBlockByHeight, _, _>(height.encode(), block_id)
    }

    /// Remove block id from given mainchain height
    fn del_block_id_at_height(&mut self, height: &BlockHeight) -> crate::Result<()> {
        self.0.get_mut::<DBBlockByHeight, _>().del(&height.encode()).map_err(Into::into)
    }
}

impl StoreTxRw<'_> {
    // Read a value from the database and decode it
    fn read<Col, I, T>(&self, key: &[u8]) -> crate::Result<Option<T>>
    where
        Col: storage::schema::Column<Kind = storage::schema::Single>,
        Schema: storage::schema::HasColumn<Col, I>,
        T: Decode,
    {
        let col = self.0.get::<Col, I>();
        let data = col.get(key).map_err(crate::Error::from)?;
        Ok(data.map(|d| T::decode_all(d).expect("Cannot decode a database value")))
    }

    // Encode a value and write it to the database
    fn write<Col, I, T>(&mut self, key: Vec<u8>, value: &T) -> crate::Result<()>
    where
        Col: storage::schema::Column<Kind = storage::schema::Single>,
        Schema: storage::schema::HasColumn<Col, I>,
        T: Encode,
    {
        self.0.get_mut::<Col, I>().put(key, value.encode()).map_err(Into::into)
    }

    // Read a value for a well-known entry
    fn read_value<E: well_known::Entry>(&self) -> crate::Result<Option<E::Value>> {
        self.read::<DBValues, _, _>(E::KEY)
    }

    // Write a value for a well-known entry
    fn write_value<E: well_known::Entry>(&mut self, val: &E::Value) -> crate::Result<()> {
        self.write::<DBValues, _, _>(E::KEY.to_vec(), val)
    }
}

impl TransactionRw for StoreTxRw<'_> {
    type Error = crate::Error;

    fn commit(self) -> crate::Result<()> {
        self.0.commit().map_err(Into::into)
    }

    fn abort(self) -> crate::Result<()> {
        self.0.abort().map_err(Into::into)
    }
}

impl TransactionRo for StoreTxRw<'_> {
    type Error = crate::Error;

    fn finalize(self) -> crate::Result<()> {
        self.0.commit().map_err(Into::into)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use common::primitives::consensus_data::ConsensusData;

    #[test]
    #[cfg(not(loom))]
    fn test_storage_manipulation() {
        use common::primitives::H256;

        // Prepare some test data
        let tx0 = Transaction::new(0xaabbccdd, vec![], vec![], 12).unwrap();
        let tx1 = Transaction::new(0xbbccddee, vec![], vec![], 34).unwrap();
        let block0 = Block::new(
            vec![tx0.clone()],
            Id::new(&H256::default()),
            12,
            ConsensusData::None,
        )
        .unwrap();
        let block1 =
            Block::new(vec![tx1.clone()], block0.get_id(), 34, ConsensusData::None).unwrap();

        // Set up the store
        let mut store = Store::new_empty().unwrap();

        // Storage version manipulation
        assert_eq!(store.get_storage_version(), Ok(1));
        assert_eq!(store.set_storage_version(2), Ok(()));
        assert_eq!(store.get_storage_version(), Ok(2));

        // Storte is now empty, the block is not there
        assert_eq!(store.get_block(block0.get_id()), Ok(None));

        // Insert the first block and check it is there
        assert_eq!(store.add_block(&block0), Ok(()));
        assert_eq!(&store.get_block(block0.get_id()).unwrap().unwrap(), &block0);

        // Insert, remove, and reinsert the second block
        assert_eq!(store.get_block(block1.get_id()), Ok(None));
        assert_eq!(store.add_block(&block1), Ok(()));
        assert_eq!(&store.get_block(block0.get_id()).unwrap().unwrap(), &block0);
        assert_eq!(store.del_block(block1.get_id()), Ok(()));
        assert_eq!(store.get_block(block1.get_id()), Ok(None));
        assert_eq!(store.add_block(&block1), Ok(()));
        assert_eq!(&store.get_block(block0.get_id()).unwrap().unwrap(), &block0);

        // Test the transaction extraction from a block
        let enc_tx0 = tx0.encode();
        let enc_block0 = block0.encode();
        let offset_tx0 = enc_block0
            .windows(enc_tx0.len())
            .enumerate()
            .find_map(|(i, d)| (d == enc_tx0).then(|| i))
            .unwrap();
        assert!(
            &enc_block0[offset_tx0..].starts_with(&enc_tx0),
            "Transaction format has changed, adjust the offset in this test",
        );
        let pos_tx0 = TxMainChainPosition::new(
            &block0.get_id().get(),
            offset_tx0 as u32,
            enc_tx0.len() as u32,
        );
        assert_eq!(
            &store.get_mainchain_tx_by_position(&pos_tx0).unwrap().unwrap(),
            &tx0
        );

        // Test setting and retrieving best chain id
        assert_eq!(store.get_best_block_id(), Ok(None));
        assert_eq!(store.set_best_block_id(&block0.get_id()), Ok(()));
        assert_eq!(store.get_best_block_id(), Ok(Some(block0.get_id())));
        assert_eq!(store.set_best_block_id(&block1.get_id()), Ok(()));
        assert_eq!(store.get_best_block_id(), Ok(Some(block1.get_id())));

        // Chain index operations
        let idx_tx0 = TxMainChainIndex::new(pos_tx0, 1).expect("Tx index creation failed");
        assert_eq!(store.get_mainchain_tx_index(&tx0.get_id()), Ok(None));
        assert_eq!(
            store.set_mainchain_tx_index(&tx0.get_id(), &idx_tx0),
            Ok(())
        );
        assert_eq!(
            store.get_mainchain_tx_index(&tx0.get_id()),
            Ok(Some(idx_tx0.clone()))
        );
        assert_eq!(store.del_mainchain_tx_index(&tx0.get_id()), Ok(()));
        assert_eq!(store.get_mainchain_tx_index(&tx0.get_id()), Ok(None));
        assert_eq!(
            store.set_mainchain_tx_index(&tx0.get_id(), &idx_tx0),
            Ok(())
        );

        // Retrieve transactions by ID using the index
        assert_eq!(store.get_mainchain_tx(&tx1.get_id()), Ok(None));
        assert_eq!(store.get_mainchain_tx(&tx0.get_id()), Ok(Some(tx0)));
    }

    #[test]
    fn get_set_transactions() {
        common::concurrency::model(|| {
            // Set up the store and initialize the version to 2
            let mut store = Store::new_empty().unwrap();
            assert_eq!(store.set_storage_version(2), Ok(()));

            // Concurrently bump version and run a transactiomn that reads the version twice.
            let thr1 = {
                let store = Store::clone(&store);
                common::thread::spawn(move || {
                    let _ = store.transaction_rw(|tx| {
                        let v = tx.get_storage_version()?;
                        tx.set_storage_version(v + 1)?;
                        storage::commit(())
                    });
                })
            };
            let thr0 = {
                let store = Store::clone(&store);
                common::thread::spawn(move || {
                    let tx_result = store.transaction_ro(|tx| {
                        let v1 = tx.get_storage_version()?;
                        let v2 = tx.get_storage_version()?;
                        assert!([2, 3].contains(&v1));
                        assert_eq!(v1, v2, "Version query in a transaction inconsistent");
                        Ok(())
                    });
                    assert!(tx_result.is_ok());
                })
            };

            let _ = thr0.join();
            let _ = thr1.join();
            assert_eq!(store.get_storage_version(), Ok(3));
        })
    }

    #[test]
    fn test_storage_transactions() {
        common::concurrency::model(|| {
            // Set up the store and initialize the version to 2
            let mut store = Store::new_empty().unwrap();
            assert_eq!(store.set_storage_version(2), Ok(()));

            // Concurrently bump version by 3 and 5 in two separate threads
            let thr0 = {
                let store = Store::clone(&store);
                common::thread::spawn(move || {
                    let tx_result = store.transaction_rw(|tx| {
                        let v = tx.get_storage_version()?;
                        tx.set_storage_version(v + 3)?;
                        storage::commit(())
                    });
                    assert!(tx_result.is_ok());
                })
            };
            let thr1 = {
                let store = Store::clone(&store);
                common::thread::spawn(move || {
                    let tx_result = store.transaction_rw(|tx| {
                        let v = tx.get_storage_version()?;
                        tx.set_storage_version(v + 5)?;
                        storage::commit(())
                    });
                    assert!(tx_result.is_ok());
                })
            };

            let _ = thr0.join();
            let _ = thr1.join();
            assert_eq!(store.get_storage_version(), Ok(10));
        })
    }

    #[test]
    fn test_storage_transactions_with_result_check() {
        common::concurrency::model(|| {
            // Set up the store and initialize the version to 2
            let mut store = Store::new_empty().unwrap();
            assert_eq!(store.set_storage_version(2), Ok(()));

            // Concurrently bump version by 3 and 5 in two separate threads
            let thr0 = {
                let store = Store::clone(&store);
                common::thread::spawn(move || {
                    let mut tx = store.start_transaction_rw();
                    let v = tx.get_storage_version().unwrap();
                    assert!(tx.set_storage_version(v + 3).is_ok());
                    assert!(tx.commit().is_ok());
                })
            };
            let thr1 = {
                let store = Store::clone(&store);
                common::thread::spawn(move || {
                    let mut tx = store.start_transaction_rw();
                    let v = tx.get_storage_version().unwrap();
                    assert!(tx.set_storage_version(v + 5).is_ok());
                    assert!(tx.commit().is_ok());
                })
            };

            let _ = thr0.join();
            let _ = thr1.join();
            assert_eq!(store.get_storage_version(), Ok(10));
        })
    }
}
