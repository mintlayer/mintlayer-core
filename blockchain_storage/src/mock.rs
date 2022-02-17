//! A mock version of the blockchian storage.

use common::chain::block::block_index::BlockIndex;
use common::chain::block::Block;
use common::chain::transaction::{Transaction, TxMainChainIndex, TxMainChainPosition};
use common::primitives::{BlockHeight, Id};

mockall::mock! {
    /// A mock object for blockchain storage
    pub Store {}

    impl crate::BlockchainStorage for Store {
        fn get_storage_version(&self) -> crate::Result<u32>;
        fn set_storage_version(&mut self, version: u32) -> crate::Result<()>;
        fn get_best_block_id(&self) -> crate::Result<Option<Id<Block>>>;
        fn set_best_block_id(&mut self, id: &Id<Block>) -> crate::Result<()>;
        fn get_block_index(&self, id: &Id<Block>) -> crate::Result<Option<BlockIndex>>;
        fn set_block_index(&mut self, block_index: &BlockIndex) -> crate::Result<()>;
        fn add_block(&mut self, block: &Block) -> crate::Result<()>;
        fn get_block(&self, id: Id<Block>) -> crate::Result<Option<Block>>;
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

        fn get_mainchain_tx(&self, txid: &Id<Transaction>) -> crate::Result<Option<Transaction>>;

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

    impl storage::traits::Transactional<'_> for Store {
        type TransactionRo = MockStoreTx;
        type TransactionRw = MockStoreTx;
        fn start_transaction_ro(&self) -> MockStoreTx;
        fn start_transaction_rw(&self) -> MockStoreTx;
    }
}

mockall::mock! {
    /// A mock object for blockcain storage transaction
    pub StoreTx {}

    impl crate::BlockchainStorage for StoreTx {
        fn get_storage_version(&self) -> crate::Result<u32>;
        fn set_storage_version(&mut self, version: u32) -> crate::Result<()>;
        fn get_best_block_id(&self) -> crate::Result<Option<Id<Block>>>;
        fn set_best_block_id(&mut self, id: &Id<Block>) -> crate::Result<()>;
        fn get_block_index(&self, id: &Id<Block>) -> crate::Result<Option<BlockIndex>>;
        fn set_block_index(&mut self, block_index: &BlockIndex) -> crate::Result<()>;
        fn add_block(&mut self, block: &Block) -> crate::Result<()>;
        fn get_block(&self, id: Id<Block>) -> crate::Result<Option<Block>>;
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

        fn get_mainchain_tx(
            &self,
            txid: &Id<Transaction>,
        ) -> crate::Result<Option<Transaction>>;

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

    impl storage::traits::TransactionRo for StoreTx {
        type Error = crate::Error;
        fn finalize(self) -> crate::Result<()>;
    }

    impl storage::traits::TransactionRw for StoreTx {
        type Error = crate::Error;
        fn abort(self) -> crate::Result<()>;
        fn commit(self) -> crate::Result<()>;
    }
}

#[cfg(test)]
mod tests {
    pub use super::*;
    pub use crate::BlockchainStorage;
    use common::primitives::consensus_data::ConsensusData;
    pub use common::primitives::{Idable, H256};
    pub use storage::traits::Transactional;

    const TXFAIL: crate::Error =
        crate::Error::Storage(storage::error::Recoverable::TransactionFailed);
    const HASH1: H256 = H256([0x01; 32]);
    const HASH2: H256 = H256([0x02; 32]);

    #[test]
    fn basic_mock() {
        let mut mock = MockStore::new();
        mock.expect_set_storage_version().times(1).return_const(Ok(()));

        let r = mock.set_storage_version(5);
        assert_eq!(r, Ok(()));
    }

    #[test]
    fn basic_fail() {
        let mut mock = MockStore::new();
        mock.expect_set_storage_version().times(1).return_const(Err(TXFAIL));

        let r = mock.set_storage_version(5);
        assert_eq!(r, Err(TXFAIL));
    }

    #[test]
    fn two_updates_second_fails() {
        let mut store = MockStore::new();
        let mut seq = mockall::Sequence::new();
        store
            .expect_set_best_block_id()
            .times(1)
            .in_sequence(&mut seq)
            .return_const(Ok(()));
        store
            .expect_set_best_block_id()
            .times(1)
            .in_sequence(&mut seq)
            .return_const(Err(TXFAIL));

        assert!(store.set_best_block_id(&Id::new(&HASH1)).is_ok());
        assert!(store.set_best_block_id(&Id::new(&HASH2)).is_err());
    }

    #[test]
    fn mock_transaction() {
        // Set up the mock store
        let mut store = MockStore::new();
        store.expect_start_transaction_rw().returning(|| {
            let mut mock_tx = MockStoreTx::new();
            mock_tx.expect_get_storage_version().return_const(Ok(3));
            mock_tx
                .expect_set_storage_version()
                .with(mockall::predicate::eq(4))
                .return_const(Ok(()));
            mock_tx.expect_commit().times(1).return_const(Ok(()));
            mock_tx
        });

        // Test some code against the mock
        let tx_result = store.transaction_rw(|tx| {
            let v = tx.get_storage_version()?;
            tx.set_storage_version(v + 1)?;
            storage::commit(())
        });
        assert_eq!(tx_result, Ok(()))
    }

    // A sample function under test
    fn attach_block_to_top<'a, BS>(store: &'a mut BS, block: &Block) -> &'static str
    where
        BS: Transactional<'a>,
        BS::TransactionRw: storage::traits::TransactionRw<Error = crate::Error> + BlockchainStorage,
    {
        let res: crate::Result<&'static str> = store.transaction_rw(|tx| {
            // Get current best block ID
            let _best_id = match tx.get_best_block_id()? {
                None => return storage::abort("top not set"),
                Some(best_id) => {
                    // Check the parent block is the current best block
                    match block.get_prev_block_id() {
                        Some(prev_block_id) => {
                            if Id::<Block>::from(prev_block_id) != best_id {
                                return storage::abort("not on top");
                            }
                        }
                        None => return storage::abort("DB corrupted"),
                    }
                    best_id
                }
            };
            // Add the block to the database
            tx.add_block(block)?;
            // Set the best block ID
            tx.set_best_block_id(&block.get_id())?;
            storage::commit("ok")
        });
        res.unwrap_or_else(|e| {
            #[allow(unreachable_patterns)]
            match e {
                crate::Error::Storage(e) => match e {
                    storage::error::Recoverable::TransactionFailed => "tx failed",
                    _ => "other storage error",
                },
                _ => "other error",
            }
        })
    }

    // sample transactions and blocks
    fn sample_data() -> (Block, Block) {
        let tx0 = Transaction::new(0xaabbccdd, vec![], vec![], 12).unwrap();
        let tx1 = Transaction::new(0xbbccddee, vec![], vec![], 34).unwrap();
        let block0 = Block::new(vec![tx0], None, 12, ConsensusData::None).unwrap();
        let block1 = Block::new(
            vec![tx1],
            Some(Id::from(block0.get_id())),
            34,
            ConsensusData::None,
        )
        .unwrap();
        (block0, block1)
    }

    #[test]
    fn attach_to_top_ok() {
        let (block0, block1) = sample_data();
        let block1_id = block1.get_id();
        let mut store = MockStore::new();
        store.expect_start_transaction_rw().returning(move || {
            let mut tx = MockStoreTx::new();
            tx.expect_get_best_block_id().return_const(Ok(Some(block0.get_id())));
            tx.expect_add_block().return_const(Ok(()));
            tx.expect_set_best_block_id()
                .with(mockall::predicate::eq(block1_id.clone()))
                .return_const(Ok(()));
            tx.expect_commit().return_const(Ok(()));
            tx
        });

        let result = attach_block_to_top(&mut store, &block1);
        assert_eq!(result, "ok");
    }

    #[test]
    fn attach_to_top_no_best_block() {
        let (_block0, block1) = sample_data();
        let mut store = MockStore::new();
        store.expect_start_transaction_rw().returning(move || {
            let mut tx = MockStoreTx::new();
            tx.expect_get_best_block_id().return_const(Ok(None));
            tx.expect_abort().return_const(Ok(()));
            tx
        });

        let result = attach_block_to_top(&mut store, &block1);
        assert_eq!(result, "top not set");
    }

    #[test]
    fn attach_to_top_bad_parent() {
        let (_block0, block1) = sample_data();
        let top_id = Id::new(&H256([0x99; 32]));
        let mut store = MockStore::new();
        store.expect_start_transaction_rw().returning(move || {
            let mut tx = MockStoreTx::new();
            tx.expect_get_best_block_id().return_const(Ok(Some(top_id.clone())));
            tx.expect_abort().return_const(Ok(()));
            tx
        });

        let result = attach_block_to_top(&mut store, &block1);
        assert_eq!(result, "not on top");
    }

    #[test]
    fn attach_to_top_commit_fail() {
        let (block0, block1) = sample_data();
        let block1_id = block1.get_id();
        let mut store = MockStore::new();
        store.expect_start_transaction_rw().returning(move || {
            let mut tx = MockStoreTx::new();
            tx.expect_get_best_block_id().return_const(Ok(Some(block0.get_id())));
            tx.expect_add_block().return_const(Ok(()));
            tx.expect_set_best_block_id()
                .with(mockall::predicate::eq(block1_id.clone()))
                .return_const(Ok(()));
            tx.expect_commit().return_const(Err(TXFAIL));
            tx
        });

        let result = attach_block_to_top(&mut store, &block1);
        assert_eq!(result, "tx failed");
    }
}
