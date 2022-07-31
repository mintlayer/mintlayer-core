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

//! A mock version of the blockchain storage.

use chainstate_types::block_index::BlockIndex;
use common::chain::transaction::{
    OutPointSourceId, Transaction, TxMainChainIndex, TxMainChainPosition,
};
use common::chain::{Block, GenBlock, OutPoint};
use common::primitives::{BlockHeight, Id};
use utxo::{BlockUndo, Utxo};

mockall::mock! {
    /// A mock object for blockchain storage
    pub Store {}

    impl crate::BlockchainStorageRead for Store {
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

        fn get_utxo(&self, outpoint: &OutPoint) -> crate::Result<Option<Utxo>>;
        fn get_best_block_for_utxos(&self) -> crate::Result<Option<Id<GenBlock>>>;
        fn get_undo_data(&self, id: Id<Block>) -> crate::Result<Option<BlockUndo>>;
    }

    impl crate::BlockchainStorageWrite for Store {
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

        fn set_utxo(&mut self, outpoint: &OutPoint, entry: Utxo) -> crate::Result<()>;
        fn del_utxo(&mut self, outpoint: &OutPoint) -> crate::Result<()>;

        fn set_best_block_for_utxos(&mut self, block_id: &Id<GenBlock>) -> crate::Result<()>;

        fn set_undo_data(&mut self, id: Id<Block>, undo: &BlockUndo) -> crate::Result<()>;
        fn del_undo_data(&mut self, id: Id<Block>) -> crate::Result<()>;
    }

    #[allow(clippy::extra_unused_lifetimes)]
    impl<'tx> crate::Transactional<'tx> for Store {
        type TransactionRo = MockStoreTxRo;
        type TransactionRw = MockStoreTxRw;
        fn transaction_ro<'st>(&'st self) -> MockStoreTxRo where 'st: 'tx;
        fn transaction_rw<'st>(&'st self) -> MockStoreTxRw where 'st: 'tx;
    }

    impl crate::BlockchainStorage for Store {}
}

mockall::mock! {
    /// A mock object for blockchain storage transaction
    pub StoreTxRo {}

    impl crate::BlockchainStorageRead for StoreTxRo {
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

        fn get_utxo(&self, outpoint: &OutPoint) -> crate::Result<Option<Utxo>>;
        fn get_best_block_for_utxos(&self) -> crate::Result<Option<Id<GenBlock>>>;
        fn get_undo_data(&self, id: Id<Block>) -> crate::Result<Option<BlockUndo>>;
    }

    impl storage::traits::TransactionRo for StoreTxRo {
        type Error = crate::Error;
        fn finalize(self) -> crate::Result<()>;
    }
}

mockall::mock! {
    /// A mock object for blockchain storage transaction
    pub StoreTxRw {}

    impl crate::BlockchainStorageRead for StoreTxRw {
        fn get_storage_version(&self) -> crate::Result<u32>;
        fn get_best_block_id(&self) -> crate::Result<Option<Id<GenBlock>>>;
        fn get_block(&self, id: Id<Block>) -> crate::Result<Option<Block>>;
        fn get_block_index(&self, id: &Id<Block>) -> crate::Result<Option<BlockIndex>>;

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

        fn get_utxo(&self, outpoint: &OutPoint) -> crate::Result<Option<Utxo>>;
        fn get_best_block_for_utxos(&self) -> crate::Result<Option<Id<GenBlock>>>;
        fn get_undo_data(&self, id: Id<Block>) -> crate::Result<Option<BlockUndo>>;
    }

    impl crate::BlockchainStorageWrite for StoreTxRw {
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

        fn set_utxo(&mut self, outpoint: &OutPoint, entry: Utxo) -> crate::Result<()>;
        fn del_utxo(&mut self, outpoint: &OutPoint) -> crate::Result<()>;

        fn set_best_block_for_utxos(&mut self, block_id: &Id<GenBlock>) -> crate::Result<()>;

        fn set_undo_data(&mut self, id: Id<Block>, undo: &BlockUndo) -> crate::Result<()>;
        fn del_undo_data(&mut self, id: Id<Block>) -> crate::Result<()>;
    }

    impl storage::traits::TransactionRw for StoreTxRw {
        type Error = crate::Error;
        fn abort(self) -> crate::Result<()>;
        fn commit(self) -> crate::Result<()>;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlockchainStorageRead, BlockchainStorageWrite, Transactional};
    use common::{
        chain::block::{timestamp::BlockTimestamp, ConsensusData},
        primitives::{Idable, H256},
    };
    use storage::traits::{TransactionRo, TransactionRw};

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

        assert!(store.set_best_block_id(&Id::new(HASH1)).is_ok());
        assert!(store.set_best_block_id(&Id::new(HASH2)).is_err());
    }

    #[test]
    fn mock_transaction() {
        // Set up the mock store
        let mut store = MockStore::new();
        store.expect_transaction_rw().returning(|| {
            let mut mock_tx = MockStoreTxRw::new();
            mock_tx.expect_get_storage_version().return_const(Ok(3));
            mock_tx
                .expect_set_storage_version()
                .with(mockall::predicate::eq(4))
                .return_const(Ok(()));
            mock_tx.expect_commit().times(1).return_const(Ok(()));
            mock_tx
        });

        // Test some code against the mock
        let tx_result = store.transaction_rw().run(|tx| {
            let v = tx.get_storage_version()?;
            tx.set_storage_version(v + 1)?;
            storage::commit(())
        });
        assert_eq!(tx_result, Ok(()))
    }

    fn generic_test<BS: crate::BlockchainStorage>(store: &BS) {
        let tx = store.transaction_ro();
        let _ = tx.get_best_block_id();
        let _ = tx.finalize();
    }

    #[test]
    fn use_generic_test() {
        common::concurrency::model(|| {
            let store = crate::Store::new_empty().unwrap();
            generic_test(&store);
        });
    }

    // A sample function under test
    fn attach_block_to_top<BS: crate::BlockchainStorage>(
        store: &mut BS,
        block: &Block,
    ) -> &'static str {
        let res: crate::Result<&'static str> = store.transaction_rw().run(|tx| {
            // Get current best block ID
            let _best_id = match tx.get_best_block_id()? {
                None => return storage::abort("top not set"),
                Some(best_id) => {
                    // Check the parent block is the current best block
                    if block.prev_block_id() != best_id {
                        return storage::abort("not on top");
                    }
                    best_id
                }
            };
            // Add the block to the database
            tx.add_block(block)?;
            // Set the best block ID
            tx.set_best_block_id(&block.get_id().into())?;
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
        let block0 = Block::new(
            vec![tx0],
            Id::<GenBlock>::new(H256([0x23; 32])),
            BlockTimestamp::from_int_seconds(12),
            ConsensusData::None,
        )
        .unwrap();
        let block1 = Block::new(
            vec![tx1],
            block0.get_id().into(),
            BlockTimestamp::from_int_seconds(34),
            ConsensusData::None,
        )
        .unwrap();
        (block0, block1)
    }

    #[test]
    fn attach_to_top_real_storage() {
        common::concurrency::model(|| {
            let mut store = crate::Store::new_empty().unwrap();
            let (_block0, block1) = sample_data();
            let _result = attach_block_to_top(&mut store, &block1);
        });
    }

    #[test]
    fn attach_to_top_ok() {
        let (block0, block1) = sample_data();
        let block1_id = block1.get_id();
        let mut store = MockStore::new();
        store.expect_transaction_rw().returning(move || {
            let mut tx = MockStoreTxRw::new();
            tx.expect_get_best_block_id().return_const(Ok(Some(block0.get_id().into())));
            tx.expect_add_block().return_const(Ok(()));
            let expected_id: Id<GenBlock> = block1_id.into();
            tx.expect_set_best_block_id()
                .with(mockall::predicate::eq(expected_id))
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
        store.expect_transaction_rw().returning(move || {
            let mut tx = MockStoreTxRw::new();
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
        let top_id = Id::new(H256([0x99; 32]));
        let mut store = MockStore::new();
        store.expect_transaction_rw().returning(move || {
            let mut tx = MockStoreTxRw::new();
            tx.expect_get_best_block_id().return_const(Ok(Some(top_id)));
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
        store.expect_transaction_rw().returning(move || {
            let mut tx = MockStoreTxRw::new();
            tx.expect_get_best_block_id().return_const(Ok(Some(block0.get_id().into())));
            tx.expect_add_block().return_const(Ok(()));
            let expected_id: Id<GenBlock> = block1_id.into();
            tx.expect_set_best_block_id()
                .with(mockall::predicate::eq(expected_id))
                .return_const(Ok(()));
            tx.expect_commit().return_const(Err(TXFAIL));
            tx
        });

        let result = attach_block_to_top(&mut store, &block1);
        assert_eq!(result, "tx failed");
    }
}
