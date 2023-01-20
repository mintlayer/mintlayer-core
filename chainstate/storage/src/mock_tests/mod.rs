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

//! A mock version of the blockchain storage.

use common::{
    chain::{transaction::Transaction, Block, GenBlock},
    primitives::Id,
};

pub mod mock;
pub use mock::{MockStore, MockStoreTxRo, MockStoreTxRw};

mod mock_accounting;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlockchainStorageRead, BlockchainStorageWrite, Transactional};
    use crate::{TransactionRo, TransactionRw};
    use common::chain::signed_transaction::SignedTransaction;
    use common::{
        chain::block::{timestamp::BlockTimestamp, BlockReward, ConsensusData},
        primitives::{Idable, H256},
    };

    type TestStore = crate::inmemory::Store;

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
    fn mock_transaction_fail() {
        // Set up the mock store
        let mut store = MockStore::new();
        let err_f = || {
            Err(crate::Error::Storage(
                storage::error::Recoverable::TransactionFailed,
            ))
        };
        store.expect_transaction_ro().returning(err_f);

        // Check it returns an error
        match store.transaction_ro() {
            Ok(_) => panic!("Err expected"),
            Err(e) => assert_eq!(
                e,
                crate::Error::Storage(storage::error::Recoverable::TransactionFailed)
            ),
        }
    }

    #[test]
    fn mock_transaction() {
        // Set up the mock store
        let mut store = MockStore::new();
        store.expect_transaction_rw().returning(|_| {
            let mut mock_tx = MockStoreTxRw::new();
            mock_tx.expect_get_storage_version().return_const(Ok(3));
            mock_tx
                .expect_set_storage_version()
                .with(mockall::predicate::eq(4))
                .return_const(Ok(()));
            mock_tx.expect_commit().times(1).return_const(Ok(()));
            Ok(mock_tx)
        });

        // Test some code against the mock
        let mut tx = store.transaction_rw(None).unwrap();
        let v = tx.get_storage_version().unwrap();
        tx.set_storage_version(v + 1).unwrap();
        tx.commit().unwrap();
    }

    fn generic_test<BS: crate::BlockchainStorage>(store: &BS) {
        let tx = store.transaction_ro().unwrap();
        let _ = tx.get_best_block_id();
        tx.close();
    }

    #[test]
    fn use_generic_test() {
        utils::concurrency::model(|| {
            let store = TestStore::new_empty().unwrap();
            generic_test(&store);
        });
    }

    // A sample function under test
    fn attach_block_to_top<BS: crate::BlockchainStorage>(
        store: &mut BS,
        block: &Block,
    ) -> &'static str {
        (|| {
            let mut tx = store.transaction_rw(None).unwrap();
            // Get current best block ID
            let _best_id = match tx.get_best_block_id()? {
                None => return Ok("top not set"),
                Some(best_id) => {
                    // Check the parent block is the current best block
                    if block.prev_block_id() != best_id {
                        return Ok("not on top");
                    }
                    best_id
                }
            };
            // Add the block to the database
            tx.add_block(block)?;
            // Set the best block ID
            tx.set_best_block_id(&block.get_id().into())?;
            tx.commit()?;
            Ok("ok")
        })()
        .unwrap_or_else(|e| {
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
            vec![SignedTransaction::new(tx0, vec![]).expect("invalid witness count")],
            Id::<GenBlock>::new(H256([0x23; 32])),
            BlockTimestamp::from_int_seconds(12),
            ConsensusData::None,
            BlockReward::new(Vec::new()),
        )
        .unwrap();
        let block1 = Block::new(
            vec![SignedTransaction::new(tx1, vec![]).expect("invalid witness count")],
            block0.get_id().into(),
            BlockTimestamp::from_int_seconds(34),
            ConsensusData::None,
            BlockReward::new(Vec::new()),
        )
        .unwrap();
        (block0, block1)
    }

    #[test]
    fn attach_to_top_real_storage() {
        utils::concurrency::model(|| {
            let mut store = TestStore::new_empty().unwrap();
            let (_block0, block1) = sample_data();
            let _result = attach_block_to_top(&mut store, &block1);
        });
    }

    #[test]
    fn attach_to_top_ok() {
        let (block0, block1) = sample_data();
        let block1_id = block1.get_id();
        let mut store = MockStore::new();
        store.expect_transaction_rw().returning(move |_| {
            let mut tx = MockStoreTxRw::new();
            tx.expect_get_best_block_id().return_const(Ok(Some(block0.get_id().into())));
            tx.expect_add_block().return_const(Ok(()));
            let expected_id: Id<GenBlock> = block1_id.into();
            tx.expect_set_best_block_id()
                .with(mockall::predicate::eq(expected_id))
                .return_const(Ok(()));
            tx.expect_commit().return_const(Ok(()));
            Ok(tx)
        });

        let result = attach_block_to_top(&mut store, &block1);
        assert_eq!(result, "ok");
    }

    #[test]
    fn attach_to_top_no_best_block() {
        let (_block0, block1) = sample_data();
        let mut store = MockStore::new();
        store.expect_transaction_rw().returning(move |_| {
            let mut tx = MockStoreTxRw::new();
            tx.expect_get_best_block_id().return_const(Ok(None));
            tx.expect_abort().return_const(());
            Ok(tx)
        });

        let result = attach_block_to_top(&mut store, &block1);
        assert_eq!(result, "top not set");
    }

    #[test]
    fn attach_to_top_bad_parent() {
        let (_block0, block1) = sample_data();
        let top_id = Id::new(H256([0x99; 32]));
        let mut store = MockStore::new();
        store.expect_transaction_rw().returning(move |_| {
            let mut tx = MockStoreTxRw::new();
            tx.expect_get_best_block_id().return_const(Ok(Some(top_id)));
            tx.expect_abort().return_const(());
            Ok(tx)
        });

        let result = attach_block_to_top(&mut store, &block1);
        assert_eq!(result, "not on top");
    }

    #[test]
    fn attach_to_top_commit_fail() {
        let (block0, block1) = sample_data();
        let block1_id = block1.get_id();
        let mut store = MockStore::new();
        store.expect_transaction_rw().returning(move |_| {
            let mut tx = MockStoreTxRw::new();
            tx.expect_get_best_block_id().return_const(Ok(Some(block0.get_id().into())));
            tx.expect_add_block().return_const(Ok(()));
            let expected_id: Id<GenBlock> = block1_id.into();
            tx.expect_set_best_block_id()
                .with(mockall::predicate::eq(expected_id))
                .return_const(Ok(()));
            tx.expect_commit().return_const(Err(TXFAIL));
            Ok(tx)
        });

        let result = attach_block_to_top(&mut store, &block1);
        assert_eq!(result, "tx failed");
    }
}
