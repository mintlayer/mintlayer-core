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

use std::sync::Arc;

use crate::helpers::make_trial;
use crate::make_test;

use api_server_common::storage::{
    impls::CURRENT_STORAGE_VERSION,
    storage_api::{
        block_aux_data::BlockAuxData, ApiServerStorage, ApiServerStorageRead,
        ApiServerStorageWrite, ApiServerTransactionRw,
    },
};
use crypto::random::Rng;

use chainstate_test_framework::{empty_witness, TestFramework, TransactionBuilder};
use common::{
    chain::{Block, OutPointSourceId, SignedTransaction, Transaction, TxInput, UtxoOutPoint},
    primitives::{Id, Idable, H256},
};
use futures::Future;
use libtest_mimic::Failed;
use test_utils::random::{make_seedable_rng, Seed};

pub async fn initialization<S, Fut, F: Fn() -> Fut>(
    storage_maker: Arc<F>,
    _seed_maker: Box<dyn Fn() -> Seed + Send>,
) -> Result<(), Failed>
where
    S: ApiServerStorage,
    Fut: Future<Output = S> + Send + 'static,
{
    let storage = storage_maker().await;
    let tx = storage.transaction_ro().await.unwrap();
    assert!(tx.is_initialized().await.unwrap());
    Ok(())
}

pub async fn set_get<S: ApiServerStorage, Fut, F: Fn() -> Fut>(
    storage_maker: Arc<F>,
    seed_maker: Box<dyn Fn() -> Seed + Send>,
) -> Result<(), Failed>
where
    S: ApiServerStorage,
    Fut: Future<Output = S> + Send + 'static,
{
    let seed = seed_maker();

    let mut rng = make_seedable_rng(seed);

    let mut storage = storage_maker().await;

    let db_tx = storage.transaction_ro().await.unwrap();

    let is_initialized = db_tx.is_initialized().await.unwrap();
    assert!(is_initialized);

    let version_option = db_tx.get_storage_version().await.unwrap();
    assert_eq!(version_option.unwrap(), CURRENT_STORAGE_VERSION);

    drop(db_tx);

    // TODO: add more tests with different variations of rw/ro transactions, where things are done in different orders

    // Test setting mainchain block id and getting it back
    {
        let mut db_tx = storage.transaction_rw().await.unwrap();

        let height_u64 = rng.gen_range::<u64, _>(1..i64::MAX as u64);
        let height = height_u64.into();

        let block_id = db_tx.get_main_chain_block_id(height).await.unwrap();
        assert!(block_id.is_none());

        let random_block_id1 = Id::<Block>::new(H256::random_using(&mut rng));
        db_tx.set_main_chain_block_id(height, random_block_id1).await.unwrap();

        let block_id = db_tx.get_main_chain_block_id(height).await.unwrap();
        assert_eq!(block_id, Some(random_block_id1));

        let random_block_id2 = Id::<Block>::new(H256::random_using(&mut rng));
        db_tx.set_main_chain_block_id(height, random_block_id2).await.unwrap();

        let block_id = db_tx.get_main_chain_block_id(height).await.unwrap();
        assert_eq!(block_id, Some(random_block_id2));

        // Now delete the block id, then get it, and it won't be there
        db_tx.del_main_chain_block_id(height).await.unwrap();
        let block_id = db_tx.get_main_chain_block_id(height).await.unwrap();
        assert!(block_id.is_none());

        // Delete again, as deleting non-existing data is OK
        db_tx.del_main_chain_block_id(height).await.unwrap();
        db_tx.del_main_chain_block_id(height).await.unwrap();

        db_tx.commit().await.unwrap();

        let db_tx = storage.transaction_ro().await.unwrap();

        {
            let block_id = db_tx.get_main_chain_block_id(height).await.unwrap();
            assert!(block_id.is_none());
        }
    }

    // Test setting/getting blocks
    {
        let mut db_tx = storage.transaction_rw().await.unwrap();

        {
            let random_block_id: Id<Block> = Id::<Block>::new(H256::random_using(&mut rng));
            let block = db_tx.get_block(random_block_id).await.unwrap();
            assert!(block.is_none());
        }
        // Create a test framework and blocks

        let mut test_framework = TestFramework::builder(&mut rng).build();
        let chain_config = test_framework.chain_config().clone();
        let genesis_id = chain_config.genesis_block_id();
        test_framework.create_chain(&genesis_id, 10, &mut rng).unwrap();

        let block_id1 =
            test_framework.block_id(1).classify(&chain_config).chain_block_id().unwrap();
        let block1 = test_framework.block(block_id1);

        {
            let block_id = db_tx.get_block(block_id1).await.unwrap();
            assert!(block_id.is_none());

            db_tx.set_block(block_id1, &block1).await.unwrap();

            let block = db_tx.get_block(block_id1).await.unwrap();
            assert_eq!(block, Some(block1));
        }

        db_tx.commit().await.unwrap();
    }

    // Test setting/getting transactions
    {
        let db_tx = storage.transaction_ro().await.unwrap();

        let random_tx_id: Id<Transaction> = Id::<Transaction>::new(H256::random_using(&mut rng));
        let tx = db_tx.get_transaction(random_tx_id).await.unwrap();
        assert!(tx.is_none());

        let owning_block1 = Id::<Block>::new(H256::random_using(&mut rng));
        let tx1: SignedTransaction = TransactionBuilder::new()
            .add_input(
                TxInput::Utxo(UtxoOutPoint::new(
                    OutPointSourceId::Transaction(Id::<Transaction>::new(H256::random_using(
                        &mut rng,
                    ))),
                    0,
                )),
                empty_witness(&mut rng),
            )
            .build();

        // before storage
        let tx_and_block_id = db_tx.get_transaction(tx1.transaction().get_id()).await.unwrap();
        assert!(tx_and_block_id.is_none());

        drop(db_tx);

        let mut db_tx = storage.transaction_rw().await.unwrap();

        // Set without owning block
        {
            db_tx.set_transaction(tx1.transaction().get_id(), None, &tx1).await.unwrap();

            let tx_and_block_id = db_tx.get_transaction(tx1.transaction().get_id()).await.unwrap();
            assert!(tx_and_block_id.is_some());

            let (owning_block, tx_retrieved) = tx_and_block_id.unwrap();
            assert!(owning_block.is_none());
            assert_eq!(tx_retrieved, tx1);
        }

        // Set with owning block
        {
            db_tx
                .set_transaction(tx1.transaction().get_id(), Some(owning_block1), &tx1)
                .await
                .unwrap();

            let tx_and_block_id = db_tx.get_transaction(tx1.transaction().get_id()).await.unwrap();
            assert!(tx_and_block_id.is_some());

            let (owning_block, tx_retrieved) = tx_and_block_id.unwrap();
            assert_eq!(owning_block, Some(owning_block1));
            assert_eq!(tx_retrieved, tx1);
        }

        db_tx.commit().await.unwrap();
    }

    // Test setting/getting block aux data
    {
        let mut db_tx = storage.transaction_rw().await.unwrap();

        let random_block_id: Id<Block> = Id::<Block>::new(H256::random_using(&mut rng));
        let block = db_tx.get_block_aux_data(random_block_id).await.unwrap();
        assert!(block.is_none());

        let height1_u64 = rng.gen_range::<u64, _>(1..i64::MAX as u64);
        let height1 = height1_u64.into();
        let aux_data1 = BlockAuxData::new(random_block_id, height1);
        db_tx.set_block_aux_data(random_block_id, &aux_data1).await.unwrap();

        let retrieved_aux_data = db_tx.get_block_aux_data(random_block_id).await.unwrap();
        assert_eq!(retrieved_aux_data, Some(aux_data1));

        // Test overwrite
        let height2_u64 = rng.gen_range::<u64, _>(1..i64::MAX as u64);
        let height2 = height2_u64.into();
        let aux_data2 = BlockAuxData::new(random_block_id, height2);
        db_tx.set_block_aux_data(random_block_id, &aux_data2).await.unwrap();

        let retrieved_aux_data = db_tx.get_block_aux_data(random_block_id).await.unwrap();
        assert_eq!(retrieved_aux_data, Some(aux_data2));

        db_tx.commit().await.unwrap();
    }

    // Test setting/getting best block
    {
        let mut db_tx = storage.transaction_rw().await.unwrap();

        // Set once then get best block
        {
            let height1_u64 = rng.gen_range::<u64, _>(1..i64::MAX as u64);
            let height1 = height1_u64.into();
            let random_block_id1 = Id::<Block>::new(H256::random_using(&mut rng));

            db_tx.set_best_block(height1, random_block_id1.into()).await.unwrap();

            let (retrieved_best_height, retrieved_best_id) = db_tx.get_best_block().await.unwrap();

            assert_eq!(height1, retrieved_best_height);
            assert_eq!(random_block_id1, retrieved_best_id);
        }

        // Set again to test overwrite
        {
            let height2_u64 = rng.gen_range::<u64, _>(1..i64::MAX as u64);
            let height2 = height2_u64.into();
            let random_block_id2 = Id::<Block>::new(H256::random_using(&mut rng));

            db_tx.set_best_block(height2, random_block_id2.into()).await.unwrap();

            let (retrieved_best_height, retrieved_best_id) = db_tx.get_best_block().await.unwrap();

            assert_eq!(height2, retrieved_best_height);
            assert_eq!(random_block_id2, retrieved_best_id);
        }

        db_tx.commit().await.unwrap();
    }

    Ok(())
}

pub fn build_tests<S, Fut, F: Fn() -> Fut + Send + Sync + 'static>(
    storage_maker: Arc<F>,
) -> impl Iterator<Item = libtest_mimic::Trial>
where
    Fut: Future<Output = S> + Send + 'static,
    S: ApiServerStorage + Send + 'static,
{
    vec![
        make_test!(initialization, storage_maker.clone()),
        make_test!(set_get, storage_maker),
    ]
    .into_iter()
}
