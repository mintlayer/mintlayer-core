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

use common::{
    chain::{block::timestamp::BlockTimestamp, config::create_unit_test_config},
    primitives::{H256, Id},
    time_getter::TimeGetter,
};
use mempool::{
    error::{BlockConstructionError, TxValidationError},
    tx_accumulator::{DefaultTxAccumulator, PackingStrategy},
};
use mocks::MockMempoolInterface;
use subsystem::error::ResponseError;
use utils::once_destructor::OnceDestructor;

use crate::{
    BlockProductionError, detail::collect_transactions, tests::helpers::setup_blockprod_test,
};

// A dummy timestamp for tests where the block timestamp is irrelevant
const DUMMY_TIMESTAMP: BlockTimestamp = BlockTimestamp::from_int_seconds(0u64);

// TODO: add tests for mempool rejecting transaction accumulator

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn collect_txs_failed() {
    let chain_config = Arc::new(create_unit_test_config());
    let (mut manager, _chainstate, _mempool, _p2p) =
        setup_blockprod_test(Arc::clone(&chain_config), TimeGetter::default());

    let mut mock_mempool = MockMempoolInterface::default();
    mock_mempool.expect_collect_txs().return_once(|_, _, _| {
        Err(BlockConstructionError::Validity(
            TxValidationError::SubsystemCallError(ResponseError::NoResponse.into()),
        ))
    });

    let mock_mempool_subsystem = manager.add_subsystem("mock-mempool", mock_mempool);

    let current_tip = Id::new(H256::zero());

    let shutdown = manager.make_shutdown_trigger();
    let tester = tokio::spawn(async move {
        let transactions = collect_transactions(
            &mock_mempool_subsystem,
            &chain_config,
            current_tip,
            DUMMY_TIMESTAMP,
            vec![],
            vec![],
            PackingStrategy::FillSpaceFromMempool,
        )
        .await;

        match transactions {
            Err(BlockProductionError::MempoolBlockConstruction(
                BlockConstructionError::Validity(TxValidationError::SubsystemCallError(_)),
            )) => {}
            _ => panic!("Expected collect_tx() to fail"),
        };

        shutdown.initiate();
    });

    let _ = tokio::join!(manager.main(), tester);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subsystem_error() {
    let chain_config = Arc::new(create_unit_test_config());
    let (mut manager, _chainstate, _mempool, _p2p) =
        setup_blockprod_test(Arc::clone(&chain_config), TimeGetter::default());

    let mock_mempool = MockMempoolInterface::default();
    let mock_mempool_subsystem = manager.add_subsystem("mock-mempool", mock_mempool);

    mock_mempool_subsystem
        .as_submit_only()
        .submit({
            let shutdown = manager.make_shutdown_trigger();
            move |_| shutdown.initiate()
        })
        .unwrap();

    // shutdown straight after startup, *then* call collect_transactions()
    manager.main().await;

    let current_tip = Id::new(H256::zero());

    // spawn rather than adding a subsystem as manager is moved into main() above
    tokio::spawn(async move {
        let transactions = collect_transactions(
            &mock_mempool_subsystem,
            &chain_config,
            current_tip,
            DUMMY_TIMESTAMP,
            vec![],
            vec![],
            PackingStrategy::LeaveEmptySpace,
        )
        .await;

        match transactions {
            Ok(_) => panic!("Expected an error"),
            Err(BlockProductionError::SubsystemCallError(_)) => {}
            Err(err) => panic!("Expected a subsystem error, got {err:?}"),
        };
    })
    .await
    .expect("Subsystem error thread failed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn succeeded() {
    let chain_config = Arc::new(create_unit_test_config());
    let (mut manager, _chainstate, _mempool, _p2p) =
        setup_blockprod_test(Arc::clone(&chain_config), TimeGetter::default());

    let mut mock_mempool = MockMempoolInterface::default();

    mock_mempool
        .expect_collect_txs()
        .returning(|_, _, _| {
            Ok(Some(Box::new(DefaultTxAccumulator::new(
                usize::default(),
                Id::new(H256::zero()),
                DUMMY_TIMESTAMP,
            ))))
        })
        .times(1);

    let mock_mempool_subsystem = manager.add_subsystem("mock-mempool", mock_mempool);

    let current_tip = Id::new(H256::zero());

    let join_handle = tokio::spawn({
        let shutdown_trigger = manager.make_shutdown_trigger();
        async move {
            // Ensure a shutdown signal will be sent by the end of the scope
            let _shutdown_signal = OnceDestructor::new(move || {
                shutdown_trigger.initiate();
            });

            let transactions = collect_transactions(
                &mock_mempool_subsystem,
                &chain_config,
                current_tip,
                DUMMY_TIMESTAMP,
                vec![],
                vec![],
                PackingStrategy::FillSpaceFromMempool,
            )
            .await;

            assert!(
                transactions.is_ok(),
                "Expected collect_transactions() to succeed"
            );

            assert!(
                transactions.unwrap().is_some(),
                "Expected collect_transactions() to return Some"
            );
        }
    });

    manager.main().await;
    join_handle.await.unwrap();
}
