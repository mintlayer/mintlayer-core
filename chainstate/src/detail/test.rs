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

use crate::detail::query::locator_tip_distances;
use crate::interface::chainstate_interface_impl::ChainstateInterfaceImpl;
use crate::DefaultTransactionVerificationStrategy;

use super::*;
use chainstate_storage::inmemory::Store;
use common::chain::config::Builder as ChainConfigBuilder;
use common::chain::config::ChainType;
use common::chain::Destination;
use common::chain::NetUpgrades;
use common::Uint256;
use static_assertions::*;

assert_impl_all!(ChainstateInterfaceImpl<chainstate_storage::inmemory::Store, DefaultTransactionVerificationStrategy>: Send);

#[test]
fn process_genesis_block() {
    utils::concurrency::model(|| {
        let chain_config = ChainConfigBuilder::new(ChainType::Mainnet)
            .net_upgrades(NetUpgrades::unit_tests())
            .genesis_unittest(Destination::AnyoneCanSpend)
            .build();
        let chainstate_config = ChainstateConfig::default();
        let chainstate_storage = Store::new_empty().unwrap();
        let time_getter = TimeGetter::default();
        let genesis_id = chain_config.genesis_block_id();

        let mut chainstate = Chainstate::new_no_genesis(
            Arc::new(chain_config),
            chainstate_config,
            chainstate_storage,
            DefaultTransactionVerificationStrategy::new(),
            None,
            time_getter,
        );

        chainstate.process_tx_index_enabled_flag().unwrap();

        chainstate.process_genesis().unwrap();
        let chainstate_ref = chainstate.make_db_tx_ro().unwrap();

        // Check the genesis block is properly set up
        assert_eq!(
            chainstate.query().unwrap().get_best_block_id().unwrap(),
            genesis_id
        );
        let genesis_index = chainstate_ref.get_gen_block_index(&genesis_id).unwrap().unwrap();
        assert_eq!(genesis_index.block_height(), BlockHeight::from(0));
        assert_eq!(genesis_index.block_id(), genesis_id);
        let block_at_0 =
            chainstate_ref.get_block_id_by_height(&BlockHeight::from(0)).unwrap().unwrap();
        assert_eq!(block_at_0, genesis_id);
        assert_eq!(genesis_index.chain_trust(), Uint256::ZERO);
    });
}

#[test]
fn locator_distances() {
    let distances: Vec<i64> = locator_tip_distances().take(7).map(From::from).collect();
    assert_eq!(distances, vec![0, 1, 2, 4, 8, 16, 32]);
}

#[test]
#[should_panic(expected = "Best block ID not initialized")]
fn empty_chainstate_no_genesis() {
    utils::concurrency::model(|| {
        let chain_config = ChainConfigBuilder::new(ChainType::Mainnet)
            .net_upgrades(NetUpgrades::unit_tests())
            .genesis_unittest(Destination::AnyoneCanSpend)
            .build();
        let chainstate_config = ChainstateConfig::default();
        let chainstate_storage = Store::new_empty().unwrap();
        let time_getter = TimeGetter::default();
        let chainstate = Chainstate::new_no_genesis(
            Arc::new(chain_config),
            chainstate_config,
            chainstate_storage,
            DefaultTransactionVerificationStrategy::new(),
            None,
            time_getter,
        );
        // This panics
        let _ = chainstate.query().unwrap().get_best_block_id();
    })
}

mod with_rw_tx_tests {
    use super::*;
    use crate::detail::tx_verification_strategy::DefaultTransactionVerificationStrategy;
    use chainstate_storage::mock::{MockStore, MockStoreTxRw};
    use chainstate_types::storage_result::Error as StorageError;
    use common::chain::config::create_unit_test_config;
    use std::sync::Arc;

    const MAX_COMMIT_ATTEMPTS: usize = 3;

    // Make some error that can be returned from "commit".
    fn make_commit_error() -> StorageError {
        StorageError::Storage(storage::error::Recoverable::Io(
            std::io::ErrorKind::Other,
            "".into(),
        ))
    }

    fn make_chainstate(
        store: MockStore,
    ) -> Chainstate<MockStore, DefaultTransactionVerificationStrategy> {
        let chain_config = Arc::new(create_unit_test_config());
        let chainstate_config =
            ChainstateConfig::new().with_max_db_commit_attempts(MAX_COMMIT_ATTEMPTS);

        Chainstate::new_no_genesis(
            chain_config,
            chainstate_config,
            store,
            DefaultTransactionVerificationStrategy::new(),
            None,
            Default::default(),
        )
    }

    // Call with_rw_tx_and_state on a new chainstate, making required expectations.
    // Use usize for the State type; the "goal" of the main action is to increment
    // the initial state by 1.
    fn test_with_rw_tx_and_state(
        store: MockStore,
        expected_result: Result<(), BlockError>,
        expected_commit_attempts: usize,
    ) {
        let initial_state = 123;
        let mut chainstate = make_chainstate(store);
        let mut actual_commit_attempts = 0;

        let (state, result) = chainstate.with_rw_tx_and_state(
            &initial_state,
            |_chainstate_ref, state| {
                assert_eq!(*state, initial_state);
                *state += 1;
                Ok(())
            },
            |attempt_number| {
                assert_eq!(attempt_number, actual_commit_attempts);
                actual_commit_attempts += 1;
            },
            |commit_attempts, db_err| -> BlockError {
                // Not all tests will reach this point, but if they do, these assertions
                // should pass.
                assert_eq!(commit_attempts, expected_commit_attempts);
                assert_eq!(db_err, make_commit_error());
                BlockError::StorageError(db_err)
            },
        );
        assert_eq!(actual_commit_attempts, expected_commit_attempts);
        assert_eq!(state, initial_state + 1);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn with_rw_tx_and_state_when_first_commit_fails() {
        utils::concurrency::model(|| {
            let mut mock_seq = mockall::Sequence::new();
            let mut store = MockStore::new();

            store.expect_transaction_rw().times(1).in_sequence(&mut mock_seq).returning(
                move |_| {
                    let mut tx_store = MockStoreTxRw::new();
                    tx_store.expect_commit().returning(move || Err(make_commit_error()));
                    Ok(tx_store)
                },
            );

            store.expect_transaction_rw().times(1).in_sequence(&mut mock_seq).returning(
                move |_| {
                    let mut tx_store = MockStoreTxRw::new();
                    tx_store.expect_commit().returning(move || Ok(()));
                    Ok(tx_store)
                },
            );

            test_with_rw_tx_and_state(store, Ok(()), 2);
        });
    }

    #[test]
    fn with_rw_tx_and_state_when_all_commits_fail() {
        utils::concurrency::model(|| {
            let mut store = MockStore::new();

            store.expect_transaction_rw().returning(move |_| {
                let mut tx_store = MockStoreTxRw::new();
                tx_store.expect_commit().returning(move || Err(make_commit_error()));
                Ok(tx_store)
            });

            test_with_rw_tx_and_state(
                store,
                Err(BlockError::StorageError(make_commit_error())),
                MAX_COMMIT_ATTEMPTS,
            );
        });
    }
}
