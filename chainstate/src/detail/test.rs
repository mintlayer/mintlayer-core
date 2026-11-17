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

use static_assertions::*;

use chainstate_storage::inmemory::Store;
use common::{
    Uint256,
    chain::{
        Destination, NetUpgrades,
        config::{Builder as ChainConfigBuilder, ChainType},
    },
};

use crate::{
    DefaultTransactionVerificationStrategy, detail::query::locator_tip_distances,
    interface::chainstate_interface_impl::ChainstateInterfaceImpl,
};

use super::*;

assert_impl_all!(ChainstateInterfaceImpl<chainstate_storage::inmemory::Store, DefaultTransactionVerificationStrategy>: Send);

#[test]
fn process_genesis_block() {
    utils::concurrency::model(|| {
        let chain_config = ChainConfigBuilder::new(ChainType::Mainnet)
            .consensus_upgrades(NetUpgrades::unit_tests())
            .genesis_unittest(Destination::AnyoneCanSpend)
            // Force empty checkpoints because a custom genesis is used.
            .checkpoints(BTreeMap::new())
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
            None,
        );

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
            chainstate_ref.get_block_id_by_height(BlockHeight::from(0)).unwrap().unwrap();
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
            .consensus_upgrades(NetUpgrades::unit_tests())
            .genesis_unittest(Destination::AnyoneCanSpend)
            // Force empty checkpoints because a custom genesis is used.
            .checkpoints(BTreeMap::new())
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
            None,
        );
        // This panics
        let _ = chainstate.query().unwrap().get_best_block_id();
    })
}

/// A failed switch-off of the reckless mode (e.g. an IO error during the forced sync
/// right after a large IBD) must not consume the counter nor panic on retry: the next
/// `dec` must retry the switch-off, and a spurious extra decrement must recover instead
/// of underflowing.
#[test]
fn reckless_mode_counter_retry_after_failed_switch_off() {
    use chainstate_storage::mock::MockStore;
    use std::sync::atomic::{AtomicBool, Ordering};

    let config = crate::config::ChainstateConfig {
        enable_db_reckless_mode_in_ibd: Some(true),
        ..Default::default()
    };

    let mut storage = MockStore::default();
    let fail_next_switch_off = AtomicBool::new(true);
    let mut seq = mockall::Sequence::new();

    // inc: switch the mode on
    storage
        .expect_set_reckless_mode()
        .times(1)
        .in_sequence(&mut seq)
        .returning(|set: bool| {
            assert!(set);
            Ok(())
        });
    // dec #1: the forced sync fails, simulating an IO error after a big IBD
    storage.expect_set_reckless_mode().times(1).in_sequence(&mut seq).returning(
        move |_set: bool| {
            if fail_next_switch_off.swap(false, Ordering::SeqCst) {
                Err(chainstate_storage::Error::Storage(
                    storage::error::Recoverable::TransactionFailed,
                ))
            } else {
                Ok(())
            }
        },
    );
    // dec #2: the retry succeeds
    storage
        .expect_set_reckless_mode()
        .times(1)
        .in_sequence(&mut seq)
        .returning(|_set: bool| Ok(()));
    // dec #3: a spurious extra decrement attempts the (idempotent) switch-off again
    storage
        .expect_set_reckless_mode()
        .times(1)
        .in_sequence(&mut seq)
        .returning(|_set: bool| Ok(()));

    let mut counter = DbRecklessModeCounter::new();

    counter.inc(&config, &storage).unwrap();
    assert_eq!(counter.counter, 1);

    // The failed switch-off must propagate its error without decrementing the counter.
    assert!(counter.dec(&config, &storage).is_err());
    assert_eq!(counter.counter, 1);

    // The retry must succeed and empty the counter.
    counter.dec(&config, &storage).unwrap();
    assert_eq!(counter.counter, 0);

    // A spurious extra decrement must not panic (including debug builds) and must
    // attempt the switch-off again.
    counter.dec(&config, &storage).unwrap();
    assert_eq!(counter.counter, 0);
}
