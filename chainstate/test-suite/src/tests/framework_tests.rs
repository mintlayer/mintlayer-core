// Copyright (c) 2021-2024 RBB S.r.l
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

use rstest::rstest;

use chainstate::{BlockIndex, ChainstateConfig};
use chainstate_storage::{BlockchainStorageWrite, TransactionRw, Transactional};
use common::{
    chain::{
        self,
        block::timestamp::BlockTimestamp,
        config::{create_regtest, ChainType},
        Destination, NetUpgrades,
    },
    primitives::Idable,
};
use randomness::Rng;

use chainstate_test_framework::TestFramework;
use chainstate_types::{BlockStatus, BlockValidationStage};
use test_utils::random::{make_seedable_rng, Seed};

use super::helpers::block_creation_helpers::build_block;

// These tests check some assumptions for the test framework itself.

// Check that "heavy" checks are automatically enabled for a "default-constructed" TestFramework.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[should_panic = "Inconsistent chainstate"]
fn test_consistency_check_enabled_by_default(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut tf = TestFramework::builder(&mut rng).build();

    assert!(tf.chainstate.get_chainstate_config().heavy_checks_enabled(tf.chain_config()));
    make_chainstate_inconsistent(&mut tf, &mut rng);
    tf.create_chain(&tf.genesis().get_id().into(), 1, &mut rng).unwrap();
}

// Check that "heavy" checks are automatically enabled for regtest.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[should_panic = "Inconsistent chainstate"]
fn test_consistency_check_enabled_for_regtest(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(create_regtest()).build();

    assert!(tf.chainstate.get_chainstate_config().heavy_checks_enabled(tf.chain_config()));
    make_chainstate_inconsistent(&mut tf, &mut rng);
    tf.create_chain(&tf.genesis().get_id().into(), 1, &mut rng).unwrap();
}

// Check that "heavy" checks can be explicitly disabled.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_consistency_check_explicitly_disabled(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut tf = TestFramework::builder(&mut rng)
        .with_chainstate_config(ChainstateConfig::new().with_heavy_checks_enabled(false))
        .build();

    assert!(!tf.chainstate.get_chainstate_config().heavy_checks_enabled(tf.chain_config()));
    make_chainstate_inconsistent(&mut tf, &mut rng);
    tf.create_chain(&tf.genesis().get_id().into(), 1, &mut rng).unwrap();
}

// Check that "heavy" checks are automatically disabled for something other than regtest
// (we use test net for this test).
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_consistency_check_disabled_for_testnet(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(
            chain::config::Builder::new(ChainType::Testnet)
                .consensus_upgrades(NetUpgrades::unit_tests())
                .genesis_unittest(Destination::AnyoneCanSpend)
                .checkpoints(BTreeMap::new())
                .build(),
        )
        .build();

    assert!(!tf.chainstate.get_chainstate_config().heavy_checks_enabled(tf.chain_config()));
    make_chainstate_inconsistent(&mut tf, &mut rng);
    tf.create_chain(&tf.genesis().get_id().into(), 1, &mut rng).unwrap();
}

// Check that "heavy" checks can be explicitly enabled.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[should_panic = "Inconsistent chainstate"]
fn test_consistency_check_explicitly_enabled_for_testnet(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(
            chain::config::Builder::new(ChainType::Testnet)
                .consensus_upgrades(NetUpgrades::unit_tests())
                .genesis_unittest(Destination::AnyoneCanSpend)
                .checkpoints(BTreeMap::new())
                .build(),
        )
        .with_chainstate_config(ChainstateConfig::new().with_heavy_checks_enabled(true))
        .build();

    assert!(tf.chainstate.get_chainstate_config().heavy_checks_enabled(tf.chain_config()));
    make_chainstate_inconsistent(&mut tf, &mut rng);
    tf.create_chain(&tf.genesis().get_id().into(), 1, &mut rng).unwrap();
}

// Store a block index with the persistence flag set, but without storing the corresponding block.
fn make_chainstate_inconsistent(tf: &mut TestFramework, rng: &mut impl Rng) {
    let genesis_id = tf.chain_config().genesis_block_id();
    let block = build_block(tf, &genesis_id, rng);

    let block_index = BlockIndex::new(
        &block,
        1u64.into(),
        genesis_id,
        1.into(),
        BlockTimestamp::from_time(tf.current_time()),
        0,
        BlockStatus::new_at_stage(BlockValidationStage::FullyChecked),
    )
    .make_persisted();

    let mut tx_rw = tf.storage.transaction_rw(None).unwrap();
    tx_rw.set_block_index(&block_index).unwrap();
    tx_rw.commit().unwrap();
}
