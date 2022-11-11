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

use super::*;
use chainstate::ChainstateError;
use chainstate_test_framework::TestFramework;
use common::{
    chain::{
        config::{Builder as ChainConfigBuilder, ChainType},
        NetUpgrades,
    },
    primitives::Id,
};
use crypto::random::CryptoRng;

#[cfg(not(loom))]
fn genesis_check_ok(num_blocks: u64, rng: &mut (impl Rng + CryptoRng)) {
    // Get initial storage from the test framework.
    let storage = {
        let mut tf = TestFramework::builder(rng).build();
        for _ in 0..num_blocks {
            let _index = tf
                .make_block_builder()
                .build_and_process()
                .expect("block processing to succeed")
                .expect("block index to be returned");
        }
        // Check there are three blocks in the storage now
        assert_eq!(
            tf.chainstate.get_best_block_height().unwrap(),
            num_blocks.into()
        );

        // Extract the final storage and drop the test framework
        tf.storage.clone()
    };

    // Initialize a different test framework with given storage.
    // The test framework should pass the genesis check (panics if not)
    let _tf = TestFramework::builder(rng).with_storage(storage).build();
}

#[cfg(not(loom))]
fn genesis_check_err(num_blocks: u64, rng: &mut (impl Rng + CryptoRng)) {
    // Two different configs with separate genesis IDs.
    let conf0 = ChainConfigBuilder::new(ChainType::Mainnet)
        .net_upgrades(NetUpgrades::unit_tests())
        .genesis_unittest(common::chain::Destination::ScriptHash(Id::new(
            [0x00; 32].into(),
        )))
        .build();
    let conf1 = ChainConfigBuilder::new(ChainType::Mainnet)
        .net_upgrades(NetUpgrades::unit_tests())
        .genesis_unittest(common::chain::Destination::ScriptHash(Id::new(
            [0x01; 32].into(),
        )))
        .build();
    assert_ne!(conf0.genesis_block_id(), conf1.genesis_block_id());

    let storage = {
        let mut tf = TestFramework::builder(rng).with_chain_config(conf0).build();

        // Add a bunch of blocks
        for _ in 0..num_blocks {
            let _index = tf
                .make_block_builder()
                .build_and_process()
                .expect("block processing to succeed")
                .expect("block index to be returned");
        }
        // Check the number of blocks in the storage matches
        assert_eq!(
            tf.chainstate.get_best_block_height().unwrap(),
            num_blocks.into()
        );

        tf.storage
    };

    // Start another chain with different genesis using the previous storage
    let result = TestFramework::builder(rng)
        .with_chain_config(conf1)
        .with_storage(storage)
        .try_build();

    // Verify the result
    match result {
        Err(ChainstateError::FailedToInitializeChainstate(_)) => (),
        Err(e) => panic!("unexpected error {e:?}, chain height {num_blocks}"),
        Ok(_) => panic!("expected chainstate initialization to fail"),
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn genesis_check_ok_empty_chain(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    genesis_check_ok(0, &mut rng);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn genesis_check_ok_nonempty_chain(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    genesis_check_ok(rng.gen_range(1..100), &mut rng);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn genesis_check_err_empty_chain(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    genesis_check_err(0, &mut rng);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn genesis_check_err_height_1(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    genesis_check_err(1, &mut rng);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn genesis_check_err_nonempty_chain(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    genesis_check_err(rng.gen_range(2..100), &mut rng);
}
