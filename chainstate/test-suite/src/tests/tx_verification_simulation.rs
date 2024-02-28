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

use super::*;
use common::{
    chain::{ConsensusUpgrade, NetUpgrades, PoSChainConfigBuilder, UtxoOutPoint},
    primitives::{BlockCount, Idable},
};
use crypto::{
    key::{KeyKind, PrivateKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};

#[rstest]
#[trace]
#[case(Seed::from_entropy(), 20, 50)]
//#[case(1326317083504692347.into(), 20, 50)]
fn simulation(#[case] seed: Seed, #[case] max_blocks: usize, #[case] max_tx_per_block: usize) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);

        let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let (staking_sk, staking_pk) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let (config_builder, genesis_pool_id) =
            chainstate_test_framework::create_chain_config_with_default_staking_pool(
                &mut rng, staking_pk, vrf_pk,
            );

        let upgrades = vec![(
            BlockHeight::new(0),
            ConsensusUpgrade::PoS {
                initial_difficulty: None,
                config: PoSChainConfigBuilder::new_for_unit_test()
                    .staking_pool_spend_maturity_block_count(BlockCount::new(5))
                    .build(),
            },
        )];
        let consensus_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");

        let chain_config = config_builder
            .consensus_upgrades(consensus_upgrades)
            .max_future_block_time_offset(std::time::Duration::from_secs(1_000_000))
            .build();
        let target_time = chain_config.target_block_spacing();
        let genesis_pool_outpoint = UtxoOutPoint::new(chain_config.genesis_block_id().into(), 1);

        // Initialize original TestFramework
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.clone())
            .with_initial_time_since_genesis(target_time.as_secs())
            .with_staking_pools(BTreeMap::from_iter([(
                genesis_pool_id,
                (
                    staking_sk.clone(),
                    vrf_sk.clone(),
                    genesis_pool_outpoint.clone(),
                ),
            )]))
            .build();

        // Generate a random chain
        for _ in 0..rng.gen_range(10..max_blocks) {
            let mut block_builder = tf.make_pos_block_builder().with_random_staking_pool(&mut rng);

            for _ in 0..rng.gen_range(10..max_tx_per_block) {
                block_builder = block_builder.add_test_transaction(&mut rng);
            }

            block_builder.build_and_process().unwrap().unwrap();

            tf.progress_time_seconds_since_epoch(target_time.as_secs());
        }
        let old_best_block_id = tf.best_block_id();

        // Create longer chain to trigger reorg and disconnect all the random txs.
        //
        // Second TestFramework with separate storage is used, because generating alternative chain
        // requires up-to-date kernel information which is not trivial to implement from outside of chainstate.
        // So here we create a separate chain from the same Genesis and submit blocks one by one eventually
        // triggering a reorg.
        let mut tf2 = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config)
            .with_initial_time_since_genesis(target_time.as_secs())
            .with_staking_pools(BTreeMap::from_iter([(
                genesis_pool_id,
                (staking_sk.clone(), vrf_sk.clone(), genesis_pool_outpoint),
            )]))
            .build();

        let mut prev_block_id = tf2.genesis().get_id().into();
        for _ in 0..max_blocks {
            let block = tf2
                .make_pos_block_builder()
                .with_parent(prev_block_id)
                .with_stake_pool(genesis_pool_id)
                .with_stake_spending_key(staking_sk.clone())
                .with_vrf_key(vrf_sk.clone())
                .build();
            prev_block_id = block.get_id().into();
            tf2.process_block(block.clone(), BlockSource::Local).unwrap();
            tf2.progress_time_seconds_since_epoch(target_time.as_secs());

            // submit block to the original chain
            tf.process_block(block, BlockSource::Local).unwrap();
        }

        assert_ne!(old_best_block_id, tf.best_block_id());
        assert_eq!(tf.best_block_id(), tf2.best_block_id());
    });
}
