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

use std::{collections::BTreeMap, num::NonZeroU64};

use super::*;
use chainstate_storage::{BlockchainStorageWrite, TransactionRw, Transactional};
use common::{
    chain::{
        ChainstateUpgradeBuilder, ConsensusUpgrade, NetUpgrades, PoSChainConfigBuilder,
        TokenIdGenerationVersion, UtxoOutPoint,
    },
    primitives::BlockCount,
};
use crypto::{
    key::{KeyKind, PrivateKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};

#[rstest]
#[trace]
#[case(Seed::from_entropy(), 20, 50)]
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

        let epoch_length = NonZeroU64::new(rng.gen_range(1..10)).unwrap();
        let sealed_epoch_distance_from_tip = rng.gen_range(1..10);
        let token_id_generation_v1_fork_height =
            BlockHeight::new(rng.gen_range(1..=max_blocks + 1) as u64);
        let chain_config = config_builder
            .consensus_upgrades(consensus_upgrades)
            .max_future_block_time_offset(Some(std::time::Duration::from_secs(1_000_000)))
            .epoch_length(epoch_length)
            .sealed_epoch_distance_from_tip(sealed_epoch_distance_from_tip)
            .chainstate_upgrades(
                common::chain::NetUpgrades::initialize(vec![
                    (
                        BlockHeight::zero(),
                        ChainstateUpgradeBuilder::latest()
                            .token_id_generation_version(TokenIdGenerationVersion::V0)
                            .build(),
                    ),
                    (
                        token_id_generation_v1_fork_height,
                        ChainstateUpgradeBuilder::latest()
                            .token_id_generation_version(TokenIdGenerationVersion::V1)
                            .build(),
                    ),
                ])
                .unwrap(),
            )
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

        // Reference TestFramework is used to recreate expected storage after reorg
        let mut reference_tf = TestFramework::builder(&mut rng)
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

        // TestFramework that represents alternative chain. Up until some arbitrary height it contains
        // common blocks with the original chain.
        //
        // Second TestFramework with separate storage is used, because generating alternative chain
        // requires up-to-date kernel information which is not trivial to implement from outside of chainstate.
        // So here we process the same blocks from separate TestFrameworks to get the same state.
        let mut tf2 = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config)
            .with_initial_time_since_genesis(target_time.as_secs())
            .with_staking_pools(BTreeMap::from_iter([(
                genesis_pool_id,
                (staking_sk.clone(), vrf_sk.clone(), genesis_pool_outpoint),
            )]))
            .build();

        // Generate a random chain
        let mut all_blocks = Vec::new();
        let blocks_to_generate = rng.gen_range((max_blocks / 2)..max_blocks);
        let reorg_at_height = rng.gen_range(0..blocks_to_generate);
        for i in 0..blocks_to_generate {
            let mut block_builder = tf.make_pos_block_builder().with_random_staking_pool(&mut rng);

            for _ in 0..rng.gen_range(10..max_tx_per_block) {
                block_builder = block_builder.add_test_transaction(&mut rng);
            }

            let block = block_builder.build(&mut rng);
            let block_index = tf.process_block(block.clone(), BlockSource::Local).unwrap();

            // submit common blocks to the alternative chain
            if i <= reorg_at_height {
                tf2.process_block(block.clone(), BlockSource::Peer).unwrap();
                tf2.progress_time_seconds_since_epoch(target_time.as_secs());
                reference_tf.process_block(block.clone(), BlockSource::Peer).unwrap();
                reference_tf.progress_time_seconds_since_epoch(target_time.as_secs());

                tf2.staking_pools = tf.staking_pools.clone();
                tf2.key_manager = tf.key_manager.clone();
            }

            all_blocks.push((block, block_index.unwrap()));
        }
        let old_best_block_id = tf.best_block_id();

        // Manually update reference storage.
        // After reorg only blocks and block indexes are left from the original chain
        {
            let mut db_tx = reference_tf.storage.transaction_rw(None).unwrap();
            for (block, block_index) in all_blocks {
                db_tx.set_block_index(&block_index).unwrap();
                db_tx.add_block(&block).unwrap();
            }
            db_tx.commit().unwrap();
        }

        // Create longer chain to trigger reorg and disconnect all the random txs.
        for _ in reorg_at_height..max_blocks {
            let mut block_builder = tf2.make_pos_block_builder().with_random_staking_pool(&mut rng);

            for _ in 0..rng.gen_range(10..max_tx_per_block) {
                block_builder = block_builder.add_test_transaction(&mut rng);
            }

            let block = block_builder.build(&mut rng);
            tf2.process_block(block.clone(), BlockSource::Local).unwrap();

            // submit alternative blocks to the original chain
            tf.process_block(block.clone(), BlockSource::Peer).unwrap();
            reference_tf.process_block(block, BlockSource::Peer).unwrap();
            reference_tf.progress_time_seconds_since_epoch(target_time.as_secs());
        }

        assert_ne!(old_best_block_id, tf.best_block_id());
        assert_eq!(tf.best_block_id(), tf2.best_block_id());

        // Exclude PoS accounting epoch delta from the comparison.
        // This is a workaround because deltas are never removed on undo but rather replaced with None value.
        // It seems like an acceptable trade-off for the simplicity of the test given that Sealed storage
        // which utilizes such epoch deltas is not used in production.
        let last_epoch =
            tf.chain_config().epoch_index_from_height(&BlockHeight::new(max_blocks as u64));
        {
            let mut db_tx = tf.storage.transaction_rw(None).unwrap();
            for i in 0..=last_epoch {
                db_tx.del_accounting_epoch_delta(i).unwrap();
                db_tx.del_accounting_epoch_undo_delta(i).unwrap();
            }
            db_tx.commit().unwrap();
        }
        {
            let mut db_tx = reference_tf.storage.transaction_rw(None).unwrap();
            for i in 0..=last_epoch {
                db_tx.del_accounting_epoch_delta(i).unwrap();
                db_tx.del_accounting_epoch_undo_delta(i).unwrap();
            }
            db_tx.commit().unwrap();
        }

        assert_eq!(
            tf.storage.transaction_ro().unwrap().dump_raw(),
            reference_tf.storage.transaction_ro().unwrap().dump_raw()
        );
    });
}
