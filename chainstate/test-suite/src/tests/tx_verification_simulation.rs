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
use common::primitives::Idable;
use crypto::{
    key::{KeyKind, PrivateKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};

#[rstest]
#[trace]
#[case(Seed::from_entropy(), 20, 50)]
//#[case(10420439202681780483.into(), 20, 50)]
//#[case(15352447044211464671.into(), 20, 50)]
fn simulation(#[case] seed: Seed, #[case] max_blocks: usize, #[case] max_tx_per_block: usize) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);

        let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let (staking_sk, staking_pk) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let (config_builder, genesis_pool) =
            chainstate_test_framework::create_chain_config_with_default_staking_pool(
                &mut rng, staking_pk, vrf_pk,
            );

        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(config_builder.build())
            .with_staking_pools(BTreeMap::from_iter([(genesis_pool, (staking_sk, vrf_sk))]))
            .build();
        tf.progress_time_seconds_since_epoch(1);

        for _ in 0..rng.gen_range(10..max_blocks) {
            let mut block_builder = tf.make_pos_block_builder(&mut rng, None);

            for _ in 0..rng.gen_range(10..max_tx_per_block) {
                block_builder = block_builder.add_test_transaction(&mut rng);
            }

            block_builder.build_and_process().unwrap().unwrap();

            tf.progress_time_seconds_since_epoch(1);
        }
        let best_block_id = tf.best_block_id();

        // create longer chain to trigger reorg and disconnect all the random txs
        let genesis = &tf.genesis().get_id().into();
        let new_best_block_id = tf.create_chain(genesis, max_blocks, &mut rng).unwrap();
        assert_ne!(best_block_id, tf.best_block_id());
        assert_eq!(new_best_block_id, tf.best_block_id());
    });
}
