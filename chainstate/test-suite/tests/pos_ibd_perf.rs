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

// (experimental) Decomposes PoS block cost into building vs chainstate processing.
// Run: cargo test -p chainstate-test-suite --release --test pos_ibd_perf -- --ignored --nocapture
//
// Throwaway measurement code for the experimental IBD/indexer performance branch.

use chainstate_test_framework::TestFramework;
use common::{
    chain::{Destination, PoolId, config::create_unit_test_config, stakelock::StakePoolData},
    primitives::{Amount, BlockDistance, H256, Idable, per_thousand::PerThousand},
};
use crypto::{
    key::{KeyKind, PrivateKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use test_utils::random::make_seedable_rng;

const BLOCKS: usize = 200;

#[test]
#[ignore = "experimental perf decomposition"]
fn pos_build_vs_process_decomposition() {
    let mut rng = make_seedable_rng(3333.into());
    let (staking_sk, staking_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let (vrf_sk, _vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

    let genesis_pool_id = PoolId::new(H256::random_using(&mut rng));
    let stake_pool_pledge = create_unit_test_config().min_stake_pool_pledge();
    let stake_pool_data = StakePoolData::new(
        stake_pool_pledge,
        Destination::PublicKey(staking_pk),
        _vrf_pk,
        Destination::AnyoneCanSpend,
        PerThousand::new(1000).unwrap(),
        Amount::ZERO,
    );
    let mint_amount = Amount::from_atoms(1000);

    let chain_config = chainstate_test_framework::create_chain_config_with_staking_pool(
        &mut rng,
        mint_amount,
        genesis_pool_id,
        stake_pool_data,
    )
    .max_depth_for_reorg(BlockDistance::new(5000))
    .build();
    let target_block_time = chain_config.target_block_spacing();

    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();
    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());

    tf.create_chain_pos(
        &mut rng,
        &tf.genesis().get_id().into(),
        5,
        genesis_pool_id,
        &staking_sk,
        &vrf_sk,
    )
    .unwrap();

    // Build/process must alternate (PoS building needs the parent's processed
    // state), so accumulate two separate stopwatches over BLOCKS blocks.
    let mut build_elapsed = std::time::Duration::ZERO;
    let mut process_elapsed = std::time::Duration::ZERO;
    let mut parent = tf.best_block_id();
    for _ in 0..BLOCKS {
        tf.progress_time_seconds_since_epoch(target_block_time.as_secs());

        let t0 = std::time::Instant::now();
        let block = tf
            .make_pos_block_builder()
            .with_parent(parent)
            .with_stake_pool_id(genesis_pool_id)
            .with_stake_spending_key(staking_sk.clone())
            .with_vrf_key(vrf_sk.clone())
            .build(&mut rng);
        build_elapsed += t0.elapsed();

        let t1 = std::time::Instant::now();
        tf.process_block(block, chainstate::BlockSource::Local).unwrap();
        process_elapsed += t1.elapsed();

        parent = tf.best_block_id();
    }

    eprintln!(
        "(experimental) PoS blocks: {BLOCKS}\n  build:   {:>8.2} ms/block\n  process: {:>8.2} ms/block",
        build_elapsed.as_nanos() as f64 / BLOCKS as f64 / 1e6,
        process_elapsed.as_nanos() as f64 / BLOCKS as f64 / 1e6,
    );
}
