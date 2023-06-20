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

use chainstate_test_framework::TestFramework;
use common::{
    chain::{stakelock::StakePoolData, Destination, Mlt, PoolId},
    primitives::{per_thousand::PerThousand, Amount, BlockDistance, BlockHeight, Idable, H256},
};
use crypto::{
    key::{KeyKind, PrivateKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use test_utils::random::make_seedable_rng;

use criterion::{criterion_group, criterion_main, Criterion};

pub fn pow_reorg(c: &mut Criterion) {
    let mut rng = make_seedable_rng(1111.into());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(
            common::chain::config::Builder::new(common::chain::config::ChainType::Regtest)
                .net_upgrades(common::chain::NetUpgrades::unit_tests())
                .max_depth_for_reorg(BlockDistance::new(5000))
                .build(),
        )
        .build();

    let common_block_id = tf.create_chain(&tf.genesis().get_id().into(), 5, &mut rng).unwrap();

    tf.create_chain(&common_block_id, 1000, &mut rng).unwrap();

    c.bench_function("PoW reorg", |b| {
        b.iter(|| {
            tf.create_chain(&common_block_id, 1001, &mut rng).unwrap();
        })
    });
}

pub fn pos_reorg(c: &mut Criterion) {
    let mut rng = make_seedable_rng(1111.into());
    let (staking_sk, staking_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

    let pool_id = PoolId::new(H256::random_using(&mut rng));
    let stake_pool_data = StakePoolData::new(
        Amount::from_atoms(40_000_000 * Mlt::ATOMS_PER_MLT),
        Destination::PublicKey(staking_pk),
        vrf_pk,
        Destination::AnyoneCanSpend,
        PerThousand::new(1000).unwrap(),
        Amount::ZERO,
    );
    let mint_amount = Amount::from_atoms(1000);

    let chain_config = chainstate_test_framework::create_chain_config_with_staking_pool(
        mint_amount,
        pool_id,
        stake_pool_data,
    )
    .max_depth_for_reorg(BlockDistance::new(5000))
    .build();
    let target_block_time =
        chainstate_test_framework::get_target_block_time(&chain_config, BlockHeight::new(1));
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();
    tf.progress_time_seconds_since_epoch(target_block_time.get());

    let common_block_id = tf
        .create_chain_pos(
            &tf.genesis().get_id().into(),
            5,
            &mut rng,
            &staking_sk,
            &vrf_sk,
        )
        .unwrap();

    tf.create_chain_pos(&common_block_id, 100, &mut rng, &staking_sk, &vrf_sk)
        .unwrap();

    c.bench_function("PoS reorg", |b| {
        b.iter(|| {
            tf.create_chain_pos(&common_block_id, 101, &mut rng, &staking_sk, &vrf_sk)
                .unwrap();
        })
    });
}

criterion_group!(benches, pow_reorg, pos_reorg);
criterion_main!(benches);
