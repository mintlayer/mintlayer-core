// Copyright (c) 2025 RBB S.r.l
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
    chain::{config::create_unit_test_config, Block, ChainConfig},
    primitives::{BlockHeight, Idable as _},
};
use crypto::{
    key::{KeyKind, PrivateKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use randomness::{CryptoRng, Rng};

/// Create a chain of the specified number of blocks, using either IgnoreConsensus or PoS.
pub fn create_chain(
    block_count: usize,
    use_pos: bool,
    rng: &mut (impl Rng + CryptoRng),
) -> (ChainConfig, Vec<Block>) {
    let (chain_config, tf) = if use_pos {
        let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel);
        let (staker_sk, staker_pk) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);

        let (chain_config_builder, genesis_pool_id) =
            chainstate_test_framework::create_chain_config_with_default_staking_pool(
                rng, staker_pk, vrf_pk,
            );
        let chain_config = chain_config_builder.build();

        let mut tf = TestFramework::builder(rng).with_chain_config(chain_config.clone()).build();

        // Note: create_chain_pos_randomizing_time will advance time after creating each block,
        // so we need to do the advancement explicitly before the first one.
        let target_block_time = chain_config.target_block_spacing();
        let time_advancement = rng.gen_range(1..target_block_time.as_secs() * 2);
        tf.progress_time_seconds_since_epoch(time_advancement);

        tf.create_chain_pos_randomizing_time(
            rng,
            &tf.genesis().get_id().into(),
            block_count,
            genesis_pool_id,
            &staker_sk,
            &vrf_sk,
        )
        .unwrap();

        (chain_config, tf)
    } else {
        let chain_config = create_unit_test_config();

        let mut tf = TestFramework::builder(rng).with_chain_config(chain_config.clone()).build();

        tf.create_chain_advancing_time_return_ids(&tf.genesis().get_id().into(), block_count, rng)
            .unwrap();

        (chain_config, tf)
    };

    let blocks = tf.chainstate.get_mainchain_blocks(BlockHeight::new(1), usize::MAX).unwrap();

    (chain_config, blocks)
}
