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

use std::sync::Arc;

use chainstate::{ban_score::BanScore, BlockError, ChainstateError, CheckBlockError};
use chainstate_test_framework::TestFramework;
use common::{
    chain::{
        block::{timestamp::BlockTimestamp, BlockReward, ConsensusData},
        config::{create_unit_test_config, Builder as ChainConfigBuilder, ChainType},
        Block, NetUpgrades,
    },
    primitives::Idable,
};
use consensus::ConsensusVerificationError;
use p2p_test_utils::start_subsystems_with_chainstate;
use test_utils::random::Seed;

use crate::{
    message::{Announcement, BlockListRequest, SyncMessage},
    sync::tests::helpers::SyncManagerHandle,
    types::peer_id::PeerId,
    P2pError,
};

// Announcements from unknown peers are ignored.
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
#[should_panic = "Received a message from unknown peer"]
async fn nonexistent_peer(#[case] seed: Seed) {
    todo!();
    // let mut rng = test_utils::random::make_seedable_rng(seed);
    //
    // let chain_config = Arc::new(create_unit_test_config());
    // let mut tf = TestFramework::builder(&mut rng)
    //     .with_chain_config(chain_config.as_ref().clone())
    //     .build();
    // let block = tf.make_block_builder().build();
    // let (chainstate, mempool) = start_subsystems_with_chainstate(tf.into_chainstate()).await;
    //
    // let mut handle = SyncManagerHandle::builder()
    //     .with_chain_config(chain_config)
    //     .with_subsystems(chainstate, mempool)
    //     .build()
    //     .await;
    //
    // let peer = PeerId::new();
    //
    // handle.make_announcement(peer, Announcement::Block(Box::new(block.header().clone())));
    //
    // handle.resume_panic().await;
}
