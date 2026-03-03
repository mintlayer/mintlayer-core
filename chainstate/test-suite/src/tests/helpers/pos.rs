// Copyright (c) 2021-2022 RBB S.r.l
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

use chainstate_test_framework::{calculate_new_pos_compact_target, TestFramework};
use common::{
    chain::{CoinUnit, Genesis},
    primitives::{BlockHeight, Compact},
};
use consensus::ConsensusPoSError;
use crypto::{key::PublicKey, vrf::VRFPublicKey};

pub fn calculate_new_target(
    tf: &TestFramework,
    block_height: BlockHeight,
) -> Result<Compact, ConsensusPoSError> {
    calculate_new_pos_compact_target(tf, block_height, &tf.best_block_id())
}

pub fn create_custom_genesis_with_stake_pool(
    staker_pk: PublicKey,
    vrf_pk: VRFPublicKey,
) -> Genesis {
    let initial_amount = CoinUnit::from_coins(100_000_000).to_amount_atoms();
    let initial_pool_amount = (initial_amount / 3).unwrap();
    let initial_mint_amount = (initial_amount - initial_pool_amount).unwrap();

    chainstate_test_framework::create_custom_genesis_with_stake_pool(
        staker_pk,
        vrf_pk,
        initial_mint_amount,
        initial_pool_amount,
    )
}
