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

use chainstate_storage::Transactional;
use chainstate_test_framework::{anyonecanspend_address, TestFramework};
use chainstate_types::{pos_randomness::PoSRandomness, vrf_tools::construct_transcript};
use common::{
    chain::{
        block::{consensus_data::PoSData, timestamp::BlockTimestamp},
        config::EpochIndex,
        signature::inputsig::InputWitness,
        stakelock::StakePoolData,
        OutPoint, PoolId, RequiredConsensus,
    },
    primitives::{Amount, BlockHeight, Compact},
};
use consensus::ConsensusPoSError;
use crypto::{
    random::{CryptoRng, Rng},
    vrf::{VRFPrivateKey, VRFPublicKey},
};

use super::block_index_handle_impl::TestBlockIndexHandle;

#[allow(clippy::too_many_arguments)]
pub fn pos_mine(
    initial_timestamp: BlockTimestamp,
    kernel_outpoint: OutPoint,
    vrf_sk: &VRFPrivateKey,
    sealed_epoch_randomness: PoSRandomness,
    pool_id: PoolId,
    pool_balance: Amount,
    epoch_index: EpochIndex,
    target: Compact,
) -> Option<(PoSData, BlockTimestamp)> {
    let mut timestamp = initial_timestamp;

    for _ in 0..1000 {
        let transcript =
            construct_transcript(epoch_index, &sealed_epoch_randomness.value(), timestamp);
        let vrf_data = vrf_sk.produce_vrf_data(transcript.into());
        let pos_data = PoSData::new(
            vec![kernel_outpoint.clone().into()],
            vec![InputWitness::NoSignature(None)],
            pool_id,
            vrf_data,
            target,
        );

        let vrf_pk = VRFPublicKey::from_private_key(vrf_sk);
        if consensus::check_pos_hash(
            epoch_index,
            &sealed_epoch_randomness,
            &pos_data,
            &vrf_pk,
            timestamp,
            pool_balance,
        )
        .is_ok()
        {
            return Some((pos_data, timestamp));
        }

        timestamp = timestamp.add_int_seconds(1).unwrap();
    }
    None
}

pub fn calculate_new_target(
    tf: &mut TestFramework,
    block_height: BlockHeight,
) -> Result<Compact, ConsensusPoSError> {
    let pos_status =
        match tf.chainstate.get_chain_config().net_upgrade().consensus_status(block_height) {
            RequiredConsensus::PoS(status) => status,
            RequiredConsensus::PoW(_) | RequiredConsensus::IgnoreConsensus => {
                panic!("Invalid consensus")
            }
        };

    let db_tx = tf.storage.transaction_ro().unwrap();
    let block_index_handle =
        TestBlockIndexHandle::new(db_tx, tf.chainstate.get_chain_config().as_ref());

    consensus::calculate_target_required(
        tf.chainstate.get_chain_config().as_ref(),
        &pos_status,
        tf.best_block_id(),
        &block_index_handle,
    )
}

pub fn create_stake_pool_data(
    rng: &mut (impl Rng + CryptoRng),
    amount: Amount,
    vrf_pk: VRFPublicKey,
) -> StakePoolData {
    let destination = super::new_pub_key_destination(rng);
    StakePoolData::new(
        amount,
        anyonecanspend_address(),
        vrf_pk,
        destination,
        0,
        Amount::ZERO,
    )
}
