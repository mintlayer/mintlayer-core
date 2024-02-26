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

use chainstate::{
    chainstate_interface::ChainstateInterface, BlockError, ChainstateError, CheckBlockError,
};
use chainstate_test_framework::{anyonecanspend_address, TestFramework};
use chainstate_types::vrf_tools::construct_transcript;
use common::{
    chain::{
        block::{consensus_data::PoSData, timestamp::BlockTimestamp, ConsensusData},
        signature::inputsig::InputWitness,
        TxInput, TxOutput,
    },
    primitives::Compact,
};
use consensus::{ConsensusPoSError, ConsensusVerificationError};
use crypto::{
    key::{KeyKind, PrivateKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn stable_block_time(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (staking_sk, staking_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

    let (config_builder, pool_id) =
        chainstate_test_framework::create_chain_config_with_default_staking_pool(
            &mut rng, staking_pk, vrf_pk,
        );
    let chain_config = config_builder.build();

    let target_block_time = chain_config.target_block_spacing();
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();
    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());

    for _i in 0..50 {
        tf.make_pos_block_builder(
            &mut rng,
            Some((pool_id, staking_sk.clone(), vrf_sk.clone())),
        )
        .build_and_process()
        .unwrap();
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn invalid_target(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (_, staking_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

    let (chain_config_builder, pool_id) =
        chainstate_test_framework::create_chain_config_with_default_staking_pool(
            &mut rng, staking_pk, vrf_pk,
        );
    let chain_config = chain_config_builder.build();

    let target_block_time = chain_config.target_block_spacing();
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();
    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());

    let invalid_target = Compact(1);
    let transcript = construct_transcript(
        0,
        &tf.chainstate.get_chain_config().initial_randomness(),
        BlockTimestamp::from_time(tf.current_time()),
    );
    let vrf_data = vrf_sk.produce_vrf_data(transcript.into());
    let best_block_outputs = tf.outputs_from_genblock(tf.best_block_id());
    let pos_data = PoSData::new(
        vec![TxInput::from_utxo(best_block_outputs.keys().next().unwrap().clone(), 0)],
        vec![InputWitness::NoSignature(None)],
        pool_id,
        vrf_data,
        invalid_target,
    );

    let reward_output = TxOutput::ProduceBlockFromStake(anyonecanspend_address(), pool_id);
    let res = tf
        .make_block_builder()
        .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
        .with_reward(vec![reward_output])
        .build_and_process()
        .unwrap_err();

    assert_eq!(
        res,
        ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
            CheckBlockError::ConsensusVerificationFailed(ConsensusVerificationError::PoSError(
                ConsensusPoSError::InvalidTarget(invalid_target)
            ))
        ))
    );
}
