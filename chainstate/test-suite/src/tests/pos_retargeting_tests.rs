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

use std::{num::NonZeroU64, time::Duration};

use super::helpers::{
    new_pub_key_destination,
    pos::{calculate_new_target, pos_mine},
};

use chainstate::{
    chainstate_interface::ChainstateInterface, BlockError, ChainstateError, CheckBlockError,
};
use chainstate_storage::{BlockchainStorageRead, Transactional};
use chainstate_test_framework::{
    anyonecanspend_address, empty_witness, TestFramework, TransactionBuilder,
};
use chainstate_types::vrf_tools::construct_transcript;
use common::{
    chain::{
        block::{consensus_data::PoSData, timestamp::BlockTimestamp, ConsensusData},
        config::Builder as ConfigBuilder,
        create_unittest_pos_config,
        signature::inputsig::InputWitness,
        stakelock::StakePoolData,
        ConsensusUpgrade, NetUpgrades, OutPoint, OutPointSourceId, PoolId, TxInput, TxOutput,
        UpgradeVersion,
    },
    primitives::{Amount, BlockHeight, Compact, Idable},
    Uint256,
};
use consensus::{ConsensusPoSError, ConsensusVerificationError};
use crypto::{random::CryptoRng, vrf::VRFPublicKey};
use crypto::{
    random::Rng,
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

const TARGET_BLOCK_TIME: Duration = Duration::from_secs(2 * 60);
const STAKED_BALANCE: Amount = Amount::from_atoms(1);

// Create a chain genesis <- block_1
// block_1 has tx with StakePool output
fn setup_test_chain_with_staked_pool(
    rng: &mut (impl Rng + CryptoRng),
    vrf_pk: VRFPublicKey,
) -> (TestFramework, PoolId) {
    let difficulty = Uint256::MAX;
    let upgrades = vec![
        (
            BlockHeight::new(0),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
        ),
        (
            BlockHeight::new(2),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoS {
                initial_difficulty: difficulty.into(),
                config: create_unittest_pos_config(),
            }),
        ),
    ];
    let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
    let chain_config = ConfigBuilder::test_chain()
        .net_upgrades(net_upgrades)
        .epoch_length(NonZeroU64::new(2).unwrap())
        .sealed_epoch_distance_from_tip(0)
        .build();
    let mut tf = TestFramework::builder(rng).with_chain_config(chain_config).build();

    let genesis_id = tf.genesis().get_id();
    let pool_id = pos_accounting::make_pool_id(&OutPoint::new(
        OutPointSourceId::BlockReward(genesis_id.into()),
        0,
    ));

    let stake_pool_data = StakePoolData::new(
        STAKED_BALANCE,
        anyonecanspend_address(),
        vrf_pk,
        new_pub_key_destination(rng),
        0,
        Amount::ZERO,
    );

    let tx = TransactionBuilder::new()
        .add_input(
            TxInput::new(OutPointSourceId::BlockReward(genesis_id.into()), 0),
            empty_witness(rng),
        )
        .add_output(TxOutput::StakePool(Box::new(stake_pool_data)))
        .build();
    tf.make_block_builder().add_transaction(tx).build_and_process().unwrap();

    (tf, pool_id)
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn stable_block_time(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (mut tf, pool_id) = setup_test_chain_with_staked_pool(&mut rng, vrf_pk);

    for _i in 0..50 {
        let initial_block_time = BlockTimestamp::from_duration_since_epoch(tf.current_time());
        let new_block_height = tf.best_block_index().block_height().next_height();
        let new_target = calculate_new_target(&mut tf, new_block_height).unwrap();

        let current_epoch_index =
            tf.chainstate.get_chain_config().epoch_index_from_height(&new_block_height);
        let sealed_epoch_index =
            tf.chainstate.get_chain_config().sealed_epoch_index(&new_block_height).unwrap();
        let sealed_epoch_randomness = tf
            .storage
            .transaction_ro()
            .unwrap()
            .get_epoch_data(sealed_epoch_index)
            .unwrap()
            .map_or(tf.chainstate.get_chain_config().initial_randomness(), |d| {
                d.randomness().value()
            });
        let best_block_outputs = tf.outputs_from_genblock(tf.best_block_id());

        let (pos_data, valid_block_timestamp) = pos_mine(
            initial_block_time,
            OutPoint::new(best_block_outputs.keys().next().unwrap().clone(), 0),
            &vrf_sk,
            chainstate_types::pos_randomness::PoSRandomness::new(sealed_epoch_randomness),
            pool_id,
            STAKED_BALANCE,
            current_epoch_index,
            new_target,
        )
        .expect("should be able to mine");

        let reward_output = TxOutput::ProduceBlockFromStake(
            Amount::from_atoms(1),
            anyonecanspend_address(),
            pool_id,
        );
        tf.make_block_builder()
            .with_consensus_data(ConsensusData::PoS(Box::new(pos_data.clone())))
            .with_timestamp(valid_block_timestamp)
            .with_reward(vec![reward_output])
            .build_and_process()
            .unwrap();

        tf.progress_time_seconds_since_epoch(TARGET_BLOCK_TIME.as_secs());
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn invalid_target(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (mut tf, pool_id) = setup_test_chain_with_staked_pool(&mut rng, vrf_pk);

    let invalid_target = Compact(1);

    let transcript = construct_transcript(
        0,
        &tf.chainstate.get_chain_config().initial_randomness(),
        BlockTimestamp::from_duration_since_epoch(tf.current_time()),
    );
    let vrf_data = vrf_sk.produce_vrf_data(transcript.into());
    let best_block_outputs = tf.outputs_from_genblock(tf.best_block_id());
    let pos_data = PoSData::new(
        vec![TxInput::new(best_block_outputs.keys().next().unwrap().clone(), 0)],
        vec![InputWitness::NoSignature(None)],
        pool_id,
        vrf_data,
        invalid_target,
    );

    let reward_output =
        TxOutput::ProduceBlockFromStake(Amount::from_atoms(1), anyonecanspend_address(), pool_id);
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
