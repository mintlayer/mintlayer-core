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

use std::num::NonZeroU64;

use chainstate::{
    chainstate_interface::ChainstateInterface, BlockError, ChainstateError, CheckBlockError,
};
use chainstate_test_framework::{
    anyonecanspend_address, empty_witness, TestFramework, TransactionBuilder,
};
use chainstate_types::vrf_tools::{construct_transcript, ProofOfStakeVRFError};
use common::{
    chain::{
        block::{consensus_data::PoSData, timestamp::BlockTimestamp, ConsensusData},
        config::{Builder as ConfigBuilder, EpochIndex},
        signature::inputsig::InputWitness,
        stakelock::StakePoolData,
        tokens::OutputValue,
        ConsensusUpgrade, NetUpgrades, OutPoint, OutPointSourceId, OutputPurpose, PoolId, TxInput,
        TxOutput, UpgradeVersion,
    },
    primitives::{Amount, BlockHeight, Compact, Idable, H256},
    Uint256,
};
use consensus::{ConsensusPoSError, ConsensusVerificationError};
use crypto::random::CryptoRng;
use crypto::{
    key::{KeyKind, PrivateKey},
    random::Rng,
    vrf::{VRFError, VRFKeyKind, VRFPrivateKey},
};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

fn create_chain_with_stake_pool(
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
) -> (OutPoint, PoolId, VRFPrivateKey) {
    let genesis_id = tf.genesis().get_id();
    let (_, pub_key) = PrivateKey::new_from_rng(rng, KeyKind::RistrettoSchnorr);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel);
    let tx = TransactionBuilder::new()
        .add_input(
            TxInput::new(OutPointSourceId::BlockReward(genesis_id.into()), 0),
            empty_witness(rng),
        )
        .add_output(TxOutput::new(
            OutputValue::Coin(Amount::from_atoms(1)),
            OutputPurpose::StakePool(Box::new(StakePoolData::new(
                anyonecanspend_address(),
                None,
                vrf_pk,
                pub_key,
                0,
                Amount::ZERO,
            ))),
        ))
        .build();
    let tx_id = tx.transaction().get_id();
    let pool_id = pos_accounting::make_pool_id(&OutPoint::new(
        OutPointSourceId::BlockReward(genesis_id.into()),
        0,
    ));

    tf.make_block_builder()
        .add_transaction(tx)
        .build_and_process()
        .unwrap()
        .unwrap();

    (
        OutPoint::new(OutPointSourceId::Transaction(tx_id), 0),
        pool_id,
        vrf_sk,
    )
}

// Create a chain genesis <- block_1 <- block_1
// PoS consensus activates on height 2.
// block_1 has valid StakePool output. block_2 has PoS kernel input from block_1.
// Check that the chain is valid.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn pos_basic(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let upgrades = vec![
        (
            BlockHeight::new(0),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
        ),
        (
            BlockHeight::new(2),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoS),
        ),
    ];
    let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
    let chain_config = ConfigBuilder::test_chain()
        .net_upgrades(net_upgrades)
        .epoch_length(NonZeroU64::new(2).unwrap())
        .sealed_epoch_distance_from_tip(0)
        .build();
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();

    let (stake_pool_outpoint, pool_id, vrf_sk) = create_chain_with_stake_pool(&mut rng, &mut tf);

    let difficulty =
        Uint256([0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF]);
    let prev_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let block_timestamp = BlockTimestamp::from_duration_since_epoch(tf.current_time());
    let vrf_transcript = construct_transcript(1, &prev_randomness, block_timestamp);
    let vrf_data = vrf_sk.produce_vrf_data(vrf_transcript.into());
    let pos_data = PoSData::new(
        vec![stake_pool_outpoint.into()],
        vec![InputWitness::NoSignature(None)],
        pool_id,
        vrf_data,
        Compact::from(difficulty),
    );

    tf.make_block_builder()
        .with_consensus_data(ConsensusData::PoS(pos_data))
        .build_and_process()
        .unwrap()
        .unwrap();
}

// PoS consensus activates on height 1.
// Try create a block from genesis, where kernel is genesis block reward.
// Check that processing of the block fails.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn pos_invalid_kernel_input(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let upgrades = vec![
        (
            BlockHeight::new(0),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
        ),
        (
            BlockHeight::new(1),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoS),
        ),
    ];
    let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
    let chain_config = ConfigBuilder::test_chain()
        .net_upgrades(net_upgrades)
        .epoch_length(NonZeroU64::new(1).unwrap())
        .sealed_epoch_distance_from_tip(0)
        .build();
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();

    let genesis_id = tf.genesis().get_id();
    let (vrf_sk, _) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let pool_id = pos_accounting::make_pool_id(&OutPoint::new(
        OutPointSourceId::BlockReward(genesis_id.into()),
        0,
    ));

    let difficulty =
        Uint256([0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF]);
    let prev_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let block_timestamp = BlockTimestamp::from_duration_since_epoch(tf.current_time());
    let vrf_transcript = construct_transcript(1, &prev_randomness, block_timestamp);
    let vrf_data = vrf_sk.produce_vrf_data(vrf_transcript.into());
    let pos_data = PoSData::new(
        vec![TxInput::new(OutPointSourceId::BlockReward(genesis_id.into()), 0)],
        vec![InputWitness::NoSignature(None)],
        pool_id,
        vrf_data,
        Compact::from(difficulty),
    );

    let res = tf
        .make_block_builder()
        .with_consensus_data(ConsensusData::PoS(pos_data))
        .build_and_process()
        .unwrap_err();

    assert!(matches!(
        res,
        ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
            CheckBlockError::ConsensusVerificationFailed(ConsensusVerificationError::PoSError(
                ConsensusPoSError::InvalidOutputPurposeInStakeKernel(_)
            ))
        ))
    ));
}

// Create a chain genesis <- block_1, where block_1 has valid StakePool output.
// PoS consensus activates on height 2.
// Try to crete block_2 with PoS data that has mistakes in VRF:
// wrong timestamp, wrong previous randomness, wrong epoch index, wrong private key.
// All these mistake should produce verification error.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn pos_invalid_vrf(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let difficulty =
        Uint256([0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF]);
    let upgrades = vec![
        (
            BlockHeight::new(0),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
        ),
        (
            BlockHeight::new(2),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoS),
        ),
    ];
    let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
    let chain_config = ConfigBuilder::test_chain()
        .net_upgrades(net_upgrades)
        .epoch_length(NonZeroU64::new(2).unwrap())
        .sealed_epoch_distance_from_tip(0)
        .build();
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();

    let (stake_pool_outpoint, pool_id, vrf_sk) = create_chain_with_stake_pool(&mut rng, &mut tf);

    let expected_error = ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
        CheckBlockError::ConsensusVerificationFailed(ConsensusVerificationError::PoSError(
            ConsensusPoSError::VRFDataVerificationFailed(
                ProofOfStakeVRFError::VRFDataVerificationFailed(VRFError::VerificationError),
            ),
        )),
    ));

    let valid_prev_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let valid_block_timestamp = BlockTimestamp::from_duration_since_epoch(tf.current_time());
    let valid_epoch: EpochIndex = 1;
    let valid_vrf_transcript =
        construct_transcript(valid_epoch, &valid_prev_randomness, valid_block_timestamp);
    let valid_vrf_data = vrf_sk.produce_vrf_data(valid_vrf_transcript.clone().into());

    {
        // invalid prev randomness
        let invalid_randomness = H256::random_using(&mut rng);
        let vrf_transcript =
            construct_transcript(valid_epoch, &invalid_randomness, valid_block_timestamp);
        let vrf_data = vrf_sk.produce_vrf_data(vrf_transcript.into());
        let pos_data = PoSData::new(
            vec![stake_pool_outpoint.clone().into()],
            vec![InputWitness::NoSignature(None)],
            pool_id,
            vrf_data,
            Compact::from(difficulty),
        );

        let res = tf
            .make_block_builder()
            .with_consensus_data(ConsensusData::PoS(pos_data))
            .build_and_process()
            .unwrap_err();

        assert_eq!(res, expected_error);
    }

    {
        // invalid timestamp
        let block_timestamp =
            BlockTimestamp::from_duration_since_epoch(tf.current_time().saturating_mul(2));
        let vrf_transcript = construct_transcript(1, &valid_prev_randomness, block_timestamp);
        let vrf_data = vrf_sk.produce_vrf_data(vrf_transcript.into());
        let pos_data = PoSData::new(
            vec![stake_pool_outpoint.clone().into()],
            vec![InputWitness::NoSignature(None)],
            pool_id,
            vrf_data,
            Compact::from(difficulty),
        );

        let res = tf
            .make_block_builder()
            .with_consensus_data(ConsensusData::PoS(pos_data))
            .build_and_process()
            .unwrap_err();

        assert_eq!(res, expected_error);
    }

    {
        // invalid epoch
        let vrf_transcript = construct_transcript(2, &valid_prev_randomness, valid_block_timestamp);
        let vrf_data = vrf_sk.produce_vrf_data(vrf_transcript.into());
        let pos_data = PoSData::new(
            vec![stake_pool_outpoint.clone().into()],
            vec![InputWitness::NoSignature(None)],
            pool_id,
            vrf_data,
            Compact::from(difficulty),
        );

        let res = tf
            .make_block_builder()
            .with_consensus_data(ConsensusData::PoS(pos_data))
            .build_and_process()
            .unwrap_err();

        assert_eq!(res, expected_error);
    }

    {
        // invalid vrf private key
        let (vrf_sk_2, _) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let vrf_data = vrf_sk_2.produce_vrf_data(valid_vrf_transcript.into());
        let pos_data = PoSData::new(
            vec![stake_pool_outpoint.clone().into()],
            vec![InputWitness::NoSignature(None)],
            pool_id,
            vrf_data,
            Compact::from(difficulty),
        );

        let res = tf
            .make_block_builder()
            .with_consensus_data(ConsensusData::PoS(pos_data))
            .build_and_process()
            .unwrap_err();

        assert_eq!(res, expected_error);
    }

    {
        // valid case
        let pos_data = PoSData::new(
            vec![stake_pool_outpoint.into()],
            vec![InputWitness::NoSignature(None)],
            pool_id,
            valid_vrf_data,
            Compact::from(difficulty),
        );

        tf.make_block_builder()
            .with_consensus_data(ConsensusData::PoS(pos_data))
            .build_and_process()
            .unwrap()
            .unwrap();
    }
}

// Create a chain genesis <- block_1, where block_1 has valid StakePool output.
// PoS consensus activates on height 2.
// Try to crete block_2 with PoS data that has refer to invalid pool id.:
// Check that processing of the block fails.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn pos_invalid_pool_id(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let upgrades = vec![
        (
            BlockHeight::new(0),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
        ),
        (
            BlockHeight::new(2),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoS),
        ),
    ];
    let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
    let chain_config = ConfigBuilder::test_chain()
        .net_upgrades(net_upgrades)
        .epoch_length(NonZeroU64::new(2).unwrap())
        .sealed_epoch_distance_from_tip(0)
        .build();
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();

    let (stake_pool_outpoint, expected_pool_id, vrf_sk) =
        create_chain_with_stake_pool(&mut rng, &mut tf);
    let random_pool_id: PoolId = H256::random_using(&mut rng).into();

    let difficulty =
        Uint256([0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF]);
    let prev_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let block_timestamp = BlockTimestamp::from_duration_since_epoch(tf.current_time());
    let vrf_transcript = construct_transcript(1, &prev_randomness, block_timestamp);
    let vrf_data = vrf_sk.produce_vrf_data(vrf_transcript.into());
    let pos_data = PoSData::new(
        vec![stake_pool_outpoint.clone().into()],
        vec![InputWitness::NoSignature(None)],
        random_pool_id,
        vrf_data.clone(),
        Compact::from(difficulty),
    );

    let res = tf
        .make_block_builder()
        .with_consensus_data(ConsensusData::PoS(pos_data))
        .build_and_process()
        .unwrap_err();

    assert_eq!(
        res,
        ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
            CheckBlockError::ConsensusVerificationFailed(ConsensusVerificationError::PoSError(
                ConsensusPoSError::PoolBalanceNotFound(random_pool_id)
            ))
        ))
    );

    // test valid case
    let pos_data = PoSData::new(
        vec![stake_pool_outpoint.into()],
        vec![InputWitness::NoSignature(None)],
        expected_pool_id,
        vrf_data,
        Compact::from(difficulty),
    );

    tf.make_block_builder()
        .with_consensus_data(ConsensusData::PoS(pos_data))
        .build_and_process()
        .unwrap()
        .unwrap();
}
