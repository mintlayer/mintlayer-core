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
use chainstate_types::{
    pos_randomness::{PoSRandomness, PoSRandomnessError},
    vrf_tools::{construct_transcript, ProofOfStakeVRFError},
};
use common::{
    chain::{
        block::{consensus_data::PoSData, timestamp::BlockTimestamp, ConsensusData},
        config::{Builder as ConfigBuilder, EpochIndex},
        signature::inputsig::InputWitness,
        stakelock::StakePoolData,
        timelock::OutputTimeLock,
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

// It's important to have short epoch length, so that genesis and th first block can seal
// an epoch, which is required for PoS validation to work.
const TEST_EPOCH_LENGTH: NonZeroU64 = match NonZeroU64::new(2) {
    Some(v) => v,
    None => panic!("epoch length cannot be 0"),
};
const TEST_SEALED_EPOCH_DISTANCE: usize = 0;

fn create_stake_pool_data(rng: &mut (impl Rng + CryptoRng)) -> (VRFPrivateKey, StakePoolData) {
    let (_, pub_key) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel);
    (
        vrf_sk,
        StakePoolData::new(
            anyonecanspend_address(),
            None,
            vrf_pk,
            pub_key,
            0,
            Amount::ZERO,
        ),
    )
}

fn add_block_with_stake_pool(
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
    stake_pool_data: StakePoolData,
) -> (OutPoint, PoolId) {
    let genesis_id = tf.genesis().get_id();
    let tx = TransactionBuilder::new()
        .add_input(
            TxInput::new(OutPointSourceId::BlockReward(genesis_id.into()), 0),
            empty_witness(rng),
        )
        .add_output(TxOutput::new(
            OutputValue::Coin(Amount::from_atoms(1)),
            OutputPurpose::StakePool(Box::new(stake_pool_data)),
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
    )
}

fn create_pos_data(
    tf: &mut TestFramework,
    outpoint: OutPoint,
    vrf_sk: &VRFPrivateKey,
    sealed_epoch_randomness: H256,
    prev_block_randomness: H256,
    pool_id: PoolId,
    epoch_index: EpochIndex,
) -> PoSData {
    let difficulty = Uint256::MAX;
    let block_timestamp = BlockTimestamp::from_duration_since_epoch(tf.current_time());

    let vrf_sealed_epoch_transcript =
        construct_transcript(epoch_index, &sealed_epoch_randomness, block_timestamp);
    let vrf_data_from_sealed_epoch = vrf_sk.produce_vrf_data(vrf_sealed_epoch_transcript.into());

    let vrf_prev_block_transcript =
        construct_transcript(epoch_index, &prev_block_randomness, block_timestamp);
    let vrf_data_from_prev_block = vrf_sk.produce_vrf_data(vrf_prev_block_transcript.into());

    PoSData::new(
        vec![outpoint.into()],
        vec![InputWitness::NoSignature(None)],
        pool_id,
        vrf_data_from_sealed_epoch,
        vrf_data_from_prev_block,
        Compact::from(difficulty),
    )
}

fn get_best_block_randomness(tf: &TestFramework) -> PoSRandomness {
    match tf.chainstate.get_best_block_index().unwrap() {
        chainstate_types::GenBlockIndex::Block(bi) => {
            match bi.preconnect_data().consensus_extra_data() {
                chainstate_types::ConsensusExtraData::None => unreachable!(),
                chainstate_types::ConsensusExtraData::PoS(r) => r.clone(),
            }
        }
        chainstate_types::GenBlockIndex::Genesis(_) => unreachable!(),
    }
}

// Create a chain genesis <- block_1 <- block_2
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
        .epoch_length(TEST_EPOCH_LENGTH)
        .sealed_epoch_distance_from_tip(TEST_SEALED_EPOCH_DISTANCE)
        .build();
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();

    let (vrf_sk, stake_pool_data) = create_stake_pool_data(&mut rng);
    let (stake_pool_outpoint, pool_id) =
        add_block_with_stake_pool(&mut rng, &mut tf, stake_pool_data);

    let initial_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let pos_data = create_pos_data(
        &mut tf,
        stake_pool_outpoint,
        &vrf_sk,
        initial_randomness,
        initial_randomness,
        pool_id,
        1,
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
        .sealed_epoch_distance_from_tip(TEST_SEALED_EPOCH_DISTANCE)
        .build();
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();

    let genesis_id = tf.genesis().get_id();
    let (vrf_sk, _) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let pool_id = pos_accounting::make_pool_id(&OutPoint::new(
        OutPointSourceId::BlockReward(genesis_id.into()),
        0,
    ));

    let initial_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let pos_data = create_pos_data(
        &mut tf,
        OutPoint::new(OutPointSourceId::BlockReward(genesis_id.into()), 0),
        &vrf_sk,
        initial_randomness,
        initial_randomness,
        pool_id,
        1,
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

    let difficulty = Uint256::MAX;
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
        .epoch_length(TEST_EPOCH_LENGTH)
        .sealed_epoch_distance_from_tip(TEST_SEALED_EPOCH_DISTANCE)
        .build();
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();

    let (vrf_sk, stake_pool_data) = create_stake_pool_data(&mut rng);
    let (stake_pool_outpoint, pool_id) =
        add_block_with_stake_pool(&mut rng, &mut tf, stake_pool_data);

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
        // invalid sealed epoch randomness
        let invalid_randomness = H256::random_using(&mut rng);
        let vrf_transcript =
            construct_transcript(valid_epoch, &invalid_randomness, valid_block_timestamp);
        let vrf_data = vrf_sk.produce_vrf_data(vrf_transcript.into());
        let pos_data = PoSData::new(
            vec![stake_pool_outpoint.clone().into()],
            vec![InputWitness::NoSignature(None)],
            pool_id,
            vrf_data,
            valid_vrf_data.clone(),
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
        // invalid prev block randomness
        let invalid_randomness = H256::random_using(&mut rng);
        let vrf_transcript =
            construct_transcript(valid_epoch, &invalid_randomness, valid_block_timestamp);
        let vrf_data = vrf_sk.produce_vrf_data(vrf_transcript.into());
        let pos_data = PoSData::new(
            vec![stake_pool_outpoint.clone().into()],
            vec![InputWitness::NoSignature(None)],
            pool_id,
            valid_vrf_data.clone(),
            vrf_data,
            Compact::from(difficulty),
        );

        let res = tf
            .make_block_builder()
            .with_consensus_data(ConsensusData::PoS(pos_data))
            .build_and_process()
            .unwrap_err();

        let expected_error =
            ChainstateError::ProcessBlockError(BlockError::ConsensusExtraDataError(
                consensus::ExtraConsensusDataError::PoSRandomnessCalculationFailed(
                    PoSRandomnessError::VRFDataVerificationFailed(
                        ProofOfStakeVRFError::VRFDataVerificationFailed(
                            VRFError::VerificationError,
                        ),
                    ),
                ),
            ));
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
            vrf_data.clone(), // FIXME:: should be vrf_data_from_sealed_epoch
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
            vrf_data.clone(), //FIXME
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
            vrf_data.clone(), // FIXME:: should be vrf_data_from_sealed_epoch
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
            valid_vrf_data.clone(), //FIXME:: fix
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
        .epoch_length(TEST_EPOCH_LENGTH)
        .sealed_epoch_distance_from_tip(TEST_SEALED_EPOCH_DISTANCE)
        .build();
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();

    let (vrf_sk, stake_pool_data) = create_stake_pool_data(&mut rng);
    let (stake_pool_outpoint, expected_pool_id) =
        add_block_with_stake_pool(&mut rng, &mut tf, stake_pool_data);

    let random_pool_id: PoolId = H256::random_using(&mut rng).into();
    let initial_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let pos_data = create_pos_data(
        &mut tf,
        stake_pool_outpoint.clone(),
        &vrf_sk,
        initial_randomness,
        initial_randomness,
        random_pool_id,
        1,
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
    let pos_data = create_pos_data(
        &mut tf,
        stake_pool_outpoint,
        &vrf_sk,
        initial_randomness,
        initial_randomness,
        expected_pool_id,
        1,
    );

    tf.make_block_builder()
        .with_consensus_data(ConsensusData::PoS(pos_data))
        .build_and_process()
        .unwrap()
        .unwrap();
}

// Create a chain:
//
// genesis <- block_1(StakePool) <- block_2(StakedOutput) <- block_3(StakedOutput).
//
// PoS consensus activates on height 2.
// block_1 has valid StakePool output.
// block_2 has kernel input from block_1 and StakedOutput as an output.
// block_3 has kernel input from block_2 and StakedOutput as an output.
// Check that the chain is valid.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn spend_staked_output_same_epoch(#[case] seed: Seed) {
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
        .epoch_length(TEST_EPOCH_LENGTH)
        .sealed_epoch_distance_from_tip(TEST_SEALED_EPOCH_DISTANCE)
        .build();
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();

    // create initial chain: genesis <- block_1
    let (vrf_sk, stake_pool_data) = create_stake_pool_data(&mut rng);
    let (stake_pool_outpoint, pool_id) =
        add_block_with_stake_pool(&mut rng, &mut tf, stake_pool_data.clone());

    // prepare and process block_2 with StakePool -> StakedOutput kernel
    let initial_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let pos_data = create_pos_data(
        &mut tf,
        stake_pool_outpoint,
        &vrf_sk,
        initial_randomness,
        initial_randomness,
        pool_id,
        1,
    );
    let consensus_data = ConsensusData::PoS(pos_data);
    let reward_maturity: i64 = consensus_data
        .reward_maturity_distance(&tf.chainstate.get_chain_config())
        .into();
    let reward_output = TxOutput::new(
        OutputValue::Coin(Amount::from_atoms(1)),
        OutputPurpose::StakedOutput(
            Box::new(stake_pool_data.clone()),
            OutputTimeLock::ForBlockCount(reward_maturity as u64),
        ),
    );
    tf.make_block_builder()
        .with_consensus_data(consensus_data)
        .with_reward(vec![reward_output])
        .build_and_process()
        .unwrap()
        .unwrap();

    // prepare and process block_3 with StakedOutput -> StakedOutput kernel
    let block_2_reward_outpoint = OutPoint::new(
        OutPointSourceId::BlockReward(tf.chainstate.get_best_block_id().unwrap()),
        0,
    );
    let prev_block_randomness = get_best_block_randomness(&tf);
    let sealed_epoch_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let pos_data = create_pos_data(
        &mut tf,
        block_2_reward_outpoint,
        &vrf_sk,
        sealed_epoch_randomness,
        prev_block_randomness.value(),
        pool_id,
        1,
    );
    let consensus_data = ConsensusData::PoS(pos_data);
    let reward_output = TxOutput::new(
        OutputValue::Coin(Amount::from_atoms(1)),
        OutputPurpose::StakedOutput(
            Box::new(stake_pool_data),
            OutputTimeLock::ForBlockCount(reward_maturity as u64),
        ),
    );
    tf.make_block_builder()
        .with_consensus_data(consensus_data)
        .with_reward(vec![reward_output])
        .build_and_process()
        .unwrap()
        .unwrap();
}
