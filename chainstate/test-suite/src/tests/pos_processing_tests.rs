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

use super::helpers::pos::{
    calculate_new_target, create_stake_pool_data_with_all_reward_to_owner, pos_mine,
};

use chainstate::{
    chainstate_interface::ChainstateInterface, BlockError, ChainstateError, CheckBlockError,
    ConnectTransactionError, SpendStakeError,
};
use chainstate_storage::{BlockchainStorageRead, SealedStorageTag, TipStorageTag, Transactional};
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
        create_unittest_pos_config,
        stakelock::StakePoolData,
        timelock::OutputTimeLock,
        tokens::OutputValue,
        ConsensusUpgrade, NetUpgrades, OutPoint, OutPointSourceId, PoSChainConfig, PoolId, TxInput,
        TxOutput, UpgradeVersion,
    },
    primitives::{Amount, BlockHeight, Idable, H256},
    Uint256,
};
use consensus::{ConsensusPoSError, ConsensusVerificationError};
use crypto::{random::CryptoRng, vrf::VRFPublicKey};
use crypto::{
    random::Rng,
    vrf::{VRFError, VRFKeyKind, VRFPrivateKey},
};
use pos_accounting::PoSAccountingStorageRead;
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

// It's important to have short epoch length, so that genesis and the first block can seal
// an epoch with pool, which is required for PoS validation to work.
const TEST_EPOCH_LENGTH: NonZeroU64 = match NonZeroU64::new(2) {
    Some(v) => v,
    None => panic!("epoch length cannot be 0"),
};
const TEST_SEALED_EPOCH_DISTANCE: usize = 0;

const MIN_DIFFICULTY: Uint256 = Uint256::MAX;

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
        .add_output(TxOutput::CreateStakePool(Box::new(stake_pool_data)))
        .build();
    let tx_id = tx.transaction().get_id();
    let pool_id = pos_accounting::make_pool_id(&OutPoint::new(
        OutPointSourceId::BlockReward(genesis_id.into()),
        0,
    ));

    tf.make_block_builder().add_transaction(tx).build_and_process().unwrap();

    (
        OutPoint::new(OutPointSourceId::Transaction(tx_id), 0),
        pool_id,
    )
}

fn add_block_with_2_stake_pools(
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
    stake_pool_data1: StakePoolData,
    stake_pool_data2: StakePoolData,
) -> (OutPoint, PoolId, OutPoint, PoolId) {
    let outpoint_genesis = OutPoint::new(
        OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
        0,
    );
    let tx1 = TransactionBuilder::new()
        .add_input(TxInput::from(outpoint_genesis.clone()), empty_witness(rng))
        .add_output(TxOutput::CreateStakePool(Box::new(stake_pool_data1)))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(1)),
            anyonecanspend_address(),
        ))
        .build();
    let stake_outpoint1 =
        OutPoint::new(OutPointSourceId::Transaction(tx1.transaction().get_id()), 0);
    let transfer_outpoint1 =
        OutPoint::new(OutPointSourceId::Transaction(tx1.transaction().get_id()), 1);

    let tx2 = TransactionBuilder::new()
        .add_input(
            TxInput::from(transfer_outpoint1.clone()),
            empty_witness(rng),
        )
        .add_output(TxOutput::CreateStakePool(Box::new(stake_pool_data2)))
        .build();
    let outpoint2 = OutPoint::new(OutPointSourceId::Transaction(tx2.transaction().get_id()), 0);

    tf.make_block_builder()
        .with_transactions(vec![tx1, tx2])
        .build_and_process()
        .unwrap();

    let pool_id1 = pos_accounting::make_pool_id(&outpoint_genesis);
    let pool_id2 = pos_accounting::make_pool_id(&transfer_outpoint1);

    (stake_outpoint1, pool_id1, outpoint2, pool_id2)
}

// Create a chain genesis <- block_1
// block_1 has tx with StakePool output
fn setup_test_chain_with_staked_pool(
    rng: &mut (impl Rng + CryptoRng),
    vrf_pk: VRFPublicKey,
) -> (TestFramework, OutPoint, PoolId) {
    let upgrades = vec![
        (
            BlockHeight::new(0),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
        ),
        (
            BlockHeight::new(2),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoS {
                initial_difficulty: MIN_DIFFICULTY.into(),
                config: create_unittest_pos_config(),
            }),
        ),
    ];
    let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
    let chain_config = ConfigBuilder::test_chain()
        .net_upgrades(net_upgrades)
        .epoch_length(TEST_EPOCH_LENGTH)
        .sealed_epoch_distance_from_tip(TEST_SEALED_EPOCH_DISTANCE)
        .build();

    let mut tf = TestFramework::builder(rng).with_chain_config(chain_config).build();

    let stake_pool_data =
        create_stake_pool_data_with_all_reward_to_owner(rng, Amount::from_atoms(1), vrf_pk);
    let (stake_pool_outpoint, pool_id) = add_block_with_stake_pool(rng, &mut tf, stake_pool_data);

    (tf, stake_pool_outpoint, pool_id)
}

// Create a chain genesis <- block_1
// block_1 has txs with 2 StakePool output
fn setup_test_chain_with_2_staked_pools(
    rng: &mut (impl Rng + CryptoRng),
    vrf_pk_1: VRFPublicKey,
    vrf_pk_2: VRFPublicKey,
) -> (TestFramework, OutPoint, PoolId, OutPoint, PoolId) {
    let upgrades = vec![
        (
            BlockHeight::new(0),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
        ),
        (
            BlockHeight::new(2),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoS {
                initial_difficulty: MIN_DIFFICULTY.into(),
                config: create_unittest_pos_config(),
            }),
        ),
    ];

    setup_test_chain_with_2_staked_pools_with_net_upgrades(rng, vrf_pk_1, vrf_pk_2, upgrades)
}

fn setup_test_chain_with_2_staked_pools_with_net_upgrades(
    rng: &mut (impl Rng + CryptoRng),
    vrf_pk_1: VRFPublicKey,
    vrf_pk_2: VRFPublicKey,
    upgrades: Vec<(BlockHeight, UpgradeVersion)>,
) -> (TestFramework, OutPoint, PoolId, OutPoint, PoolId) {
    let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
    let chain_config = ConfigBuilder::test_chain()
        .net_upgrades(net_upgrades)
        .epoch_length(TEST_EPOCH_LENGTH)
        .sealed_epoch_distance_from_tip(TEST_SEALED_EPOCH_DISTANCE)
        .build();

    let mut tf = TestFramework::builder(rng).with_chain_config(chain_config).build();

    let stake_pool_data1 =
        create_stake_pool_data_with_all_reward_to_owner(rng, Amount::from_atoms(1), vrf_pk_1);
    let stake_pool_data2 =
        create_stake_pool_data_with_all_reward_to_owner(rng, Amount::from_atoms(1), vrf_pk_2);
    let (stake_pool_outpoint1, pool_id1, stake_pool_outpoint2, pool_id2) =
        add_block_with_2_stake_pools(rng, &mut tf, stake_pool_data1, stake_pool_data2);

    (
        tf,
        stake_pool_outpoint1,
        pool_id1,
        stake_pool_outpoint2,
        pool_id2,
    )
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
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (mut tf, stake_pool_outpoint, pool_id) =
        setup_test_chain_with_staked_pool(&mut rng, vrf_pk);

    let initial_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let sealed_pool_balance =
        PoSAccountingStorageRead::<SealedStorageTag>::get_pool_balance(&tf.storage, pool_id)
            .unwrap()
            .unwrap();
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&mut tf, new_block_height).unwrap();
    let (pos_data, block_timestamp) = pos_mine(
        BlockTimestamp::from_duration_since_epoch(tf.current_time()),
        stake_pool_outpoint,
        &vrf_sk,
        PoSRandomness::new(initial_randomness),
        pool_id,
        sealed_pool_balance,
        1,
        current_difficulty,
    )
    .expect("should be able to mine");
    let consensus_data = ConsensusData::PoS(Box::new(pos_data));

    // skip block reward output
    let res = tf
        .make_block_builder()
        .with_consensus_data(consensus_data.clone())
        .with_timestamp(block_timestamp)
        .build_and_process()
        .unwrap_err();
    assert_eq!(
        res,
        ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
            ConnectTransactionError::SpendStakeError(SpendStakeError::NoBlockRewardOutputs)
        ))
    );

    // valid case
    let subsidy = tf.chainstate.get_chain_config().block_subsidy_at_height(&BlockHeight::from(2));
    let initially_staked = Amount::from_atoms(1);
    let total_reward = (subsidy + initially_staked).unwrap();

    let reward_output = TxOutput::ProduceBlockFromStake(anyonecanspend_address(), pool_id);
    tf.make_block_builder()
        .with_consensus_data(consensus_data)
        .with_timestamp(block_timestamp)
        .with_reward(vec![reward_output])
        .build_and_process()
        .unwrap();

    let res_pool_balance =
        PoSAccountingStorageRead::<TipStorageTag>::get_pool_balance(&tf.storage, pool_id)
            .unwrap()
            .unwrap();
    assert_eq!(total_reward, res_pool_balance);
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
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoS {
                initial_difficulty: MIN_DIFFICULTY.into(),
                config: create_unittest_pos_config(),
            }),
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

    let invalid_kernel_input = OutPoint::new(OutPointSourceId::BlockReward(genesis_id.into()), 0);
    let initial_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&mut tf, new_block_height).unwrap();
    let (pos_data, block_timestamp) = pos_mine(
        BlockTimestamp::from_duration_since_epoch(tf.current_time()),
        invalid_kernel_input,
        &vrf_sk,
        PoSRandomness::new(initial_randomness),
        pool_id,
        Amount::from_atoms(1),
        1,
        current_difficulty,
    )
    .expect("should be able to mine");

    let res = tf
        .make_block_builder()
        .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
        .with_timestamp(block_timestamp)
        .build_and_process()
        .unwrap_err();

    assert!(matches!(
        res,
        ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
            CheckBlockError::ConsensusVerificationFailed(ConsensusVerificationError::PoSError(
                ConsensusPoSError::RandomnessError(
                    PoSRandomnessError::InvalidOutputTypeInStakeKernel(_)
                )
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
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (mut tf, stake_pool_outpoint, pool_id) =
        setup_test_chain_with_staked_pool(&mut rng, vrf_pk);

    let expected_error = ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
        CheckBlockError::ConsensusVerificationFailed(ConsensusVerificationError::PoSError(
            ConsensusPoSError::RandomnessError(PoSRandomnessError::VRFDataVerificationFailed(
                ProofOfStakeVRFError::VRFDataVerificationFailed(VRFError::VerificationError),
            )),
        )),
    ));

    let valid_prev_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let valid_block_timestamp = BlockTimestamp::from_duration_since_epoch(tf.current_time());
    let valid_epoch: EpochIndex = 1;
    let valid_vrf_transcript =
        construct_transcript(valid_epoch, &valid_prev_randomness, valid_block_timestamp);

    let sealed_pool_balance =
        PoSAccountingStorageRead::<SealedStorageTag>::get_pool_balance(&tf.storage, pool_id)
            .unwrap()
            .unwrap();
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&mut tf, new_block_height).unwrap();
    let (valid_pos_data, valid_block_timestamp) = pos_mine(
        BlockTimestamp::from_duration_since_epoch(tf.current_time()),
        stake_pool_outpoint,
        &vrf_sk,
        PoSRandomness::new(valid_prev_randomness),
        pool_id,
        sealed_pool_balance,
        valid_epoch,
        current_difficulty,
    )
    .expect("should be able to mine");

    {
        // invalid sealed epoch randomness
        let invalid_randomness = H256::random_using(&mut rng);
        let vrf_transcript =
            construct_transcript(valid_epoch, &invalid_randomness, valid_block_timestamp);
        let vrf_data = vrf_sk.produce_vrf_data(vrf_transcript.into());
        let pos_data = PoSData::new(
            valid_pos_data.kernel_inputs().to_owned(),
            valid_pos_data.kernel_witness().to_owned(),
            pool_id,
            vrf_data,
            valid_pos_data.compact_target(),
        );

        let res = tf
            .make_block_builder()
            .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
            .build_and_process()
            .unwrap_err();

        assert_eq!(res, expected_error);
    }

    {
        // invalid timestamp
        let block_timestamp = valid_block_timestamp.add_int_seconds(1).unwrap();
        let vrf_transcript =
            construct_transcript(valid_epoch, &valid_prev_randomness, block_timestamp);
        let vrf_data = vrf_sk.produce_vrf_data(vrf_transcript.into());
        let pos_data = PoSData::new(
            valid_pos_data.kernel_inputs().to_owned(),
            valid_pos_data.kernel_witness().to_owned(),
            pool_id,
            vrf_data,
            valid_pos_data.compact_target(),
        );

        let res = tf
            .make_block_builder()
            .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
            .build_and_process()
            .unwrap_err();

        assert_eq!(res, expected_error);
    }

    {
        // invalid epoch
        let vrf_transcript = construct_transcript(
            valid_epoch + 1,
            &valid_prev_randomness,
            valid_block_timestamp,
        );
        let vrf_data = vrf_sk.produce_vrf_data(vrf_transcript.into());
        let pos_data = PoSData::new(
            valid_pos_data.kernel_inputs().to_owned(),
            valid_pos_data.kernel_witness().to_owned(),
            pool_id,
            vrf_data,
            valid_pos_data.compact_target(),
        );

        let res = tf
            .make_block_builder()
            .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
            .build_and_process()
            .unwrap_err();

        assert_eq!(res, expected_error);
    }

    {
        // invalid vrf private key
        let (vrf_sk_2, _) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let vrf_data = vrf_sk_2.produce_vrf_data(valid_vrf_transcript.into());
        let pos_data = PoSData::new(
            valid_pos_data.kernel_inputs().to_owned(),
            valid_pos_data.kernel_witness().to_owned(),
            pool_id,
            vrf_data,
            valid_pos_data.compact_target(),
        );

        let res = tf
            .make_block_builder()
            .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
            .build_and_process()
            .unwrap_err();

        assert_eq!(res, expected_error);
    }

    {
        // valid case
        let consensus_data = ConsensusData::PoS(Box::new(valid_pos_data));
        let reward_output = TxOutput::ProduceBlockFromStake(anyonecanspend_address(), pool_id);
        tf.make_block_builder()
            .with_consensus_data(consensus_data)
            .with_reward(vec![reward_output])
            .with_timestamp(valid_block_timestamp)
            .build_and_process()
            .unwrap();
    }
}

// Create a chain genesis <- block_1, where block_1 has valid StakePool output.
// PoS consensus activates on height 2.
// Try to crete block_2 with PoS data that has refer to invalid pool id.
// Check that processing of the block fails.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn pos_invalid_pool_id(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (mut tf, stake_pool_outpoint, pool_id) =
        setup_test_chain_with_staked_pool(&mut rng, vrf_pk);

    let initial_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let sealed_pool_balance =
        PoSAccountingStorageRead::<SealedStorageTag>::get_pool_balance(&tf.storage, pool_id)
            .unwrap()
            .unwrap();
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&mut tf, new_block_height).unwrap();
    let (valid_pos_data, block_timestamp) = pos_mine(
        BlockTimestamp::from_duration_since_epoch(tf.current_time()),
        stake_pool_outpoint,
        &vrf_sk,
        PoSRandomness::new(initial_randomness),
        pool_id,
        sealed_pool_balance,
        1,
        current_difficulty,
    )
    .expect("should be able to mine");

    let random_pool_id: PoolId = H256::random_using(&mut rng).into();
    let invalid_pos_data = PoSData::new(
        valid_pos_data.kernel_inputs().to_owned(),
        valid_pos_data.kernel_witness().to_owned(),
        random_pool_id,
        valid_pos_data.vrf_data().clone(),
        valid_pos_data.compact_target(),
    );

    let res = tf
        .make_block_builder()
        .with_consensus_data(ConsensusData::PoS(Box::new(invalid_pos_data)))
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
    let reward_output = TxOutput::ProduceBlockFromStake(anyonecanspend_address(), pool_id);
    tf.make_block_builder()
        .with_consensus_data(ConsensusData::PoS(Box::new(valid_pos_data)))
        .with_reward(vec![reward_output])
        .with_timestamp(block_timestamp)
        .build_and_process()
        .unwrap();
}

// Create a chain genesis <- block_1, where block_1 has valid StakePool output.
// PoS consensus activates on height 2 and an epoch is sealed at height 2.
// Try to crete block_2 with PoS data that has refer to staked pool.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn not_sealed_pool_cannot_be_used(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

    let upgrades = vec![
        (
            BlockHeight::new(0),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
        ),
        (
            BlockHeight::new(2),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoS {
                initial_difficulty: MIN_DIFFICULTY.into(),
                config: create_unittest_pos_config(),
            }),
        ),
    ];
    let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
    let chain_config = ConfigBuilder::test_chain()
        .net_upgrades(net_upgrades)
        .epoch_length(NonZeroU64::new(3).unwrap()) // stake pool won't be sealed at height 1
        .sealed_epoch_distance_from_tip(TEST_SEALED_EPOCH_DISTANCE)
        .build();
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();

    let stake_pool_data =
        create_stake_pool_data_with_all_reward_to_owner(&mut rng, Amount::from_atoms(1), vrf_pk);
    let (stake_pool_outpoint, pool_id) =
        add_block_with_stake_pool(&mut rng, &mut tf, stake_pool_data);

    let initial_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&mut tf, new_block_height).unwrap();
    let (pos_data, block_timestamp) = pos_mine(
        BlockTimestamp::from_duration_since_epoch(tf.current_time()),
        stake_pool_outpoint,
        &vrf_sk,
        PoSRandomness::new(initial_randomness),
        pool_id,
        Amount::from_atoms(1),
        1,
        current_difficulty,
    )
    .expect("should be able to mine");

    let res = tf
        .make_block_builder()
        .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
        .with_timestamp(block_timestamp)
        .build_and_process()
        .unwrap_err();

    assert_eq!(
        res,
        ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
            CheckBlockError::ConsensusVerificationFailed(ConsensusVerificationError::PoSError(
                ConsensusPoSError::PoolBalanceNotFound(pool_id)
            ))
        ))
    );
}

// Create a chain:
//
// genesis <- block_1(StakePool) <- block_2(ProduceBlockFromStake) <- block_3(ProduceBlockFromStake) <- block_4(ProduceBlockFromStake).
//
// PoS consensus activates for block_2 and on. Epoch length is 2.
// block_1 has valid StakePool output.
// block_2 has kernel input from block_1 and ProduceBlockFromStake as an output. Initial randomness is used.
// block_3 has kernel input from block_2 and ProduceBlockFromStake as an output. Randomness of prev block
// and initial randomness are used.
// block_4 has kernel input from block_3 and ProduceBlockFromStake as an output. Randomness of prev block
// and randomness of sealed epoch are used.
// Check that the chain is valid.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn spend_stake_pool_in_block_reward(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (mut tf, stake_pool_outpoint, pool_id) =
        setup_test_chain_with_staked_pool(&mut rng, vrf_pk);
    let target_block_time = create_unittest_pos_config().target_block_time().get();

    // prepare and process block_2 with StakePool -> ProduceBlockFromStake kernel
    let initial_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&mut tf, new_block_height).unwrap();
    let (pos_data, block_timestamp) = pos_mine(
        BlockTimestamp::from_duration_since_epoch(tf.current_time()),
        stake_pool_outpoint,
        &vrf_sk,
        // no epoch is sealed yet so use initial randomness
        PoSRandomness::new(initial_randomness),
        pool_id,
        Amount::from_atoms(1),
        1,
        current_difficulty,
    )
    .expect("should be able to mine");
    let reward_output = TxOutput::ProduceBlockFromStake(anyonecanspend_address(), pool_id);
    tf.make_block_builder()
        .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
        .with_reward(vec![reward_output])
        .with_timestamp(block_timestamp)
        .build_and_process()
        .unwrap();
    tf.progress_time_seconds_since_epoch(target_block_time);

    // prepare and process block_3 with ProduceBlockFromStake -> ProduceBlockFromStake kernel
    let block_2_reward_outpoint = OutPoint::new(
        OutPointSourceId::BlockReward(tf.chainstate.get_best_block_id().unwrap()),
        0,
    );
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&mut tf, new_block_height).unwrap();
    let (pos_data, block_timestamp) = pos_mine(
        BlockTimestamp::from_duration_since_epoch(tf.current_time()),
        block_2_reward_outpoint,
        &vrf_sk,
        // no epoch is sealed yet so use initial randomness
        PoSRandomness::new(initial_randomness),
        pool_id,
        Amount::from_atoms(1),
        1,
        current_difficulty,
    )
    .expect("should be able to mine");
    let reward_output = TxOutput::ProduceBlockFromStake(anyonecanspend_address(), pool_id);
    tf.make_block_builder()
        .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
        .with_reward(vec![reward_output])
        .with_timestamp(block_timestamp)
        .build_and_process()
        .unwrap();
    tf.progress_time_seconds_since_epoch(target_block_time);

    // prepare and process block_4 with ProduceBlockFromStake -> ProduceBlockFromStake kernel
    let block_3_reward_outpoint = OutPoint::new(
        OutPointSourceId::BlockReward(tf.chainstate.get_best_block_id().unwrap()),
        0,
    );

    // sealed epoch randomness can be used
    let sealed_epoch_randomness =
        tf.storage.transaction_ro().unwrap().get_epoch_data(1).unwrap().unwrap();
    let sealed_pool_balance =
        PoSAccountingStorageRead::<SealedStorageTag>::get_pool_balance(&tf.storage, pool_id)
            .unwrap()
            .unwrap();
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&mut tf, new_block_height).unwrap();
    let (pos_data, block_timestamp) = pos_mine(
        BlockTimestamp::from_duration_since_epoch(tf.current_time()),
        block_3_reward_outpoint,
        &vrf_sk,
        *sealed_epoch_randomness.randomness(),
        pool_id,
        sealed_pool_balance,
        2,
        current_difficulty,
    )
    .expect("should be able to mine");
    let reward_output = TxOutput::ProduceBlockFromStake(anyonecanspend_address(), pool_id);
    tf.make_block_builder()
        .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
        .with_reward(vec![reward_output])
        .with_timestamp(block_timestamp)
        .build_and_process()
        .unwrap();

    let res_pool_balance =
        PoSAccountingStorageRead::<TipStorageTag>::get_pool_balance(&tf.storage, pool_id)
            .unwrap()
            .unwrap();
    let total_subsidy =
        tf.chainstate.get_chain_config().block_subsidy_at_height(&BlockHeight::from(1)) * 3;
    let initially_staked = Amount::from_atoms(1);
    assert_eq!(
        (total_subsidy.unwrap() + initially_staked).unwrap(),
        res_pool_balance
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn mismatched_pools_in_kernel_and_reward(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk_1, vrf_pk_1) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (_, vrf_pk_2) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

    // create initial chain: genesis <- block_1
    // block1 creates 2 separate pools
    let (mut tf, stake_pool_outpoint1, pool_id1, _, pool_id2) =
        setup_test_chain_with_2_staked_pools(&mut rng, vrf_pk_1, vrf_pk_2);

    // prepare and process block_2 with StakePool -> ProduceBlockFromStake kernel
    // kernel refers to pool1, while block reward refers to pool2
    let initial_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let sealed_pool_balance =
        PoSAccountingStorageRead::<SealedStorageTag>::get_pool_balance(&tf.storage, pool_id1)
            .unwrap()
            .unwrap();
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&mut tf, new_block_height).unwrap();
    let (pos_data, block_timestamp) = pos_mine(
        BlockTimestamp::from_duration_since_epoch(tf.current_time()),
        stake_pool_outpoint1,
        &vrf_sk_1,
        PoSRandomness::new(initial_randomness),
        pool_id1,
        sealed_pool_balance,
        1,
        current_difficulty,
    )
    .expect("should be able to mine");
    let reward_output = TxOutput::ProduceBlockFromStake(anyonecanspend_address(), pool_id2);
    let res = tf
        .make_block_builder()
        .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
        .with_reward(vec![reward_output])
        .with_timestamp(block_timestamp)
        .build_and_process()
        .unwrap_err();

    assert_eq!(
        res,
        ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
            ConnectTransactionError::SpendStakeError(SpendStakeError::StakePoolDataMismatch)
        ))
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn stake_pool_as_reward_output(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = ConfigBuilder::test_chain()
        .epoch_length(TEST_EPOCH_LENGTH)
        .sealed_epoch_distance_from_tip(TEST_SEALED_EPOCH_DISTANCE)
        .build();
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();

    let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let stake_pool_data =
        create_stake_pool_data_with_all_reward_to_owner(&mut rng, Amount::from_atoms(1), vrf_pk);
    let reward_output = TxOutput::CreateStakePool(Box::new(stake_pool_data));
    let block = tf.make_block_builder().with_reward(vec![reward_output]).build();
    let block_id = block.get_id();
    assert_eq!(
        tf.process_block(block, chainstate::BlockSource::Local).unwrap_err(),
        ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
            CheckBlockError::InvalidBlockRewardOutputType(block_id)
        ))
    );
}

// Produce `genesis -> a -> b` chain, then a parallel `genesis -> a -> c -> d` that should trigger a reorg.
// Block `a` has stake pool output. Also at block 'a' PoS activates.
// Blocks `b`, `c`, `d` have produce block from stake outputs.
// Check that after reorg pool balance doesn't include reward from block `a`
//
// TODO: enable when mintlayer/mintlayer-core/issues/752 is implemented
#[ignore]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_pool_balance_after_reorg(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

    // create initial chain: genesis <- block_a
    let (mut tf, stake_pool_outpoint, pool_id) =
        setup_test_chain_with_staked_pool(&mut rng, vrf_pk);
    let block_a_id = tf.best_block_id();

    // prepare and process block_b with StakePool -> ProduceBlockFromStake kernel
    let initial_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let sealed_pool_balance =
        PoSAccountingStorageRead::<SealedStorageTag>::get_pool_balance(&tf.storage, pool_id)
            .unwrap()
            .unwrap();
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&mut tf, new_block_height).unwrap();
    let (pos_data, block_timestamp) = pos_mine(
        BlockTimestamp::from_duration_since_epoch(tf.current_time()),
        stake_pool_outpoint.clone(),
        &vrf_sk,
        // no epoch is sealed yet so use initial randomness
        PoSRandomness::new(initial_randomness),
        pool_id,
        sealed_pool_balance,
        1,
        current_difficulty,
    )
    .expect("should be able to mine");
    let reward_output = TxOutput::ProduceBlockFromStake(anyonecanspend_address(), pool_id);
    tf.make_block_builder()
        .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
        .with_reward(vec![reward_output])
        .with_timestamp(block_timestamp)
        .build_and_process()
        .unwrap();

    // prepare and process block_c with StakePool -> ProduceBlockFromStake kernel
    let sealed_pool_balance =
        PoSAccountingStorageRead::<SealedStorageTag>::get_pool_balance(&tf.storage, pool_id)
            .unwrap()
            .unwrap();
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&mut tf, new_block_height).unwrap();
    let (pos_data, block_timestamp) = pos_mine(
        block_timestamp,
        stake_pool_outpoint,
        &vrf_sk,
        // no epoch is sealed yet so use initial randomness
        PoSRandomness::new(initial_randomness),
        pool_id,
        sealed_pool_balance,
        1,
        current_difficulty,
    )
    .expect("should be able to mine");
    let reward_output = TxOutput::ProduceBlockFromStake(anyonecanspend_address(), pool_id);
    let block_c_index = tf
        .make_block_builder()
        .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
        .with_reward(vec![reward_output])
        .with_timestamp(block_timestamp)
        .with_parent(block_a_id)
        .build_and_process()
        .unwrap()
        .unwrap();

    // prepare and process block_d with ProduceBlockFromStake -> ProduceBlockFromStake kernel
    let block_3_reward_outpoint = OutPoint::new(
        OutPointSourceId::BlockReward((*block_c_index.block_id()).into()),
        0,
    );

    // both sealed epoch and pre block randomness can be used
    let sealed_epoch_randomness =
        tf.storage.transaction_ro().unwrap().get_epoch_data(1).unwrap().unwrap();
    let sealed_pool_balance =
        PoSAccountingStorageRead::<SealedStorageTag>::get_pool_balance(&tf.storage, pool_id)
            .unwrap()
            .unwrap();
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&mut tf, new_block_height).unwrap();
    let (pos_data, block_timestamp) = pos_mine(
        block_timestamp,
        block_3_reward_outpoint,
        &vrf_sk,
        *sealed_epoch_randomness.randomness(),
        pool_id,
        sealed_pool_balance,
        2,
        current_difficulty,
    )
    .expect("should be able to mine");
    let reward_output = TxOutput::ProduceBlockFromStake(anyonecanspend_address(), pool_id);
    tf.make_block_builder()
        .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
        .with_reward(vec![reward_output])
        .with_timestamp(block_timestamp)
        .with_parent((*block_c_index.block_id()).into())
        .build_and_process()
        .unwrap();

    let res_pool_balance =
        PoSAccountingStorageRead::<TipStorageTag>::get_pool_balance(&tf.storage, pool_id)
            .unwrap()
            .unwrap();
    let total_subsidy =
        tf.chainstate.get_chain_config().block_subsidy_at_height(&BlockHeight::from(1)) * 3;
    let initially_staked = Amount::from_atoms(1);
    assert_eq!(
        (total_subsidy.unwrap() + initially_staked).unwrap(),
        res_pool_balance
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn decommission_from_produce_block(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk_1, vrf_pk_1) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (vrf_sk_2, vrf_pk_2) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let target_block_time = create_unittest_pos_config().target_block_time().get();

    // create initial chain: genesis <- block_1
    // block1 creates 2 separate pools
    let (mut tf, stake_pool_outpoint1, pool_id1, stake_pool_outpoint2, pool_id2) =
        setup_test_chain_with_2_staked_pools(&mut rng, vrf_pk_1, vrf_pk_2);

    // prepare and process block_2 with StakePool -> ProduceBlockFromStake kernel
    let initial_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&mut tf, new_block_height).unwrap();
    let (pos_data, block_timestamp) = pos_mine(
        BlockTimestamp::from_duration_since_epoch(tf.current_time()),
        stake_pool_outpoint1,
        &vrf_sk_1,
        // no epoch is sealed yet so use initial randomness
        PoSRandomness::new(initial_randomness),
        pool_id1,
        Amount::from_atoms(1),
        1,
        current_difficulty,
    )
    .expect("should be able to mine");

    let subsidy = tf.chainstate.get_chain_config().block_subsidy_at_height(&BlockHeight::from(2));
    let initially_staked = Amount::from_atoms(1);
    let total_reward = (subsidy + initially_staked).unwrap();

    let produce_block_output = TxOutput::ProduceBlockFromStake(anyonecanspend_address(), pool_id1);
    tf.make_block_builder()
        .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
        .with_reward(vec![produce_block_output])
        .with_timestamp(block_timestamp)
        .build_and_process()
        .unwrap();
    tf.progress_time_seconds_since_epoch(target_block_time);

    // prepare and process block_3 with ProduceBlockFromStake -> Decommission
    let block_2_reward_outpoint = OutPoint::new(
        OutPointSourceId::BlockReward(tf.chainstate.get_best_block_id().unwrap()),
        0,
    );
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&mut tf, new_block_height).unwrap();
    let (pos_data, block_timestamp) = pos_mine(
        BlockTimestamp::from_duration_since_epoch(tf.current_time()),
        stake_pool_outpoint2,
        &vrf_sk_2,
        // no epoch is sealed yet so use initial randomness
        PoSRandomness::new(initial_randomness),
        pool_id2,
        Amount::from_atoms(1),
        1,
        current_difficulty,
    )
    .expect("should be able to mine");

    let tx = TransactionBuilder::new()
        .add_input(block_2_reward_outpoint.into(), empty_witness(&mut rng))
        .add_output(TxOutput::DecommissionPool(
            total_reward,
            anyonecanspend_address(),
            pool_id1,
            OutputTimeLock::ForBlockCount(2000),
        ))
        .build();

    let produce_block_output = TxOutput::ProduceBlockFromStake(anyonecanspend_address(), pool_id2);
    tf.make_block_builder()
        .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
        .with_reward(vec![produce_block_output])
        .with_timestamp(block_timestamp)
        .add_transaction(tx)
        .build_and_process()
        .unwrap();
    tf.progress_time_seconds_since_epoch(target_block_time);

    let res_pool_balance =
        PoSAccountingStorageRead::<TipStorageTag>::get_pool_balance(&tf.storage, pool_id1).unwrap();
    assert!(res_pool_balance.is_none());
}

// Produce `genesis -> a` chain. Block `a` has 2 stake pool outputs (one to produce block and one to decommission)
// Also at block 'a' PoS activates. At height 2 and 3 chain changes configuration of decommission maturity.
// The test creates block 'b' from block 'a'. And the block 'c' from block 'a'.
// The goal of the test is to check that block 'c' follows the maturity rules from height 2 and not 3.
//
// TODO: enable when mintlayer/mintlayer-core/issues/752 is implemented
#[ignore]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn decommission_from_not_best_block(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk_1, vrf_pk_1) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (_, vrf_pk_2) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let target_block_time = create_unittest_pos_config().target_block_time().get();

    let upgrades = vec![
        (
            BlockHeight::new(0),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
        ),
        (
            BlockHeight::new(2),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoS {
                initial_difficulty: MIN_DIFFICULTY.into(),
                config: PoSChainConfig::new(
                    Uint256::MAX,
                    target_block_time,
                    2000.into(),
                    50.into(),
                    5,
                )
                .unwrap(),
            }),
        ),
        (
            BlockHeight::new(3),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoS {
                initial_difficulty: MIN_DIFFICULTY.into(),
                config: PoSChainConfig::new(
                    Uint256::MAX,
                    target_block_time,
                    2000.into(),
                    100.into(), // decommission maturity increased
                    5,
                )
                .unwrap(),
            }),
        ),
    ];

    // create initial chain: genesis <- block_a
    // block_a creates 2 separate pools
    let (mut tf, stake_pool_outpoint1, pool_id1, stake_pool_outpoint2, pool_id2) =
        setup_test_chain_with_2_staked_pools_with_net_upgrades(
            &mut rng, vrf_pk_1, vrf_pk_2, upgrades,
        );
    let block_a_id = tf.best_block_id();
    let block_a_height = tf.best_block_index().block_height();

    // prepare and process block_a <- block_b with StakePool -> ProduceBlockFromStake kernel
    let initial_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let current_difficulty = calculate_new_target(&mut tf, block_a_height.next_height()).unwrap();
    let (pos_data, block_timestamp) = pos_mine(
        BlockTimestamp::from_duration_since_epoch(tf.current_time()),
        stake_pool_outpoint1,
        &vrf_sk_1,
        // no epoch is sealed yet so use initial randomness
        PoSRandomness::new(initial_randomness),
        pool_id1,
        Amount::from_atoms(1),
        1,
        current_difficulty,
    )
    .expect("should be able to mine");

    // prepare and process block_a <- block_c with StakePool -> Decommission
    let subsidy = tf.chainstate.get_chain_config().block_subsidy_at_height(&BlockHeight::from(2));
    let initially_staked = Amount::from_atoms(1);
    let total_reward = (subsidy + initially_staked).unwrap();

    let produce_block_output = TxOutput::ProduceBlockFromStake(anyonecanspend_address(), pool_id1);
    tf.make_block_builder()
        .with_consensus_data(ConsensusData::PoS(Box::new(pos_data.clone())))
        .with_reward(vec![produce_block_output])
        .with_timestamp(block_timestamp)
        .build_and_process()
        .unwrap();

    let tx = TransactionBuilder::new()
        .add_input(stake_pool_outpoint2.into(), empty_witness(&mut rng))
        .add_output(TxOutput::DecommissionPool(
            total_reward,
            anyonecanspend_address(),
            pool_id2,
            OutputTimeLock::ForBlockCount(50),
        ))
        .build();

    let produce_block_output = TxOutput::ProduceBlockFromStake(anyonecanspend_address(), pool_id1);
    tf.make_block_builder()
        .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
        .with_reward(vec![produce_block_output])
        .with_timestamp(block_timestamp)
        .with_parent(block_a_id)
        .add_transaction(tx)
        .build_and_process()
        .unwrap();
    tf.progress_time_seconds_since_epoch(target_block_time);

    // no reorg happened so decommission has no effect
    let res_pool_balance =
        PoSAccountingStorageRead::<TipStorageTag>::get_pool_balance(&tf.storage, pool_id2)
            .unwrap()
            .unwrap();
    let total_subsidy =
        tf.chainstate.get_chain_config().block_subsidy_at_height(&BlockHeight::from(1)) * 3;
    let initially_staked = Amount::from_atoms(1);
    assert_eq!(
        (total_subsidy.unwrap() + initially_staked).unwrap(),
        res_pool_balance
    );
}
