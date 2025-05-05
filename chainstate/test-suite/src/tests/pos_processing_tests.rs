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

use rstest::rstest;

use chainstate::{
    chainstate_interface::ChainstateInterface, BlockError, BlockSource, ChainstateError,
    CheckBlockError, ConnectTransactionError, SpendStakeError,
};
use chainstate_storage::Transactional;
use chainstate_test_framework::{
    anyonecanspend_address, create_stake_pool_data_with_all_reward_to_staker, empty_witness,
    TestFramework, TransactionBuilder,
};
use chainstate_types::{
    pos_randomness::{PoSRandomness, PoSRandomnessError},
    vrf_tools::{construct_transcript, ProofOfStakeVRFError},
    EpochStorageRead, TipStorageTag,
};
use common::{
    chain::{
        block::{
            consensus_data::PoSData, timestamp::BlockTimestamp, BlockRewardTransactable,
            ConsensusData,
        },
        config::{create_unit_test_config, Builder as ConfigBuilder, ChainType, EpochIndex},
        make_delegation_id,
        output_value::OutputValue,
        signature::{
            inputsig::{standard_signature::StandardInputSignature, InputWitness},
            sighash::sighashtype::SigHashType,
        },
        stakelock::StakePoolData,
        timelock::OutputTimeLock,
        AccountNonce, AccountOutPoint, AccountSpending, ChainConfig, ChainstateUpgradeBuilder,
        ConsensusUpgrade, Destination, GenBlock, NetUpgrades, OutPointSourceId, PoSChainConfig,
        PoSChainConfigBuilder, PoolId, RequiredConsensus, SignedTransaction,
        StakerDestinationUpdateForbidden, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{per_thousand::PerThousand, Amount, BlockCount, BlockHeight, Id, Idable, H256},
    Uint256,
};
use consensus::{BlockSignatureError, ConsensusPoSError, ConsensusVerificationError};
use crypto::{
    key::{KeyKind, PrivateKey, PublicKey},
    vrf::{VRFError, VRFKeyKind, VRFPrivateKey, VRFPublicKey},
};
use pos_accounting::PoSAccountingStorageRead;
use randomness::{CryptoRng, Rng};
use test_utils::{
    assert_matches,
    random::{make_seedable_rng, Seed},
};
use utils::const_nz_u64;

use super::helpers::pos::{calculate_new_target, create_custom_genesis_with_stake_pool};

// It's important to have short epoch length, so that genesis and the first block can seal
// an epoch with pool, which is required for PoS validation to work.
const TEST_EPOCH_LENGTH: NonZeroU64 = const_nz_u64!(2);
const TEST_SEALED_EPOCH_DISTANCE: usize = 0;

const MIN_DIFFICULTY: Uint256 = Uint256::MAX;

fn add_block_with_stake_pool(
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
    stake_pool_data: StakePoolData,
) -> (UtxoOutPoint, PoolId) {
    let genesis_outpoint = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
        0,
    );
    let pool_id = PoolId::from_utxo(&genesis_outpoint);
    let tx = TransactionBuilder::new()
        .add_input(genesis_outpoint.into(), empty_witness(rng))
        .add_output(TxOutput::CreateStakePool(
            pool_id,
            Box::new(stake_pool_data),
        ))
        .build();
    let tx_id = tx.transaction().get_id();

    tf.make_block_builder().add_transaction(tx).build_and_process(rng).unwrap();

    tf.progress_time_seconds_since_epoch(1);

    (
        UtxoOutPoint::new(OutPointSourceId::Transaction(tx_id), 0),
        pool_id,
    )
}

fn add_block_with_2_stake_pools(
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
    stake_pool_data1: StakePoolData,
    stake_pool_data2: StakePoolData,
) -> (UtxoOutPoint, PoolId, UtxoOutPoint, PoolId) {
    let outpoint_genesis = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
        0,
    );
    let pool_id1 = PoolId::from_utxo(&outpoint_genesis);
    let tx1 = TransactionBuilder::new()
        .add_input(outpoint_genesis.into(), empty_witness(rng))
        .add_output(TxOutput::CreateStakePool(
            pool_id1,
            Box::new(stake_pool_data1),
        ))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(tf.chainstate.get_chain_config().min_stake_pool_pledge()),
            anyonecanspend_address(),
        ))
        .build();
    let stake_outpoint1 =
        UtxoOutPoint::new(OutPointSourceId::Transaction(tx1.transaction().get_id()), 0);
    let transfer_outpoint1 =
        UtxoOutPoint::new(OutPointSourceId::Transaction(tx1.transaction().get_id()), 1);

    let pool_id2 = PoolId::from_utxo(&transfer_outpoint1);
    let tx2 = TransactionBuilder::new()
        .add_input(transfer_outpoint1.into(), empty_witness(rng))
        .add_output(TxOutput::CreateStakePool(
            pool_id2,
            Box::new(stake_pool_data2),
        ))
        .build();
    let outpoint2 = UtxoOutPoint::new(OutPointSourceId::Transaction(tx2.transaction().get_id()), 0);

    tf.make_block_builder()
        .with_transactions(vec![tx1, tx2])
        .build_and_process(rng)
        .unwrap();

    tf.progress_time_seconds_since_epoch(1);

    (stake_outpoint1, pool_id1, outpoint2, pool_id2)
}

fn consensus_upgrades_with_pos_at_height(height: BlockHeight) -> NetUpgrades<ConsensusUpgrade> {
    NetUpgrades::initialize(vec![
        (BlockHeight::new(0), ConsensusUpgrade::IgnoreConsensus),
        (
            height,
            ConsensusUpgrade::PoS {
                initial_difficulty: Some(MIN_DIFFICULTY.into()),
                config: PoSChainConfigBuilder::new_for_unit_test().build(),
            },
        ),
    ])
    .unwrap()
}

// Create a chain genesis <- block_1
// block_1 has tx with StakePool output
fn setup_test_chain_with_staked_pool(
    rng: &mut (impl Rng + CryptoRng),
    vrf_pk: VRFPublicKey,
) -> (TestFramework, UtxoOutPoint, PoolId, PrivateKey) {
    let net_upgrades = consensus_upgrades_with_pos_at_height(BlockHeight::new(2));
    let chain_config = ConfigBuilder::test_chain()
        .consensus_upgrades(net_upgrades)
        .epoch_length(TEST_EPOCH_LENGTH)
        .sealed_epoch_distance_from_tip(TEST_SEALED_EPOCH_DISTANCE)
        .build();

    let mut tf = TestFramework::builder(rng).with_chain_config(chain_config).build();

    let (stake_pool_data, staking_sk) = create_stake_pool_data_with_all_reward_to_staker(
        rng,
        tf.chainstate.get_chain_config().min_stake_pool_pledge(),
        vrf_pk,
    );
    let (stake_pool_outpoint, pool_id) = add_block_with_stake_pool(rng, &mut tf, stake_pool_data);

    (tf, stake_pool_outpoint, pool_id, staking_sk)
}

// Create a chain genesis <- block_1
// block_1 has txs with 2 StakePool output
fn setup_test_chain_with_2_staked_pools(
    rng: &mut (impl Rng + CryptoRng),
    vrf_pk_1: VRFPublicKey,
    vrf_pk_2: VRFPublicKey,
) -> (
    TestFramework,
    UtxoOutPoint,
    PoolId,
    PrivateKey,
    UtxoOutPoint,
    PoolId,
    PrivateKey,
) {
    let upgrades = vec![
        (BlockHeight::new(0), ConsensusUpgrade::IgnoreConsensus),
        (
            BlockHeight::new(2),
            ConsensusUpgrade::PoS {
                initial_difficulty: Some(MIN_DIFFICULTY.into()),
                config: PoSChainConfigBuilder::new_for_unit_test().build(),
            },
        ),
    ];

    setup_test_chain_with_2_staked_pools_with_net_upgrades(rng, vrf_pk_1, vrf_pk_2, upgrades)
}

fn setup_test_chain_with_2_staked_pools_with_net_upgrades(
    rng: &mut (impl Rng + CryptoRng),
    vrf_pk_1: VRFPublicKey,
    vrf_pk_2: VRFPublicKey,
    upgrades: Vec<(BlockHeight, ConsensusUpgrade)>,
) -> (
    TestFramework,
    UtxoOutPoint,
    PoolId,
    PrivateKey,
    UtxoOutPoint,
    PoolId,
    PrivateKey,
) {
    let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
    let chain_config = ConfigBuilder::test_chain()
        .consensus_upgrades(net_upgrades)
        .epoch_length(TEST_EPOCH_LENGTH)
        .sealed_epoch_distance_from_tip(TEST_SEALED_EPOCH_DISTANCE)
        .build();

    let mut tf = TestFramework::builder(rng).with_chain_config(chain_config).build();

    let (stake_pool_data1, sk1) = create_stake_pool_data_with_all_reward_to_staker(
        rng,
        tf.chainstate.get_chain_config().min_stake_pool_pledge(),
        vrf_pk_1,
    );
    let (stake_pool_data2, sk2) = create_stake_pool_data_with_all_reward_to_staker(
        rng,
        tf.chainstate.get_chain_config().min_stake_pool_pledge(),
        vrf_pk_2,
    );
    let (stake_pool_outpoint1, pool_id1, stake_pool_outpoint2, pool_id2) =
        add_block_with_2_stake_pools(rng, &mut tf, stake_pool_data1, stake_pool_data2);

    (
        tf,
        stake_pool_outpoint1,
        pool_id1,
        sk1,
        stake_pool_outpoint2,
        pool_id2,
        sk2,
    )
}

fn produce_kernel_signature(
    rng: &mut (impl Rng + CryptoRng),
    tf: &TestFramework,
    staking_sk: &PrivateKey,
    reward_outputs: &[TxOutput],
    staking_destination: Destination,
    kernel_utxo_block_id: Id<GenBlock>,
    kernel_outpoint: UtxoOutPoint,
) -> StandardInputSignature {
    let block_outputs = tf.outputs_from_genblock(kernel_utxo_block_id);
    let utxo = &block_outputs.get(&kernel_outpoint.source_id()).unwrap()
        [kernel_outpoint.output_index() as usize];

    let kernel_inputs = vec![kernel_outpoint.into()];

    let block_reward_tx =
        BlockRewardTransactable::new(Some(kernel_inputs.as_slice()), Some(reward_outputs), None);
    StandardInputSignature::produce_uniparty_signature_for_input(
        staking_sk,
        SigHashType::default(),
        staking_destination,
        &block_reward_tx,
        std::iter::once(Some(utxo)).collect::<Vec<_>>().as_slice(),
        0,
        rng,
    )
    .unwrap()
}

fn get_pos_chain_config(chain_config: &ChainConfig, block_height: BlockHeight) -> PoSChainConfig {
    match chain_config.consensus_upgrades().consensus_status(block_height) {
        RequiredConsensus::PoS(status) => status.get_chain_config().clone(),
        RequiredConsensus::PoW(_) | RequiredConsensus::IgnoreConsensus => {
            panic!("Invalid consensus")
        }
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn pos_enforce_strict_time_ordering(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (mut tf, _stake_pool_outpoint, pool_id, _staking_sk) =
        setup_test_chain_with_staked_pool(&mut rng, vrf_pk);

    let initial_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&tf, new_block_height).unwrap();
    let block_timestamp = tf.chainstate.get_chain_config().genesis_block().timestamp();

    // skip kernel inputs
    {
        // We don't need to "mine" (search for timestamp that leads to hash <= target) because timestamp is checked first
        let transcript = construct_transcript(1, &initial_randomness, block_timestamp);
        let vrf_data = vrf_sk.produce_vrf_data(transcript);
        let pos_data = PoSData::new(vec![], vec![], pool_id, vrf_data, current_difficulty);

        let block = tf
            .make_block_builder()
            .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
            .with_timestamp(block_timestamp)
            .build(&mut rng);
        let block_id = block.get_id();

        let res = tf.process_block(block, BlockSource::Local).unwrap_err();

        assert_eq!(
            res,
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::ConsensusVerificationFailed(ConsensusVerificationError::PoSError(
                    ConsensusPoSError::PoSBlockTimeStrictOrderInvalid(block_id)
                ))
            ))
        );
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
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (mut tf, stake_pool_outpoint, pool_id, staking_sk) =
        setup_test_chain_with_staked_pool(&mut rng, vrf_pk);

    let staking_destination = Destination::PublicKey(PublicKey::from_private_key(&staking_sk));
    let reward_outputs =
        vec![TxOutput::ProduceBlockFromStake(staking_destination.clone(), pool_id)];

    let kernel_sig = produce_kernel_signature(
        &mut rng,
        &tf,
        &staking_sk,
        reward_outputs.as_slice(),
        staking_destination,
        tf.best_block_id(),
        stake_pool_outpoint.clone(),
    );

    let initial_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&tf, new_block_height).unwrap();
    let final_supply = tf.chainstate.get_chain_config().final_supply().unwrap();

    let (pos_data, block_timestamp) = chainstate_test_framework::pos_mine(
        &mut rng,
        &tf.storage.transaction_ro().unwrap(),
        &get_pos_chain_config(tf.chainstate.get_chain_config(), new_block_height),
        BlockTimestamp::from_time(tf.current_time()),
        stake_pool_outpoint,
        InputWitness::Standard(kernel_sig),
        &vrf_sk,
        PoSRandomness::new(initial_randomness),
        pool_id,
        final_supply,
        1,
        current_difficulty,
    )
    .expect("should be able to mine");
    let consensus_data = ConsensusData::PoS(Box::new(pos_data));

    // skip kernel inputs
    {
        let transcript = construct_transcript(1, &initial_randomness, block_timestamp);
        let vrf_data = vrf_sk.produce_vrf_data(transcript);
        let pos_data = PoSData::new(vec![], vec![], pool_id, vrf_data, current_difficulty);

        let res = tf
            .make_block_builder()
            .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
            .with_timestamp(block_timestamp)
            .build_and_process(&mut rng)
            .unwrap_err();
        assert_eq!(
            res,
            ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
                CheckBlockError::ConsensusVerificationFailed(ConsensusVerificationError::PoSError(
                    ConsensusPoSError::NoKernel
                ))
            ))
        );
    }

    // skip block reward output
    {
        let res = tf
            .make_block_builder()
            .with_consensus_data(consensus_data.clone())
            .with_block_signing_key(staking_sk.clone())
            .with_timestamp(block_timestamp)
            .build_and_process(&mut rng)
            .unwrap_err();
        assert_eq!(
            res,
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::SpendStakeError(SpendStakeError::NoBlockRewardOutputs)
            ))
        );
    }

    // valid case
    let subsidy = tf.chainstate.get_chain_config().block_subsidy_at_height(&BlockHeight::from(2));
    let initially_staked = tf.chainstate.get_chain_config().min_stake_pool_pledge();
    let total_reward = (subsidy + initially_staked).unwrap();

    tf.make_block_builder()
        .with_consensus_data(consensus_data)
        .with_block_signing_key(staking_sk)
        .with_timestamp(block_timestamp)
        .with_reward(reward_outputs)
        .build_and_process(&mut rng)
        .unwrap();

    let res_pool_balance =
        PoSAccountingStorageRead::<TipStorageTag>::get_pool_balance(&tf.storage, pool_id)
            .unwrap()
            .unwrap();
    assert_eq!(total_reward, res_pool_balance);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn pos_block_signature(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (mut tf, stake_pool_outpoint, pool_id, staking_sk) =
        setup_test_chain_with_staked_pool(&mut rng, vrf_pk);

    let initial_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&tf, new_block_height).unwrap();
    let final_supply = tf.chainstate.get_chain_config().final_supply().unwrap();

    let (pos_data, block_timestamp) = chainstate_test_framework::pos_mine(
        &mut rng,
        &tf.storage.transaction_ro().unwrap(),
        &get_pos_chain_config(tf.chainstate.get_chain_config(), new_block_height),
        BlockTimestamp::from_time(tf.current_time()),
        stake_pool_outpoint.clone(),
        InputWitness::NoSignature(None),
        &vrf_sk,
        PoSRandomness::new(initial_randomness),
        pool_id,
        final_supply,
        1,
        current_difficulty,
    )
    .expect("should be able to mine");
    let consensus_data = ConsensusData::PoS(Box::new(pos_data));
    let reward_output = TxOutput::ProduceBlockFromStake(anyonecanspend_address(), pool_id);

    // empty block signature
    let block = tf
        .make_block_builder()
        .with_consensus_data(consensus_data.clone())
        .with_reward(vec![reward_output.clone()])
        .with_timestamp(block_timestamp)
        .build(&mut rng);
    let block_id = block.get_id();
    assert_eq!(
        tf.process_block(block, BlockSource::Local).unwrap_err(),
        ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
            CheckBlockError::ConsensusVerificationFailed(ConsensusVerificationError::PoSError(
                ConsensusPoSError::BlockSignatureError(
                    BlockSignatureError::BlockSignatureNotFound(block_id)
                )
            ))
        ))
    );

    // bad block signature
    // Note: this tx is not strictly needed for the test, but without it the block id here
    // may become equal to the id of the previous test block, in which case process_block
    // would return a different error from what is expected here (namely, it would return
    // InvalidBlockAlreadySeen).
    let tx = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(
                OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                0,
            ),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::Burn(OutputValue::Coin(Amount::from_atoms(
            100_000,
        ))))
        .build();
    let block = tf
        .make_block_builder()
        .with_block_signing_key(PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr).0)
        .with_consensus_data(consensus_data)
        .with_reward(vec![reward_output])
        .with_timestamp(block_timestamp)
        .with_transactions(vec![tx])
        .build(&mut rng);
    let block_id = block.get_id();
    assert_eq!(
        tf.process_block(block, BlockSource::Local).unwrap_err(),
        ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
            CheckBlockError::ConsensusVerificationFailed(ConsensusVerificationError::PoSError(
                ConsensusPoSError::BlockSignatureError(BlockSignatureError::BadSignature(block_id))
            ))
        ))
    );

    // valid case
    let staking_destination = Destination::PublicKey(PublicKey::from_private_key(&staking_sk));
    let reward_outputs =
        vec![TxOutput::ProduceBlockFromStake(staking_destination.clone(), pool_id)];

    let kernel_sig = produce_kernel_signature(
        &mut rng,
        &tf,
        &staking_sk,
        reward_outputs.as_slice(),
        staking_destination,
        tf.best_block_id(),
        stake_pool_outpoint.clone(),
    );
    let new_block_height = tf.best_block_index().block_height().next_height();

    let (pos_data, block_timestamp) = chainstate_test_framework::pos_mine(
        &mut rng,
        &tf.storage.transaction_ro().unwrap(),
        &get_pos_chain_config(tf.chainstate.get_chain_config(), new_block_height),
        BlockTimestamp::from_time(tf.current_time()),
        stake_pool_outpoint,
        InputWitness::Standard(kernel_sig),
        &vrf_sk,
        PoSRandomness::new(initial_randomness),
        pool_id,
        final_supply,
        1,
        current_difficulty,
    )
    .expect("should be able to mine");
    let consensus_data = ConsensusData::PoS(Box::new(pos_data));

    tf.make_block_builder()
        .with_consensus_data(consensus_data)
        .with_block_signing_key(staking_sk)
        .with_timestamp(block_timestamp)
        .with_reward(reward_outputs)
        .build_and_process(&mut rng)
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
    let (staking_sk, staking_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

    let upgrades = vec![
        (BlockHeight::new(0), ConsensusUpgrade::IgnoreConsensus),
        (
            BlockHeight::new(1),
            ConsensusUpgrade::PoS {
                initial_difficulty: None,
                config: PoSChainConfigBuilder::new_for_unit_test().build(),
            },
        ),
    ];
    let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
    let genesis = create_custom_genesis_with_stake_pool(staking_pk, vrf_pk);
    let chain_config = ConfigBuilder::new(ChainType::Regtest)
        .consensus_upgrades(net_upgrades)
        .genesis_custom(genesis)
        .build();
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();

    let genesis_id = tf.genesis().get_id();
    let pool_id = H256::zero().into();

    let invalid_kernel_input =
        UtxoOutPoint::new(OutPointSourceId::BlockReward(genesis_id.into()), 0);
    let initial_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&tf, new_block_height).unwrap();
    let final_supply = tf.chainstate.get_chain_config().final_supply().unwrap();

    let (pos_data, block_timestamp) = chainstate_test_framework::pos_mine(
        &mut rng,
        &tf.storage.transaction_ro().unwrap(),
        &get_pos_chain_config(tf.chainstate.get_chain_config(), new_block_height),
        BlockTimestamp::from_time((tf.current_time() + Duration::from_secs(1)).unwrap()),
        invalid_kernel_input,
        InputWitness::NoSignature(None),
        &vrf_sk,
        PoSRandomness::new(initial_randomness),
        pool_id,
        final_supply,
        1,
        current_difficulty,
    )
    .expect("should be able to mine");

    let block = tf
        .make_block_builder()
        .with_block_signing_key(staking_sk)
        .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
        .with_timestamp(block_timestamp)
        .build(&mut rng);
    let block_id = block.get_id();

    assert_eq!(
        tf.process_block(block, BlockSource::Local).unwrap_err(),
        ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
            CheckBlockError::ConsensusVerificationFailed(ConsensusVerificationError::PoSError(
                ConsensusPoSError::InvalidOutputTypeInStakeKernel(block_id)
            ))
        ))
    );
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
    let (mut tf, stake_pool_outpoint, pool_id, staking_sk) =
        setup_test_chain_with_staked_pool(&mut rng, vrf_pk);

    let expected_error = ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
        CheckBlockError::ConsensusVerificationFailed(ConsensusVerificationError::PoSError(
            ConsensusPoSError::RandomnessError(PoSRandomnessError::VRFDataVerificationFailed(
                ProofOfStakeVRFError::VRFDataVerificationFailed(VRFError::VerificationError),
            )),
        )),
    ));

    let valid_prev_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let valid_block_timestamp = BlockTimestamp::from_time(tf.current_time());
    let valid_epoch: EpochIndex = 1;
    let valid_vrf_transcript =
        construct_transcript(valid_epoch, &valid_prev_randomness, valid_block_timestamp);

    let staking_destination = Destination::PublicKey(PublicKey::from_private_key(&staking_sk));
    let reward_outputs =
        vec![TxOutput::ProduceBlockFromStake(staking_destination.clone(), pool_id)];

    let kernel_sig = produce_kernel_signature(
        &mut rng,
        &tf,
        &staking_sk,
        reward_outputs.as_slice(),
        staking_destination,
        tf.best_block_id(),
        stake_pool_outpoint.clone(),
    );

    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&tf, new_block_height).unwrap();
    let final_supply = tf.chainstate.get_chain_config().final_supply().unwrap();

    let (valid_pos_data, valid_block_timestamp) = chainstate_test_framework::pos_mine(
        &mut rng,
        &tf.storage.transaction_ro().unwrap(),
        &get_pos_chain_config(tf.chainstate.get_chain_config(), new_block_height),
        BlockTimestamp::from_time(tf.current_time()),
        stake_pool_outpoint,
        InputWitness::Standard(kernel_sig),
        &vrf_sk,
        PoSRandomness::new(valid_prev_randomness),
        pool_id,
        final_supply,
        valid_epoch,
        current_difficulty,
    )
    .expect("should be able to mine");

    {
        // invalid sealed epoch randomness
        let invalid_randomness = H256::random_using(&mut rng);
        let vrf_transcript =
            construct_transcript(valid_epoch, &invalid_randomness, valid_block_timestamp);
        let vrf_data = vrf_sk.produce_vrf_data(vrf_transcript);
        let pos_data = PoSData::new(
            valid_pos_data.kernel_inputs().to_owned(),
            valid_pos_data.kernel_witness().to_owned(),
            pool_id,
            vrf_data,
            valid_pos_data.compact_target(),
        );

        let res = tf
            .make_block_builder()
            .with_block_signing_key(staking_sk.clone())
            .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
            .build_and_process(&mut rng)
            .unwrap_err();

        assert_eq!(res, expected_error);
    }

    {
        // invalid timestamp
        let block_timestamp = valid_block_timestamp.add_int_seconds(1).unwrap();
        let vrf_transcript =
            construct_transcript(valid_epoch, &valid_prev_randomness, block_timestamp);
        let vrf_data = vrf_sk.produce_vrf_data(vrf_transcript);
        let pos_data = PoSData::new(
            valid_pos_data.kernel_inputs().to_owned(),
            valid_pos_data.kernel_witness().to_owned(),
            pool_id,
            vrf_data,
            valid_pos_data.compact_target(),
        );

        let res = tf
            .make_block_builder()
            .with_block_signing_key(staking_sk.clone())
            .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
            .build_and_process(&mut rng)
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
        let vrf_data = vrf_sk.produce_vrf_data(vrf_transcript);
        let pos_data = PoSData::new(
            valid_pos_data.kernel_inputs().to_owned(),
            valid_pos_data.kernel_witness().to_owned(),
            pool_id,
            vrf_data,
            valid_pos_data.compact_target(),
        );

        let res = tf
            .make_block_builder()
            .with_block_signing_key(staking_sk.clone())
            .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
            .build_and_process(&mut rng)
            .unwrap_err();

        assert_eq!(res, expected_error);
    }

    {
        // invalid vrf private key
        let (vrf_sk_2, _) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let vrf_data = vrf_sk_2.produce_vrf_data(valid_vrf_transcript);
        let pos_data = PoSData::new(
            valid_pos_data.kernel_inputs().to_owned(),
            valid_pos_data.kernel_witness().to_owned(),
            pool_id,
            vrf_data,
            valid_pos_data.compact_target(),
        );

        let res = tf
            .make_block_builder()
            .with_block_signing_key(staking_sk.clone())
            .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
            .build_and_process(&mut rng)
            .unwrap_err();

        assert_eq!(res, expected_error);
    }

    {
        // valid case
        let consensus_data = ConsensusData::PoS(Box::new(valid_pos_data));
        tf.make_block_builder()
            .with_block_signing_key(staking_sk)
            .with_consensus_data(consensus_data)
            .with_reward(reward_outputs)
            .with_timestamp(valid_block_timestamp)
            .build_and_process(&mut rng)
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
    let (mut tf, stake_pool_outpoint, pool_id, staking_sk) =
        setup_test_chain_with_staked_pool(&mut rng, vrf_pk);

    let staking_destination = Destination::PublicKey(PublicKey::from_private_key(&staking_sk));
    let reward_outputs =
        vec![TxOutput::ProduceBlockFromStake(staking_destination.clone(), pool_id)];

    let kernel_sig = produce_kernel_signature(
        &mut rng,
        &tf,
        &staking_sk,
        reward_outputs.as_slice(),
        staking_destination,
        tf.best_block_id(),
        stake_pool_outpoint.clone(),
    );

    let initial_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&tf, new_block_height).unwrap();
    let final_supply = tf.chainstate.get_chain_config().final_supply().unwrap();

    let (valid_pos_data, block_timestamp) = chainstate_test_framework::pos_mine(
        &mut rng,
        &tf.storage.transaction_ro().unwrap(),
        &get_pos_chain_config(tf.chainstate.get_chain_config(), new_block_height),
        BlockTimestamp::from_time(tf.current_time()),
        stake_pool_outpoint,
        InputWitness::Standard(kernel_sig),
        &vrf_sk,
        PoSRandomness::new(initial_randomness),
        pool_id,
        final_supply,
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
        .with_block_signing_key(staking_sk.clone())
        .with_timestamp(block_timestamp)
        .with_consensus_data(ConsensusData::PoS(Box::new(invalid_pos_data)))
        .build_and_process(&mut rng)
        .unwrap_err();

    assert_eq!(
        res,
        ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
            CheckBlockError::ConsensusVerificationFailed(ConsensusVerificationError::PoSError(
                ConsensusPoSError::PoolDataNotFound(random_pool_id)
            ))
        ))
    );

    // test valid case
    tf.make_block_builder()
        .with_block_signing_key(staking_sk)
        .with_consensus_data(ConsensusData::PoS(Box::new(valid_pos_data)))
        .with_reward(reward_outputs)
        .with_timestamp(block_timestamp)
        .build_and_process(&mut rng)
        .unwrap();
}

// Create a chain genesis <- block_1, where block_1 has valid StakePool output.
// PoS consensus activates on height 2 and an epoch is sealed at height 2.
// Try to crete block_2 with PoS data that has refer to staked pool.
#[ignore = "Disabled because of switch from SealedStorageTag to TipStorageTag"]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn not_sealed_pool_cannot_be_used(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

    let upgrades = vec![
        (BlockHeight::new(0), ConsensusUpgrade::IgnoreConsensus),
        (
            BlockHeight::new(2),
            ConsensusUpgrade::PoS {
                initial_difficulty: None,
                config: PoSChainConfigBuilder::new_for_unit_test().build(),
            },
        ),
    ];
    let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
    let chain_config = ConfigBuilder::test_chain()
        .consensus_upgrades(net_upgrades)
        .epoch_length(NonZeroU64::new(3).unwrap()) // stake pool won't be sealed at height 1
        .sealed_epoch_distance_from_tip(TEST_SEALED_EPOCH_DISTANCE)
        .build();
    let min_stake_pool_pledge = chain_config.min_stake_pool_pledge();
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();

    let (stake_pool_data, staking_sk) =
        create_stake_pool_data_with_all_reward_to_staker(&mut rng, min_stake_pool_pledge, vrf_pk);
    let (stake_pool_outpoint, pool_id) =
        add_block_with_stake_pool(&mut rng, &mut tf, stake_pool_data);

    let initial_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&tf, new_block_height).unwrap();
    let final_supply = tf.chainstate.get_chain_config().final_supply().unwrap();

    let (pos_data, block_timestamp) = chainstate_test_framework::pos_mine(
        &mut rng,
        &tf.storage.transaction_ro().unwrap(),
        &get_pos_chain_config(tf.chainstate.get_chain_config(), new_block_height),
        BlockTimestamp::from_time(tf.current_time()),
        stake_pool_outpoint,
        InputWitness::NoSignature(None),
        &vrf_sk,
        PoSRandomness::new(initial_randomness),
        pool_id,
        final_supply,
        0,
        current_difficulty,
    )
    .expect("should be able to mine");

    let res = tf
        .make_block_builder()
        .with_block_signing_key(staking_sk)
        .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
        .with_timestamp(block_timestamp)
        .build_and_process(&mut rng)
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
    let (mut tf, stake_pool_outpoint, pool_id, staking_sk) =
        setup_test_chain_with_staked_pool(&mut rng, vrf_pk);
    let target_block_time = tf.chain_config().target_block_spacing();

    // prepare and process block_2 with StakePool -> ProduceBlockFromStake kernel
    let staking_destination = Destination::PublicKey(PublicKey::from_private_key(&staking_sk));
    let reward_outputs =
        vec![TxOutput::ProduceBlockFromStake(staking_destination.clone(), pool_id)];

    let kernel_sig = produce_kernel_signature(
        &mut rng,
        &tf,
        &staking_sk,
        reward_outputs.as_slice(),
        staking_destination,
        tf.best_block_id(),
        stake_pool_outpoint.clone(),
    );

    let initial_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&tf, new_block_height).unwrap();
    let final_supply = tf.chainstate.get_chain_config().final_supply().unwrap();

    let (pos_data, block_timestamp) = chainstate_test_framework::pos_mine(
        &mut rng,
        &tf.storage.transaction_ro().unwrap(),
        &get_pos_chain_config(tf.chainstate.get_chain_config(), new_block_height),
        BlockTimestamp::from_time(tf.current_time()),
        stake_pool_outpoint,
        InputWitness::Standard(kernel_sig),
        &vrf_sk,
        // no epoch is sealed yet so use initial randomness
        PoSRandomness::new(initial_randomness),
        pool_id,
        final_supply,
        1,
        current_difficulty,
    )
    .expect("should be able to mine");
    tf.make_block_builder()
        .with_block_signing_key(staking_sk.clone())
        .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
        .with_reward(reward_outputs)
        .with_timestamp(block_timestamp)
        .build_and_process(&mut rng)
        .unwrap();
    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());

    // prepare and process block_3 with ProduceBlockFromStake -> ProduceBlockFromStake kernel
    let block_2_reward_outpoint = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(tf.chainstate.get_best_block_id().unwrap()),
        0,
    );
    let staking_destination = Destination::PublicKey(PublicKey::from_private_key(&staking_sk));
    let reward_outputs =
        vec![TxOutput::ProduceBlockFromStake(staking_destination.clone(), pool_id)];

    let kernel_sig = produce_kernel_signature(
        &mut rng,
        &tf,
        &staking_sk,
        reward_outputs.as_slice(),
        staking_destination,
        tf.best_block_id(),
        block_2_reward_outpoint.clone(),
    );
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&tf, new_block_height).unwrap();
    let (pos_data, block_timestamp) = chainstate_test_framework::pos_mine(
        &mut rng,
        &tf.storage.transaction_ro().unwrap(),
        &get_pos_chain_config(tf.chainstate.get_chain_config(), new_block_height),
        BlockTimestamp::from_time(tf.current_time()),
        block_2_reward_outpoint,
        InputWitness::Standard(kernel_sig),
        &vrf_sk,
        // no epoch is sealed yet so use initial randomness
        PoSRandomness::new(initial_randomness),
        pool_id,
        final_supply,
        1,
        current_difficulty,
    )
    .expect("should be able to mine");
    tf.make_block_builder()
        .with_block_signing_key(staking_sk.clone())
        .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
        .with_reward(reward_outputs)
        .with_timestamp(block_timestamp)
        .build_and_process(&mut rng)
        .unwrap();
    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());

    // prepare and process block_4 with ProduceBlockFromStake -> ProduceBlockFromStake kernel
    let block_3_reward_outpoint = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(tf.chainstate.get_best_block_id().unwrap()),
        0,
    );

    let staking_destination = Destination::PublicKey(PublicKey::from_private_key(&staking_sk));
    let reward_outputs =
        vec![TxOutput::ProduceBlockFromStake(staking_destination.clone(), pool_id)];

    let kernel_sig = produce_kernel_signature(
        &mut rng,
        &tf,
        &staking_sk,
        reward_outputs.as_slice(),
        staking_destination,
        tf.best_block_id(),
        block_3_reward_outpoint.clone(),
    );

    // sealed epoch randomness can be used
    let sealed_epoch_randomness =
        tf.storage.transaction_ro().unwrap().get_epoch_data(1).unwrap().unwrap();
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&tf, new_block_height).unwrap();
    let final_supply = tf.chainstate.get_chain_config().final_supply().unwrap();

    let (pos_data, block_timestamp) = chainstate_test_framework::pos_mine(
        &mut rng,
        &tf.storage.transaction_ro().unwrap(),
        &get_pos_chain_config(tf.chainstate.get_chain_config(), new_block_height),
        BlockTimestamp::from_time(tf.current_time()),
        block_3_reward_outpoint,
        InputWitness::Standard(kernel_sig),
        &vrf_sk,
        *sealed_epoch_randomness.randomness(),
        pool_id,
        final_supply,
        2,
        current_difficulty,
    )
    .expect("should be able to mine");
    tf.make_block_builder()
        .with_block_signing_key(staking_sk)
        .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
        .with_reward(reward_outputs)
        .with_timestamp(block_timestamp)
        .build_and_process(&mut rng)
        .unwrap();

    let res_pool_balance =
        PoSAccountingStorageRead::<TipStorageTag>::get_pool_balance(&tf.storage, pool_id)
            .unwrap()
            .unwrap();
    let total_subsidy =
        tf.chainstate.get_chain_config().block_subsidy_at_height(&BlockHeight::from(1)) * 3;
    let initially_staked = tf.chainstate.get_chain_config().min_stake_pool_pledge();
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
    let (mut tf, stake_pool_outpoint1, pool_id1, staking_sk_1, _, pool_id2, _) =
        setup_test_chain_with_2_staked_pools(&mut rng, vrf_pk_1, vrf_pk_2);

    // prepare and process block_2 with StakePool -> ProduceBlockFromStake kernel
    // kernel refers to pool1, while block reward refers to pool2
    let initial_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&tf, new_block_height).unwrap();
    let final_supply = tf.chainstate.get_chain_config().final_supply().unwrap();

    let (pos_data, block_timestamp) = chainstate_test_framework::pos_mine(
        &mut rng,
        &tf.storage.transaction_ro().unwrap(),
        &get_pos_chain_config(tf.chainstate.get_chain_config(), new_block_height),
        BlockTimestamp::from_time(tf.current_time()),
        stake_pool_outpoint1,
        InputWitness::NoSignature(None),
        &vrf_sk_1,
        PoSRandomness::new(initial_randomness),
        pool_id1,
        final_supply,
        1,
        current_difficulty,
    )
    .expect("should be able to mine");
    let reward_output = TxOutput::ProduceBlockFromStake(anyonecanspend_address(), pool_id2);
    let res = tf
        .make_block_builder()
        .with_block_signing_key(staking_sk_1)
        .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
        .with_reward(vec![reward_output])
        .with_timestamp(block_timestamp)
        .build_and_process(&mut rng)
        .unwrap_err();

    assert_eq!(
        res,
        ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
            ConnectTransactionError::SpendStakeError(SpendStakeError::StakePoolIdMismatch(
                pool_id1, pool_id2
            ))
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

    let genesis_outpoint = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
        0,
    );
    let pool_id = PoolId::from_utxo(&genesis_outpoint);

    let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (stake_pool_data, staking_sk) =
        create_stake_pool_data_with_all_reward_to_staker(&mut rng, Amount::from_atoms(1), vrf_pk);
    let reward_output = TxOutput::CreateStakePool(pool_id, Box::new(stake_pool_data));
    let block = tf
        .make_block_builder()
        .with_reward(vec![reward_output])
        .with_block_signing_key(staking_sk)
        .build(&mut rng);
    let block_id = block.get_id();
    assert_eq!(
        tf.process_block(block, chainstate::BlockSource::Local).unwrap_err(),
        ChainstateError::ProcessBlockError(BlockError::CheckBlockFailed(
            CheckBlockError::InvalidBlockRewardOutputType(block_id)
        ))
    );
}

// Produce `genesis -> a -> b -> c` chain, then a parallel `genesis -> a -> d -> e -> f` that should trigger a reorg.
// It's important for the test that and block `c` and `e` epoch 1 is sealed.
// Block `a` has stake pool output. PoS activates at height 2 with block `b` and `d`.
// Blocks `b`, `c`, `d`, `e`, `f` have produce block from stake outputs.
// Check that after reorg pool balance doesn't include reward from block `b` and `c`
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_pool_balance_after_reorg(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (staking_sk, staking_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

    // create initial chain with genesis
    let (chain_config_builder, genesis_pool_id) =
        chainstate_test_framework::create_chain_config_with_default_staking_pool(
            &mut rng,
            staking_pk,
            vrf_pk.clone(),
        );
    let chain_config = chain_config_builder
        .epoch_length(TEST_EPOCH_LENGTH)
        .sealed_epoch_distance_from_tip(TEST_SEALED_EPOCH_DISTANCE)
        .build();
    let initial_randomness = PoSRandomness::new(chain_config.initial_randomness());

    let target_block_time = chain_config.target_block_spacing();
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();
    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());

    let initially_staked =
        PoSAccountingStorageRead::<TipStorageTag>::get_pool_balance(&tf.storage, genesis_pool_id)
            .unwrap()
            .unwrap();

    let block_a_id = *tf
        .make_pos_block_builder()
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process(&mut rng)
        .unwrap()
        .unwrap()
        .block_id();

    // prepare and process block_b from block_a
    tf.make_pos_block_builder()
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process(&mut rng)
        .unwrap();

    // prepare and process block_c from block_b
    let block_c_id = *tf
        .make_pos_block_builder()
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .with_randomness(initial_randomness) // no epoch is sealed yet while constructing this block
        .build_and_process(&mut rng)
        .unwrap()
        .unwrap()
        .block_id();

    // prepare and process block_d from block_a
    let block_d = tf
        .make_pos_block_builder()
        .with_parent(block_a_id.into())
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build(&mut rng);
    let block_d_id = block_d.get_id();
    tf.process_block(block_d, BlockSource::Local).unwrap();

    // prepare and process block_e from block_d
    let block_e = tf
        .make_pos_block_builder()
        .with_parent(block_d_id.into())
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk.clone())
        .with_randomness(initial_randomness) // no epoch is sealed yet while constructing this block
        .with_vrf_key(vrf_sk.clone())
        .build(&mut rng);
    let block_e_id = block_e.get_id();
    // have to calculate randomness of prev block because reorg hasn't happen yet and it's not in the db
    let block_e_pos_data = match block_e.consensus_data() {
        ConsensusData::None | ConsensusData::PoW(_) => {
            unreachable!()
        }
        ConsensusData::PoS(pos_data) => pos_data.as_ref(),
    };
    let block_e_randomness = PoSRandomness::from_block(
        1,
        block_e.timestamp(),
        &initial_randomness,
        block_e_pos_data.vrf_data(),
        &vrf_pk,
    )
    .unwrap();
    tf.process_block(block_e, BlockSource::Local).unwrap();

    // no reorg here
    assert_eq!(Id::<GenBlock>::from(block_c_id), tf.best_block_id());

    // prepare and process block_f from block_e
    let block_f_id = *tf
        .make_pos_block_builder()
        .with_parent(block_e_id.into())
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk)
        .with_vrf_key(vrf_sk)
        .with_randomness(block_e_randomness)
        .build_and_process(&mut rng)
        .unwrap()
        .unwrap()
        .block_id();

    // reorg should be triggered
    assert_eq!(Id::<GenBlock>::from(block_f_id), tf.best_block_id());

    let res_pool_balance =
        PoSAccountingStorageRead::<TipStorageTag>::get_pool_balance(&tf.storage, genesis_pool_id)
            .unwrap()
            .unwrap();
    let total_subsidy =
        tf.chainstate.get_chain_config().block_subsidy_at_height(&BlockHeight::from(1)) * 4;
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

    // create initial chain: genesis <- block_1
    // block1 creates 2 separate pools: first will be decommissioned and the second one will be used
    // to produce block with decommissioning tx
    let (
        mut tf,
        stake_pool_outpoint1,
        pool_id1,
        staking_sk1,
        stake_pool_outpoint2,
        pool_id2,
        staking_sk2,
    ) = setup_test_chain_with_2_staked_pools(&mut rng, vrf_pk_1, vrf_pk_2);
    let target_block_time = tf.chain_config().target_block_spacing();

    let stake_pool_block_id = tf.best_block_id();

    // prepare and process block_2 with StakePool -> ProduceBlockFromStake kernel
    let staking_destination = Destination::PublicKey(PublicKey::from_private_key(&staking_sk1));
    let reward_outputs =
        vec![TxOutput::ProduceBlockFromStake(staking_destination.clone(), pool_id1)];

    let kernel_sig = produce_kernel_signature(
        &mut rng,
        &tf,
        &staking_sk1,
        reward_outputs.as_slice(),
        staking_destination,
        tf.best_block_id(),
        stake_pool_outpoint1.clone(),
    );

    let initial_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&tf, new_block_height).unwrap();
    let final_supply = tf.chainstate.get_chain_config().final_supply().unwrap();

    let (pos_data, block_timestamp) = chainstate_test_framework::pos_mine(
        &mut rng,
        &tf.storage.transaction_ro().unwrap(),
        &get_pos_chain_config(tf.chainstate.get_chain_config(), new_block_height),
        BlockTimestamp::from_time(tf.current_time()),
        stake_pool_outpoint1,
        InputWitness::Standard(kernel_sig),
        &vrf_sk_1,
        // no epoch is sealed yet so use initial randomness
        PoSRandomness::new(initial_randomness),
        pool_id1,
        final_supply,
        1,
        current_difficulty,
    )
    .expect("should be able to mine");

    tf.make_block_builder()
        .with_block_signing_key(staking_sk1)
        .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
        .with_reward(reward_outputs)
        .with_timestamp(block_timestamp)
        .build_and_process(&mut rng)
        .unwrap();
    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());

    // prepare and process block_3 with ProduceBlockFromStake -> Decommission
    let staking_destination = Destination::PublicKey(PublicKey::from_private_key(&staking_sk2));
    let reward_outputs =
        vec![TxOutput::ProduceBlockFromStake(staking_destination.clone(), pool_id2)];

    let kernel_sig = produce_kernel_signature(
        &mut rng,
        &tf,
        &staking_sk2,
        reward_outputs.as_slice(),
        staking_destination,
        stake_pool_block_id,
        stake_pool_outpoint2.clone(),
    );
    let block_2_reward_outpoint = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(tf.chainstate.get_best_block_id().unwrap()),
        0,
    );
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&tf, new_block_height).unwrap();
    let (pos_data, block_timestamp) = chainstate_test_framework::pos_mine(
        &mut rng,
        &tf.storage.transaction_ro().unwrap(),
        &get_pos_chain_config(tf.chainstate.get_chain_config(), new_block_height),
        BlockTimestamp::from_time(tf.current_time()),
        stake_pool_outpoint2,
        InputWitness::Standard(kernel_sig),
        &vrf_sk_2,
        // no epoch is sealed yet so use initial randomness
        PoSRandomness::new(initial_randomness),
        pool_id2,
        final_supply,
        1,
        current_difficulty,
    )
    .expect("should be able to mine");

    let subsidy = tf.chainstate.get_chain_config().block_subsidy_at_height(&BlockHeight::from(2));
    let initially_staked = tf.chainstate.get_chain_config().min_stake_pool_pledge();
    let total_reward = (subsidy + initially_staked).unwrap();

    let tx = TransactionBuilder::new()
        .add_input(block_2_reward_outpoint.into(), empty_witness(&mut rng))
        .add_output(TxOutput::LockThenTransfer(
            OutputValue::Coin(total_reward),
            anyonecanspend_address(),
            OutputTimeLock::ForBlockCount(2000),
        ))
        .build();

    tf.make_block_builder()
        .with_block_signing_key(staking_sk2)
        .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
        .with_reward(reward_outputs)
        .with_timestamp(block_timestamp)
        .add_transaction(tx)
        .build_and_process(&mut rng)
        .unwrap();
    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());

    let res_pool_balance =
        PoSAccountingStorageRead::<TipStorageTag>::get_pool_balance(&tf.storage, pool_id1).unwrap();
    assert!(res_pool_balance.is_none());
}

// Produce `genesis -> a` chain. Block `a` has 2 stake pool outputs (one to produce block and one to decommission)
// PoS activates at height 2. At height 3 chain changes configuration of decommission maturity.
// The test creates block 'b' from block 'a'. And the block 'c' from block 'a'.
// The goal of the test is to check that block 'c' follows the maturity rules from height 2 and not 3.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn decommission_from_not_best_block(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk_1, vrf_pk_1) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (_, vrf_pk_2) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

    let upgrades = vec![
        (BlockHeight::new(0), ConsensusUpgrade::IgnoreConsensus),
        (
            BlockHeight::new(2),
            ConsensusUpgrade::PoS {
                initial_difficulty: Some(MIN_DIFFICULTY.into()),
                config: PoSChainConfigBuilder::new_for_unit_test()
                    .staking_pool_spend_maturity_block_count(BlockCount::new(50))
                    .build(),
            },
        ),
        (
            BlockHeight::new(3),
            ConsensusUpgrade::PoS {
                initial_difficulty: None,
                config: PoSChainConfigBuilder::new_for_unit_test()
                    // decommission maturity increased
                    .staking_pool_spend_maturity_block_count(BlockCount::new(100))
                    .build(),
            },
        ),
    ];

    // create initial chain: genesis <- block_a
    // block_a creates 2 separate pools
    let (mut tf, stake_pool_outpoint1, pool_id1, staking_sk1, stake_pool_outpoint2, pool_id2, _) =
        setup_test_chain_with_2_staked_pools_with_net_upgrades(
            &mut rng, vrf_pk_1, vrf_pk_2, upgrades,
        );
    let target_block_time = tf.chain_config().target_block_spacing();

    let block_a_id = tf.best_block_id();
    let block_a_height = tf.best_block_index().block_height();

    let staking_destination = Destination::PublicKey(PublicKey::from_private_key(&staking_sk1));
    let produce_block_output =
        vec![TxOutput::ProduceBlockFromStake(staking_destination.clone(), pool_id1)];
    let kernel_sig = produce_kernel_signature(
        &mut rng,
        &tf,
        &staking_sk1,
        produce_block_output.as_slice(),
        staking_destination,
        tf.best_block_id(),
        stake_pool_outpoint1.clone(),
    );

    // prepare and process block_a <- block_b with StakePool -> ProduceBlockFromStake kernel
    let initial_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let current_difficulty = calculate_new_target(&tf, block_a_height.next_height()).unwrap();
    let final_supply = tf.chainstate.get_chain_config().final_supply().unwrap();
    let new_block_height = tf.best_block_index().block_height().next_height();

    let (pos_data, block_timestamp) = chainstate_test_framework::pos_mine(
        &mut rng,
        &tf.storage.transaction_ro().unwrap(),
        &get_pos_chain_config(tf.chainstate.get_chain_config(), new_block_height),
        BlockTimestamp::from_time(tf.current_time()),
        stake_pool_outpoint1,
        InputWitness::Standard(kernel_sig),
        &vrf_sk_1,
        // no epoch is sealed yet so use initial randomness
        PoSRandomness::new(initial_randomness),
        pool_id1,
        final_supply,
        1,
        current_difficulty,
    )
    .expect("should be able to mine");

    // prepare and process block_a <- block_c with StakePool -> Decommission
    let subsidy = tf.chainstate.get_chain_config().block_subsidy_at_height(&BlockHeight::from(2));
    let initially_staked = Amount::from_atoms(1);
    let total_reward = (subsidy + initially_staked).unwrap();

    let block_b_index = tf
        .make_block_builder()
        .with_block_signing_key(staking_sk1.clone())
        .with_consensus_data(ConsensusData::PoS(Box::new(pos_data.clone())))
        .with_reward(produce_block_output.clone())
        .with_timestamp(block_timestamp)
        .build_and_process(&mut rng)
        .unwrap();

    let tx = TransactionBuilder::new()
        .add_input(stake_pool_outpoint2.into(), empty_witness(&mut rng))
        .add_output(TxOutput::LockThenTransfer(
            OutputValue::Coin(total_reward),
            anyonecanspend_address(),
            OutputTimeLock::ForBlockCount(50),
        ))
        .build();

    tf.make_block_builder()
        .with_block_signing_key(staking_sk1)
        .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
        .with_reward(produce_block_output)
        .with_timestamp(block_timestamp)
        .with_parent(block_a_id)
        .add_transaction(tx)
        .build_and_process(&mut rng)
        .unwrap();
    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());

    // no reorg happened so decommission has no effect on pool2
    assert_eq!(
        tf.best_block_id(),
        block_b_index.unwrap().into_gen_block_index().block_id()
    );

    let total_subsidy =
        tf.chainstate.get_chain_config().block_subsidy_at_height(&BlockHeight::from(1));
    let initially_staked = tf.chainstate.get_chain_config().min_stake_pool_pledge();

    let res_pool_balance_1 =
        PoSAccountingStorageRead::<TipStorageTag>::get_pool_balance(&tf.storage, pool_id1)
            .unwrap()
            .unwrap();
    assert_eq!(
        (total_subsidy + initially_staked).unwrap(),
        res_pool_balance_1
    );

    let res_pool_balance_2 =
        PoSAccountingStorageRead::<TipStorageTag>::get_pool_balance(&tf.storage, pool_id2)
            .unwrap()
            .unwrap();
    assert_eq!(initially_staked, res_pool_balance_2);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn pos_stake_testnet_genesis(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let upgrades = vec![
        (BlockHeight::new(0), ConsensusUpgrade::IgnoreConsensus),
        (
            BlockHeight::new(1),
            ConsensusUpgrade::PoS {
                initial_difficulty: Some(MIN_DIFFICULTY.into()),
                config: PoSChainConfigBuilder::new_for_unit_test().build(),
            },
        ),
    ];
    let genesis_pool_id = PoolId::new(H256::zero());
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (staker_sk, staker_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let genesis = create_custom_genesis_with_stake_pool(staker_pk, vrf_pk);

    let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
    let chain_config = ConfigBuilder::new(ChainType::Regtest)
        .consensus_upgrades(net_upgrades)
        .genesis_custom(genesis)
        .build();

    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();

    // Required due to strict timestamp ordering in PoS
    tf.set_time_seconds_since_epoch(tf.best_block_index().block_timestamp().as_int_seconds() + 1);

    let stake_pool_outpoint = UtxoOutPoint::new(tf.best_block_id().into(), 1);
    let staking_destination = Destination::PublicKey(PublicKey::from_private_key(&staker_sk));
    let reward_outputs =
        vec![TxOutput::ProduceBlockFromStake(staking_destination.clone(), genesis_pool_id)];

    let kernel_sig = produce_kernel_signature(
        &mut rng,
        &tf,
        &staker_sk,
        reward_outputs.as_slice(),
        staking_destination.clone(),
        tf.best_block_id(),
        stake_pool_outpoint.clone(),
    );

    let initial_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&tf, new_block_height).unwrap();
    let final_supply = tf.chainstate.get_chain_config().final_supply().unwrap();

    let (pos_data, block_timestamp) = chainstate_test_framework::pos_mine(
        &mut rng,
        &tf.storage.transaction_ro().unwrap(),
        &get_pos_chain_config(tf.chainstate.get_chain_config(), new_block_height),
        BlockTimestamp::from_time(tf.current_time()),
        stake_pool_outpoint,
        InputWitness::Standard(kernel_sig),
        &vrf_sk,
        PoSRandomness::new(initial_randomness),
        genesis_pool_id,
        final_supply,
        0,
        current_difficulty,
    )
    .expect("should be able to mine");
    let consensus_data = ConsensusData::PoS(Box::new(pos_data));

    tf.make_block_builder()
        .with_consensus_data(consensus_data)
        .with_block_signing_key(staker_sk.clone())
        .with_timestamp(block_timestamp)
        .with_reward(reward_outputs)
        .build_and_process(&mut rng)
        .unwrap()
        .unwrap();

    // -----------------------------------------
    // produce another block
    // -----------------------------------------
    // Required due to strict timestamp ordering in PoS
    tf.set_time_seconds_since_epoch(tf.best_block_index().block_timestamp().as_int_seconds() + 1);

    let block_1_reward_outpoint = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(tf.chainstate.get_best_block_id().unwrap()),
        0,
    );
    let reward_outputs =
        vec![TxOutput::ProduceBlockFromStake(staking_destination.clone(), genesis_pool_id)];

    let kernel_sig = produce_kernel_signature(
        &mut rng,
        &tf,
        &staker_sk,
        reward_outputs.as_slice(),
        staking_destination,
        tf.best_block_id(),
        block_1_reward_outpoint.clone(),
    );

    let initial_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&tf, new_block_height).unwrap();
    let final_supply = tf.chainstate.get_chain_config().final_supply().unwrap();

    let (pos_data, block_timestamp) = chainstate_test_framework::pos_mine(
        &mut rng,
        &tf.storage.transaction_ro().unwrap(),
        &get_pos_chain_config(tf.chainstate.get_chain_config(), new_block_height),
        BlockTimestamp::from_time(tf.current_time()),
        block_1_reward_outpoint,
        InputWitness::Standard(kernel_sig),
        &vrf_sk,
        PoSRandomness::new(initial_randomness),
        genesis_pool_id,
        final_supply,
        0,
        current_difficulty,
    )
    .expect("should be able to mine");
    let consensus_data = ConsensusData::PoS(Box::new(pos_data));

    tf.make_block_builder()
        .with_consensus_data(consensus_data)
        .with_block_signing_key(staker_sk)
        .with_timestamp(block_timestamp)
        .with_reward(reward_outputs)
        .build_and_process(&mut rng)
        .unwrap();
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn spend_from_delegation_with_reward(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (staking_sk, staking_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

    let genesis_pool_id = PoolId::new(H256::random_using(&mut rng));
    let pledge_amount = create_unit_test_config().min_stake_pool_pledge();

    let staker_reward_per_block = Amount::from_atoms(1000);
    let stake_pool_data = StakePoolData::new(
        pledge_amount,
        Destination::PublicKey(staking_pk),
        vrf_pk,
        Destination::AnyoneCanSpend,
        PerThousand::new(0).unwrap(),
        staker_reward_per_block,
    );

    let amount_to_delegate = Amount::from_atoms(rng.gen_range(100..100_000));
    // mint amount == amount to delegate to avoid dealing with fees
    let chain_config = chainstate_test_framework::create_chain_config_with_staking_pool(
        &mut rng,
        amount_to_delegate,
        genesis_pool_id,
        stake_pool_data,
    )
    .build();
    let target_block_time = chain_config.target_block_spacing();
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();
    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());

    // Process block_1: create delegation and delegate some amount

    let genesis_outpoint = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
        0,
    );

    let tx1 = TransactionBuilder::new()
        .add_input(genesis_outpoint.into(), empty_witness(&mut rng))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(amount_to_delegate),
            Destination::AnyoneCanSpend,
        ))
        .add_output(TxOutput::CreateDelegationId(
            Destination::AnyoneCanSpend,
            genesis_pool_id,
        ))
        .build();
    let delegation_id = make_delegation_id(tx1.inputs()).unwrap();
    let tx1_id = tx1.transaction().get_id();
    let tx2 = TransactionBuilder::new()
        .add_input(
            UtxoOutPoint::new(tx1_id.into(), 0).into(),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::DelegateStaking(amount_to_delegate, delegation_id))
        .build();

    tf.make_pos_block_builder()
        .with_transactions(vec![tx1, tx2])
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process(&mut rng)
        .unwrap();

    // Process block_2: distribute some reward
    tf.make_pos_block_builder()
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build_and_process(&mut rng)
        .unwrap();

    // Process block_3: spend part of the share including reward
    let amount_to_withdraw = Amount::from_atoms(rng.gen_range(1..amount_to_delegate.into_atoms()));
    let tx_input_spend_from_delegation = TxInput::Account(AccountOutPoint::new(
        AccountNonce::new(0),
        AccountSpending::DelegationBalance(delegation_id, amount_to_withdraw),
    ));
    let tx = TransactionBuilder::new()
        .add_input(tx_input_spend_from_delegation, empty_witness(&mut rng))
        .add_output(TxOutput::LockThenTransfer(
            OutputValue::Coin(amount_to_withdraw),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForBlockCount(2000),
        ))
        .build();

    tf.make_pos_block_builder()
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .add_transaction(tx)
        .build_and_process(&mut rng)
        .unwrap();

    // Process block_4 and spend some share including reward
    let delegation_balance =
        tf.chainstate.get_stake_delegation_balance(delegation_id).unwrap().unwrap();

    // try overspend
    {
        let delegation_balance_overspend = (delegation_balance + Amount::from_atoms(1)).unwrap();
        let tx_input_spend_from_delegation = TxInput::Account(AccountOutPoint::new(
            AccountNonce::new(1),
            AccountSpending::DelegationBalance(delegation_id, delegation_balance_overspend),
        ));
        let tx = TransactionBuilder::new()
            .add_input(tx_input_spend_from_delegation, empty_witness(&mut rng))
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(delegation_balance_overspend),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(2000),
            ))
            .build();
        let tx_id = tx.transaction().get_id();

        let res = tf
            .make_pos_block_builder()
            .with_stake_pool_id(genesis_pool_id)
            .with_stake_spending_key(staking_sk.clone())
            .with_vrf_key(vrf_sk.clone())
            .add_transaction(tx)
            .build_and_process(&mut rng)
            .unwrap_err();
        assert_eq!(
            res,
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ConstrainedValueAccumulatorError(
                    constraints_value_accumulator::Error::PoSAccountingError(
                        pos_accounting::Error::AccountingError(
                            accounting::Error::ArithmeticErrorSumToUnsignedFailed
                        )
                    ),
                    tx_id.into()
                )
            ))
        );
    }

    let tx_input_spend_from_delegation = TxInput::Account(AccountOutPoint::new(
        AccountNonce::new(1),
        AccountSpending::DelegationBalance(delegation_id, delegation_balance),
    ));
    let tx = TransactionBuilder::new()
        .add_input(tx_input_spend_from_delegation, empty_witness(&mut rng))
        .add_output(TxOutput::LockThenTransfer(
            OutputValue::Coin(delegation_balance),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForBlockCount(2000),
        ))
        .build();

    tf.make_pos_block_builder()
        .with_stake_pool_id(genesis_pool_id)
        .with_stake_spending_key(staking_sk)
        .with_vrf_key(vrf_sk)
        .add_transaction(tx)
        .build_and_process(&mut rng)
        .unwrap();

    let res_pool_balance = PoSAccountingStorageRead::<TipStorageTag>::get_delegation_balance(
        &tf.storage,
        delegation_id,
    )
    .unwrap();
    assert_eq!(None, res_pool_balance);
}

// Create custom genesis with a staking pool.
// Produce a block that creates another staking pool.
// Produce another block using new staking pool and decommission genesis pool.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn pos_decommission_genesis_pool(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (genesis_staking_sk, genesis_staking_pk) =
        PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let (genesis_vrf_sk, genesis_vrf_pk) =
        VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

    let upgrades = vec![(
        BlockHeight::new(0),
        ConsensusUpgrade::PoS {
            initial_difficulty: Some(MIN_DIFFICULTY.into()),
            config: PoSChainConfigBuilder::new_for_unit_test().build(),
        },
    )];
    let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
    let genesis =
        create_custom_genesis_with_stake_pool(genesis_staking_pk.clone(), genesis_vrf_pk.clone());
    let chain_config = ConfigBuilder::test_chain()
        .consensus_upgrades(net_upgrades)
        .genesis_custom(genesis)
        .build();
    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();
    tf.progress_time_seconds_since_epoch(1);

    let genesis_outpoint_0 = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
        0,
    );
    let genesis_outpoint_1 = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
        1,
    );
    let genesis_pool_id: PoolId = H256::zero().into();

    let staking_destination = Destination::PublicKey(genesis_staking_pk.clone());
    let reward_outputs =
        vec![TxOutput::ProduceBlockFromStake(staking_destination.clone(), genesis_pool_id)];

    let kernel_sig = produce_kernel_signature(
        &mut rng,
        &tf,
        &genesis_staking_sk,
        reward_outputs.as_slice(),
        staking_destination,
        tf.best_block_id(),
        genesis_outpoint_1.clone(),
    );

    let initial_randomness = tf.chainstate.get_chain_config().initial_randomness();
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&tf, new_block_height).unwrap();
    let final_supply = tf.chainstate.get_chain_config().final_supply().unwrap();

    // create a block with new pool
    let (pos_data, block_timestamp) = chainstate_test_framework::pos_mine(
        &mut rng,
        &tf.storage.transaction_ro().unwrap(),
        &get_pos_chain_config(tf.chainstate.get_chain_config(), new_block_height),
        BlockTimestamp::from_time(tf.current_time()),
        genesis_outpoint_1.clone(),
        InputWitness::Standard(kernel_sig),
        &genesis_vrf_sk,
        PoSRandomness::new(initial_randomness),
        genesis_pool_id,
        final_supply,
        0,
        current_difficulty,
    )
    .expect("should be able to mine");
    let consensus_data = ConsensusData::PoS(Box::new(pos_data));

    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (stake_pool_data, staking_sk) = create_stake_pool_data_with_all_reward_to_staker(
        &mut rng,
        tf.chainstate.get_chain_config().min_stake_pool_pledge(),
        vrf_pk,
    );
    let new_pool_id = PoolId::from_utxo(&genesis_outpoint_0);

    let create_new_pool_tx = TransactionBuilder::new()
        .add_input(genesis_outpoint_0.into(), empty_witness(&mut rng))
        .add_output(TxOutput::CreateStakePool(
            new_pool_id,
            Box::new(stake_pool_data),
        ))
        .build();
    let create_new_pool_tx_id = create_new_pool_tx.transaction().get_id();

    tf.make_block_builder()
        .with_consensus_data(consensus_data)
        .with_block_signing_key(genesis_staking_sk.clone())
        .with_timestamp(block_timestamp)
        .with_reward(reward_outputs)
        .add_transaction(create_new_pool_tx)
        .build_and_process(&mut rng)
        .unwrap();
    tf.progress_time_seconds_since_epoch(1);

    let genesis_pool_balance =
        PoSAccountingStorageRead::<TipStorageTag>::get_pool_balance(&tf.storage, genesis_pool_id)
            .unwrap()
            .unwrap();
    assert!(
        PoSAccountingStorageRead::<TipStorageTag>::get_pool_balance(&tf.storage, new_pool_id)
            .unwrap()
            .is_some()
    );

    // decommission genesis pool
    let staking_destination = Destination::PublicKey(PublicKey::from_private_key(&staking_sk));
    let reward_outputs =
        vec![TxOutput::ProduceBlockFromStake(staking_destination.clone(), new_pool_id)];

    let kernel_sig = produce_kernel_signature(
        &mut rng,
        &tf,
        &staking_sk,
        reward_outputs.as_slice(),
        staking_destination,
        tf.best_block_id(),
        UtxoOutPoint::new(create_new_pool_tx_id.into(), 0),
    );

    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&tf, new_block_height).unwrap();

    // create a block with new pool
    let (pos_data, block_timestamp) = chainstate_test_framework::pos_mine(
        &mut rng,
        &tf.storage.transaction_ro().unwrap(),
        &get_pos_chain_config(tf.chainstate.get_chain_config(), new_block_height),
        BlockTimestamp::from_time(tf.current_time()),
        UtxoOutPoint::new(create_new_pool_tx_id.into(), 0),
        InputWitness::Standard(kernel_sig),
        &vrf_sk,
        PoSRandomness::new(initial_randomness),
        new_pool_id,
        final_supply,
        0,
        current_difficulty,
    )
    .expect("should be able to mine");
    let consensus_data = ConsensusData::PoS(Box::new(pos_data));

    let decommission_genesis_pool_tx = {
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(tf.best_block_id().into(), 0),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(genesis_pool_balance),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(2000),
            ))
            .build()
            .transaction()
            .clone();

        let input_utxo = tf
            .chainstate
            .utxo(&UtxoOutPoint::new(tf.best_block_id().into(), 0))
            .unwrap()
            .unwrap();

        let input_sign = StandardInputSignature::produce_uniparty_signature_for_input(
            &genesis_staking_sk,
            SigHashType::all(),
            Destination::PublicKey(genesis_staking_pk),
            &tx,
            &[Some(input_utxo.output())],
            0,
            &mut rng,
        )
        .unwrap();
        SignedTransaction::new(tx, vec![InputWitness::Standard(input_sign)])
            .expect("invalid witness count")
    };
    let decommission_genesis_pool_tx_id = decommission_genesis_pool_tx.transaction().get_id();

    tf.make_block_builder()
        .with_consensus_data(consensus_data)
        .with_block_signing_key(staking_sk)
        .with_timestamp(block_timestamp)
        .with_reward(reward_outputs)
        .add_transaction(decommission_genesis_pool_tx)
        .build_and_process(&mut rng)
        .unwrap();

    let decommissioned_genesis_utxo = tf
        .chainstate
        .utxo(&UtxoOutPoint::new(
            decommission_genesis_pool_tx_id.into(),
            0,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(
        chainstate_test_framework::get_output_value(decommissioned_genesis_utxo.output()).unwrap(),
        OutputValue::Coin(genesis_pool_balance)
    );

    assert!(PoSAccountingStorageRead::<TipStorageTag>::get_pool_balance(
        &tf.storage,
        genesis_pool_id
    )
    .unwrap()
    .is_none());
    assert!(
        PoSAccountingStorageRead::<TipStorageTag>::get_pool_balance(&tf.storage, new_pool_id)
            .unwrap()
            .is_some()
    );
}

// Check that modifying staker destination in ProduceBlockFromStake is allowed before the corresponding
// fork and prohibited afterwards.
// 1) The fork height is a few blocks (zero is possible too) after the height 2 (where the chain
// switches to PoS).
// All block after height 2 are produces by the same pool.
// 2) Produce blocks until the fork height is reached, changing the staker destination in each block.
// 3) At the fork height try producing a block changing the staker destination - it fails.
// 4) Produce a few more blocks without changing the destination - it succeeds.
// 5) Try producing a block changing the staker destination again - it still fails.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn staker_destination_change(#[case] seed: Seed) {
    use staker_destination_change_test_utils::*;

    let mut rng = make_seedable_rng(seed);

    let pos_height = BlockHeight::new(2);
    let block_count_before_fork = rng.gen_range(0..(TEST_EPOCH_LENGTH.get() * 3));
    let fork_height = BlockHeight::new(pos_height.into_int() + block_count_before_fork);
    let chain_config = ConfigBuilder::test_chain()
        .consensus_upgrades(consensus_upgrades_with_pos_at_height(pos_height))
        .epoch_length(TEST_EPOCH_LENGTH)
        .sealed_epoch_distance_from_tip(TEST_SEALED_EPOCH_DISTANCE)
        .chainstate_upgrades(
            NetUpgrades::initialize(vec![
                (
                    BlockHeight::zero(),
                    ChainstateUpgradeBuilder::latest()
                        .staker_destination_update_forbidden(StakerDestinationUpdateForbidden::No)
                        .build(),
                ),
                (
                    fork_height,
                    ChainstateUpgradeBuilder::latest()
                        .staker_destination_update_forbidden(StakerDestinationUpdateForbidden::Yes)
                        .build(),
                ),
            ])
            .unwrap(),
        )
        .build();

    let mut tf = TestFramework::builder(&mut rng).with_chain_config(chain_config).build();

    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (stake_pool_data, initial_staking_sk) = create_stake_pool_data_with_all_reward_to_staker(
        &mut rng,
        tf.chainstate.get_chain_config().min_stake_pool_pledge(),
        vrf_pk,
    );
    let (initial_stake_pool_outpoint, pool_id) =
        add_block_with_stake_pool(&mut rng, &mut tf, stake_pool_data);

    let mut stake_pool_outpoint = initial_stake_pool_outpoint;
    let mut pool_balance = tf.chainstate.get_chain_config().min_stake_pool_pledge();

    let (staking_destination, staking_sk) = {
        let initial_block_height = tf.best_block_index().block_height().next_height();

        let mut staking_destination =
            Destination::PublicKey(PublicKey::from_private_key(&initial_staking_sk));
        let mut staking_sk = initial_staking_sk.clone();

        for new_block_height in initial_block_height.iter_up_to(fork_height) {
            let (next_staking_sk, next_staking_pk) =
                PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
            let next_staking_destination = Destination::PublicKey(next_staking_pk);

            let (pos_data, block_timestamp, reward_outputs) = pos_mine(
                &tf,
                pool_id,
                staking_destination,
                &staking_sk,
                next_staking_destination.clone(),
                &vrf_sk,
                stake_pool_outpoint,
                &mut rng,
            );

            let block_id = *tf
                .make_block_builder()
                .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
                .with_block_signing_key(staking_sk)
                .with_timestamp(block_timestamp)
                .with_reward(reward_outputs)
                .build_and_process(&mut rng)
                .unwrap()
                .unwrap()
                .block_id();

            let new_pool_balance =
                PoSAccountingStorageRead::<TipStorageTag>::get_pool_balance(&tf.storage, pool_id)
                    .unwrap()
                    .unwrap();
            let subsidy =
                tf.chainstate.get_chain_config().block_subsidy_at_height(&new_block_height);
            let expected_pool_balance = (pool_balance + subsidy).unwrap();
            assert_eq!(new_pool_balance, expected_pool_balance);

            staking_destination = next_staking_destination;
            staking_sk = next_staking_sk;
            stake_pool_outpoint =
                UtxoOutPoint::new(OutPointSourceId::BlockReward(block_id.into()), 0);
            pool_balance = new_pool_balance;

            tf.progress_time_seconds_since_epoch(rng.gen_range(1..10));
        }

        (staking_destination, staking_sk)
    };

    let new_block_height = tf.best_block_index().block_height().next_height();
    // Sanity check
    assert_eq!(new_block_height, fork_height);

    // The fork height has been reached, so attempts to change the staking destination should fail.
    {
        let (_, next_staking_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let next_staking_destination = Destination::PublicKey(next_staking_pk);

        let (pos_data, block_timestamp, reward_outputs) = pos_mine(
            &tf,
            pool_id,
            staking_destination.clone(),
            &staking_sk,
            next_staking_destination,
            &vrf_sk,
            stake_pool_outpoint.clone(),
            &mut rng,
        );

        let err = tf
            .make_block_builder()
            .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
            .with_block_signing_key(staking_sk.clone())
            .with_timestamp(block_timestamp)
            .with_reward(reward_outputs)
            .build_and_process(&mut rng)
            .unwrap_err();

        assert_matches!(
            err,
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ProduceBlockFromStakeChangesStakerDestination(_, _)
            ))
        );
    }

    // Produce a few blocks without changing the staking destination.
    let block_count_after_fork = rng.gen_range(0..(TEST_EPOCH_LENGTH.get() * 3));
    for _ in 0..block_count_after_fork {
        let (pos_data, block_timestamp, reward_outputs) = pos_mine(
            &tf,
            pool_id,
            staking_destination.clone(),
            &staking_sk,
            staking_destination.clone(),
            &vrf_sk,
            stake_pool_outpoint,
            &mut rng,
        );

        let block_id = *tf
            .make_block_builder()
            .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
            .with_block_signing_key(staking_sk.clone())
            .with_timestamp(block_timestamp)
            .with_reward(reward_outputs)
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap()
            .block_id();

        let new_pool_balance =
            PoSAccountingStorageRead::<TipStorageTag>::get_pool_balance(&tf.storage, pool_id)
                .unwrap()
                .unwrap();
        let subsidy = tf.chainstate.get_chain_config().block_subsidy_at_height(&new_block_height);
        let expected_pool_balance = (pool_balance + subsidy).unwrap();
        assert_eq!(new_pool_balance, expected_pool_balance);

        stake_pool_outpoint = UtxoOutPoint::new(OutPointSourceId::BlockReward(block_id.into()), 0);
        pool_balance = new_pool_balance;

        tf.progress_time_seconds_since_epoch(rng.gen_range(1..10));
    }

    // Attempt to change the destination again - it still fails.
    {
        let (_, next_staking_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let next_staking_destination = Destination::PublicKey(next_staking_pk);

        let (pos_data, block_timestamp, reward_outputs) = pos_mine(
            &tf,
            pool_id,
            staking_destination,
            &staking_sk,
            next_staking_destination,
            &vrf_sk,
            stake_pool_outpoint,
            &mut rng,
        );

        let err = tf
            .make_block_builder()
            .with_consensus_data(ConsensusData::PoS(Box::new(pos_data)))
            .with_block_signing_key(staking_sk)
            .with_timestamp(block_timestamp)
            .with_reward(reward_outputs)
            .build_and_process(&mut rng)
            .unwrap_err();

        assert_matches!(
            err,
            ChainstateError::ProcessBlockError(BlockError::StateUpdateFailed(
                ConnectTransactionError::ProduceBlockFromStakeChangesStakerDestination(_, _)
            ))
        );
    }
}

mod staker_destination_change_test_utils {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    pub fn pos_mine(
        tf: &TestFramework,
        pool_id: PoolId,
        cur_staking_destination: Destination,
        cur_staking_sk: &PrivateKey,
        next_staking_destination: Destination,
        vrf_sk: &VRFPrivateKey,
        kernel_outpoint: UtxoOutPoint,
        rng: &mut (impl Rng + CryptoRng),
    ) -> (PoSData, BlockTimestamp, Vec<TxOutput>) {
        let reward_outputs =
            vec![TxOutput::ProduceBlockFromStake(next_staking_destination, pool_id)];

        let kernel_sig = produce_kernel_signature(
            rng,
            tf,
            cur_staking_sk,
            reward_outputs.as_slice(),
            cur_staking_destination,
            tf.best_block_id(),
            kernel_outpoint.clone(),
        );

        let chain_config = tf.chainstate.get_chain_config();
        let new_block_height = tf.best_block_index().block_height().next_height();
        let current_difficulty = calculate_new_target(tf, new_block_height).unwrap();
        let final_supply = chain_config.final_supply().unwrap();
        let epoch_index = chain_config.epoch_index_from_height(&new_block_height);
        let randomness = tf.pos_randomness_for_height(&new_block_height);

        let (pos_data, block_timestamp) = chainstate_test_framework::pos_mine(
            rng,
            &tf.storage.transaction_ro().unwrap(),
            &get_pos_chain_config(chain_config, new_block_height),
            BlockTimestamp::from_time(tf.current_time()),
            kernel_outpoint,
            InputWitness::Standard(kernel_sig),
            vrf_sk,
            randomness,
            pool_id,
            final_supply,
            epoch_index,
            current_difficulty,
        )
        .unwrap();

        (pos_data, block_timestamp, reward_outputs)
    }
}
