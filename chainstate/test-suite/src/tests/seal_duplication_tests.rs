// Copyright (c) 2026 RBB S.r.l
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

//! Tests for the indexing of PoS block seals and the recording of duplicate seal evidence.

use std::time::Duration;

use rstest::rstest;

use chainstate::{BlockSource, ChainstateConfig};
use chainstate_storage::{BlockchainStorageRead, Transactional as _};
use chainstate_test_framework::{
    TestFramework, TestFrameworkBuilder, pos_mine,
    produce_kernel_signature as produce_block_reward_kernel_signature,
};
use chainstate_types::{BlockSeal, pos_randomness::PoSRandomness};
use common::{
    chain::{
        ChainConfig, Destination, OutPointSourceId, PoolId, TxInput, TxOutput, UtxoOutPoint,
        block::{ConsensusData, consensus_data::PoSData, timestamp::BlockTimestamp},
        config::Builder as ConfigBuilder,
        signature::inputsig::InputWitness,
    },
    primitives::{Id, Idable},
};
use crypto::{
    key::{PrivateKey, PublicKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use randomness::CryptoRng;
use test_utils::random::{Seed, make_seedable_rng};

use super::helpers::pos::{
    FIRST_POS_BLOCK_HEIGHT, add_block_with_stake_pool, calculate_new_target,
    calculate_new_target_for_chain, consensus_upgrades_with_pos_at_height, get_pos_chain_config,
    produce_kernel_signature, setup_chain_with_stake_pool,
    setup_chain_with_stake_pool_with_chainstate_config,
};

/// Mine two PoS consensus datas for the same slot by calling `pos_mine` twice with
/// byte-identical arguments. The same arguments make the mining find the same timestamp,
/// and thus produce the same VRF output (which identifies the seal), while the VRF proof
/// bytes differ between the two signings.
///
/// Both blocks are built on top of the same parent and processed as fully valid blocks;
/// the second one becomes a side block of the first one.
///
/// Returns the common seal and the ids of the two processed blocks.
fn process_two_blocks_with_same_seal(
    rng: &mut impl CryptoRng,
    tf: &mut TestFramework,
    vrf_sk: &VRFPrivateKey,
    stake_pool_outpoint: &UtxoOutPoint,
    pool_id: PoolId,
    staking_sk: &PrivateKey,
) -> (
    BlockSeal,
    Id<common::chain::Block>,
    Id<common::chain::Block>,
) {
    let staking_destination = Destination::PublicKey(PublicKey::from_private_key(staking_sk));
    let reward_outputs =
        vec![TxOutput::ProduceBlockFromStake(staking_destination.clone(), pool_id)];

    let kernel_sig = produce_kernel_signature(
        rng,
        tf,
        staking_sk,
        reward_outputs.as_slice(),
        staking_destination,
        stake_pool_outpoint.clone(),
    );

    let chain_config = tf.chainstate.get_chain_config();
    let initial_randomness = chain_config.initial_randomness();
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(tf, new_block_height).unwrap();
    let final_supply = chain_config.final_supply().unwrap();
    let pos_config = get_pos_chain_config(chain_config, new_block_height);
    let initial_timestamp = BlockTimestamp::from_time(tf.current_time());
    let parent_id = tf.best_block_id();

    let (pos_data_1, block_timestamp_1) = pos_mine(
        rng,
        &tf.storage.transaction_ro().unwrap(),
        &pos_config,
        initial_timestamp,
        stake_pool_outpoint.clone(),
        InputWitness::Standard(kernel_sig.clone()),
        vrf_sk,
        PoSRandomness::new(initial_randomness),
        pool_id,
        final_supply,
        1,
        current_difficulty,
    )
    .expect("should be able to mine");

    let (pos_data_2, block_timestamp_2) = pos_mine(
        rng,
        &tf.storage.transaction_ro().unwrap(),
        &pos_config,
        initial_timestamp,
        stake_pool_outpoint.clone(),
        InputWitness::Standard(kernel_sig),
        vrf_sk,
        PoSRandomness::new(initial_randomness),
        pool_id,
        final_supply,
        1,
        current_difficulty,
    )
    .expect("should be able to mine");

    assert_eq!(block_timestamp_1, block_timestamp_2);
    // The VRF proofs differ, because they are randomized, but the VRF outputs, and thus
    // the seals, must be identical.
    assert_ne!(pos_data_1.vrf_data(), pos_data_2.vrf_data());

    let consensus_data_1 = ConsensusData::PoS(pos_data_1.into());
    let consensus_data_2 = ConsensusData::PoS(pos_data_2.into());

    let seal = BlockSeal::from_consensus_data(&consensus_data_1).unwrap();
    assert_eq!(
        BlockSeal::from_consensus_data(&consensus_data_2),
        Some(seal.clone())
    );

    let block_1 = tf
        .make_block_builder()
        .with_parent(parent_id)
        .with_consensus_data(consensus_data_1)
        .with_block_signing_key(staking_sk.clone())
        .with_timestamp(block_timestamp_1)
        .with_reward(reward_outputs.clone())
        .build(rng);
    let block_id_1 = block_1.get_id();
    tf.process_block(block_1, BlockSource::Local).unwrap();

    let block_2 = tf
        .make_block_builder()
        .with_parent(parent_id)
        .with_consensus_data(consensus_data_2)
        .with_block_signing_key(staking_sk.clone())
        .with_timestamp(block_timestamp_2)
        .with_reward(reward_outputs)
        .build(rng);
    let block_id_2 = block_2.get_id();
    assert_ne!(block_id_1, block_id_2);
    tf.process_block(block_2, BlockSource::Local).unwrap();

    (seal, block_id_1, block_id_2)
}

/// Mine and process two same-seal PoS blocks on top of the given parent (both
/// fully valid, the second one a side block of the first one), mirroring
/// `process_two_blocks_with_same_seal` but with an explicit parent, so twins
/// can be released on side branches and below the current tip.
#[allow(clippy::too_many_arguments)]
fn mine_and_process_same_seal_twins_on_parent(
    rng: &mut impl CryptoRng,
    tf: &mut TestFramework,
    vrf_sk: &VRFPrivateKey,
    stake_pool_outpoint: &UtxoOutPoint,
    pool_id: PoolId,
    staking_sk: &PrivateKey,
    parent_id: Id<common::chain::Block>,
    timestamp_offset_seconds: u64,
    process_second: bool,
) -> (
    BlockSeal,
    Id<common::chain::Block>,
    Id<common::chain::Block>,
    Option<common::chain::Block>,
) {
    let staking_destination = Destination::PublicKey(PublicKey::from_private_key(staking_sk));
    let reward_outputs =
        vec![TxOutput::ProduceBlockFromStake(staking_destination.clone(), pool_id)];

    // The kernel depends on the parent: a PoS parent's stake lives in its
    // `ProduceBlockFromStake` reward output (the pool creation output was
    // consumed by the first PoS block of the chain), while a non-PoS parent
    // leaves the pool creation output in place. The PoS-ness of the parent is
    // detected via its block-reward outputs, which is exact for every parent
    // shape used in this suite.
    let parent_reward_outpoint =
        UtxoOutPoint::new(OutPointSourceId::BlockReward(parent_id.into()), 0);
    let parent_reward_outputs = tf.outputs_from_genblock(parent_id.into());
    let parent_is_pos = parent_reward_outputs
        .get(&OutPointSourceId::BlockReward(parent_id.into()))
        .is_some_and(|outputs| !outputs.is_empty());

    let chain_config = tf.chainstate.get_chain_config();
    let parent_height = tf
        .storage
        .transaction_ro()
        .unwrap()
        .get_block_index(&parent_id)
        .unwrap()
        .expect("parent block index is present")
        .block_height();
    let new_block_height = parent_height.next_height();
    let pos_randomness = tf.pos_randomness_for_height(&new_block_height);
    let current_difficulty =
        calculate_new_target_for_chain(tf, &parent_id.into(), new_block_height).unwrap();
    let final_supply = chain_config.final_supply().unwrap();
    let pos_config = get_pos_chain_config(chain_config, new_block_height);
    let initial_timestamp = BlockTimestamp::from_time(tf.current_time())
        .add_int_seconds(timestamp_offset_seconds)
        .unwrap();
    let epoch_index = chain_config.epoch_index_from_height(&new_block_height);

    let (kernel_sig, kernel_outpoint) = if parent_is_pos {
        let kernel_outpoint = parent_reward_outpoint.clone();
        let kernel_sig = produce_block_reward_kernel_signature(
            tf,
            rng,
            staking_sk,
            reward_outputs.as_slice(),
            staking_destination.clone(),
            parent_id.into(),
            kernel_outpoint.clone(),
        );
        (kernel_sig, kernel_outpoint)
    } else {
        let kernel_outpoint = stake_pool_outpoint.clone();
        let kernel_sig = produce_kernel_signature(
            rng,
            tf,
            staking_sk,
            reward_outputs.as_slice(),
            staking_destination.clone(),
            kernel_outpoint.clone(),
        );
        (kernel_sig, kernel_outpoint)
    };

    let (pos_data_1, block_timestamp_1) = pos_mine(
        rng,
        &tf.storage.transaction_ro().unwrap(),
        &pos_config,
        initial_timestamp,
        kernel_outpoint.clone(),
        InputWitness::Standard(kernel_sig.clone()),
        vrf_sk,
        pos_randomness,
        pool_id,
        final_supply,
        epoch_index,
        current_difficulty,
    )
    .expect("should be able to mine");

    let (pos_data_2, block_timestamp_2) = pos_mine(
        rng,
        &tf.storage.transaction_ro().unwrap(),
        &pos_config,
        initial_timestamp,
        kernel_outpoint,
        InputWitness::Standard(kernel_sig),
        vrf_sk,
        pos_randomness,
        pool_id,
        final_supply,
        epoch_index,
        current_difficulty,
    )
    .expect("should be able to mine");

    assert_eq!(block_timestamp_1, block_timestamp_2);
    // The VRF proofs differ (they are randomized per signing), so the blocks
    // are distinct while sharing the seal.
    assert_ne!(pos_data_1.vrf_data(), pos_data_2.vrf_data());

    let consensus_data_1 = ConsensusData::PoS(pos_data_1.into());
    let consensus_data_2 = ConsensusData::PoS(pos_data_2.into());
    let seal = BlockSeal::from_consensus_data(&consensus_data_1).unwrap();
    assert_eq!(
        BlockSeal::from_consensus_data(&consensus_data_2),
        Some(seal.clone())
    );

    let block_1 = tf
        .make_block_builder()
        .with_parent(parent_id.into())
        .with_consensus_data(consensus_data_1)
        .with_block_signing_key(staking_sk.clone())
        .with_timestamp(block_timestamp_1)
        .with_reward(reward_outputs.clone())
        .build(rng);
    let block_id_1 = block_1.get_id();
    tf.process_block(block_1, BlockSource::Local).unwrap();

    let block_2 = tf
        .make_block_builder()
        .with_parent(parent_id.into())
        .with_consensus_data(consensus_data_2)
        .with_block_signing_key(staking_sk.clone())
        .with_timestamp(block_timestamp_2)
        .with_reward(reward_outputs)
        .build(rng);
    let block_id_2 = block_2.get_id();
    assert_ne!(block_id_1, block_id_2);
    if process_second {
        tf.process_block(block_2.clone(), BlockSource::Local).unwrap();
        (seal, block_id_1, block_id_2, None)
    } else {
        (seal, block_id_1, block_id_2, Some(block_2))
    }
}

// Create a chain genesis <- block_1(StakePool), then process two blocks (block_2a and
// block_2b) that carry the same PoS seal (same pool and same VRF output) on top of
// block_1. Both blocks are fully valid; block_2b remains a side block.
// Check that the seal is indexed for both blocks and that the single evidence
// record of the seal retains both signed headers.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn duplicate_pos_seal_records_evidence(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (mut tf, stake_pool_outpoint, pool_id, staking_sk) =
        setup_chain_with_stake_pool(&mut rng, vrf_pk);

    let (seal, block_id_a, block_id_b) = process_two_blocks_with_same_seal(
        &mut rng,
        &mut tf,
        &vrf_sk,
        &stake_pool_outpoint,
        pool_id,
        &staking_sk,
    );

    // The second block must not have replaced the first one as the best block.
    assert_eq!(
        tf.best_block_id(),
        Id::<common::chain::GenBlock>::from(block_id_a)
    );

    let db_tx = tf.storage.transaction_ro().unwrap();

    // The seal index contains both blocks at the same height.
    let index_entry = db_tx.get_seal_index_entry(&seal).unwrap().unwrap();
    assert_eq!(index_entry.seal(), &seal);
    let expected_block_height = FIRST_POS_BLOCK_HEIGHT;
    assert_eq!(
        index_entry.blocks(),
        &[(block_id_a, expected_block_height), (block_id_b, expected_block_height),]
    );

    // The evidence is recorded per seal: a single record keyed by the seal
    // itself retains the signed headers of both blocks.
    let evidence = db_tx.get_duplicate_seal_evidence(&seal).unwrap().unwrap();
    assert_eq!(evidence.seal(), &seal);
    assert_eq!(
        evidence.headers().iter().map(|header| header.get_id()).collect::<Vec<_>>(),
        vec![block_id_a, block_id_b]
    );
}

// Same as `duplicate_pos_seal_records_evidence`, but with the seal tracking disabled in
// the chainstate config. Check that both blocks are still processed as fully valid, but
// neither the seal index nor the evidence is recorded.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn seal_tracking_disabled_records_nothing(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let chainstate_config = ChainstateConfig {
        pos_seal_duplication_tracking: false.into(),
        // The gate defaults to enabled on this testnet-type chain; disabling the
        // tracking with the gate on is now rejected at initialization.
        pos_seal_activation_gate: Some(false),
        ..Default::default()
    };
    let (mut tf, stake_pool_outpoint, pool_id, staking_sk) =
        setup_chain_with_stake_pool_with_chainstate_config(&mut rng, vrf_pk, chainstate_config);

    let (seal, block_id_a, _block_id_b) = process_two_blocks_with_same_seal(
        &mut rng,
        &mut tf,
        &vrf_sk,
        &stake_pool_outpoint,
        pool_id,
        &staking_sk,
    );

    assert_eq!(
        tf.best_block_id(),
        Id::<common::chain::GenBlock>::from(block_id_a)
    );

    let db_tx = tf.storage.transaction_ro().unwrap();
    assert!(db_tx.get_seal_index_entry(&seal).unwrap().is_none());
    assert!(db_tx.get_duplicate_seal_evidence(&seal).unwrap().is_none());
}

// Create a chain genesis <- block_1(StakePool), then process two blocks (block_2a and
// block_2b) that carry the same PoS seal, with block_2b remaining a side block (see
// `process_two_blocks_with_same_seal`). Then extend the branch of block_2b with a child
// block, which makes it the best chain and triggers a reorg that disconnects block_2a.
// Check that the seal records survive the reorg: they are not rolled back on disconnect,
// so the seal is still indexed for both blocks and the evidence recorded for the seal
// still retains both signed headers.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn duplicate_seal_records_survive_reorg(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (mut tf, stake_pool_outpoint, pool_id, staking_sk) =
        setup_chain_with_stake_pool(&mut rng, vrf_pk);

    let (seal, block_id_a, block_id_b) = process_two_blocks_with_same_seal(
        &mut rng,
        &mut tf,
        &vrf_sk,
        &stake_pool_outpoint,
        pool_id,
        &staking_sk,
    );

    // block_2a is the tip and block_2b is its side sibling.
    assert_eq!(
        tf.best_block_id(),
        Id::<common::chain::GenBlock>::from(block_id_a)
    );

    // Advance the time, so that the child block below is staked in a different slot
    // and thus carries a different seal than the one under test.
    tf.progress_time_seconds_since_epoch(30);

    // Extend the branch of block_2b with a child block, which makes it the best chain
    // and triggers a reorg that disconnects block_2a.
    let child_index = tf
        .make_pos_block_builder()
        .with_parent(block_id_b.into())
        .with_stake_pool_id(pool_id)
        .with_stake_spending_key(staking_sk)
        .with_vrf_key(vrf_sk)
        .build_and_process(&mut rng)
        .unwrap()
        .unwrap();
    assert_eq!(
        tf.best_block_id(),
        Id::<common::chain::GenBlock>::from(*child_index.block_id())
    );

    let db_tx = tf.storage.transaction_ro().unwrap();

    // The seal index still contains both blocks at the same height; in particular,
    // the record of the disconnected block_2a was not rolled back.
    let index_entry = db_tx.get_seal_index_entry(&seal).unwrap().unwrap();
    let expected_block_height = FIRST_POS_BLOCK_HEIGHT;
    assert_eq!(
        index_entry.blocks(),
        &[(block_id_a, expected_block_height), (block_id_b, expected_block_height),]
    );

    // The evidence recorded for the seal survived the reorg as well.
    let evidence = db_tx.get_duplicate_seal_evidence(&seal).unwrap().unwrap();
    assert_eq!(evidence.seal(), &seal);
    assert_eq!(
        evidence.headers().iter().map(|header| header.get_id()).collect::<Vec<_>>(),
        vec![block_id_a, block_id_b]
    );
}

// ---------------------------------------------------------------
// PoS seal activation gate
//
// The gate (enabled by default on testnet chains -- which includes the
// testnet-type chains this suite builds -- and disabled by default elsewhere)
// refuses to activate a chain whose newly activated segment consists entirely
// of blocks reusing already-known PoS consensus proofs. It never fires on a
// segment that contains at least one block with a fresh proof, and it is
// bypassed only for the reorgs of the user-initiated block invalidation path.

/// The contradictory combination (gate enabled, tracking disabled) is refused
/// at chainstate initialization instead of silently neutralizing the gate.
#[test]
#[should_panic(expected = "SealActivationGateWithoutTracking")]
fn gate_enabled_without_tracking_is_rejected() {
    let mut rng = test_utils::random::make_seedable_rng(Seed::from_entropy());
    let (_vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

    let chainstate_config = ChainstateConfig {
        pos_seal_duplication_tracking: false.into(),
        pos_seal_activation_gate: Some(true),
        ..Default::default()
    };

    let _tf =
        setup_chain_with_stake_pool_with_chainstate_config(&mut rng, vrf_pk, chainstate_config);
}

fn gate_enabled_config() -> ChainstateConfig {
    ChainstateConfig {
        pos_seal_activation_gate: true.into(),
        ..Default::default()
    }
}

/// Mine a fresh-proof PoS block on top of `parent_id` without processing
/// it. The block is mined from a timestamp well after the current framework
/// time, so its seal (which binds the timestamp) differs from the seals of all
/// previously processed blocks. The kernel signature is produced against the
/// current tip's UTXO set, so siblings of a non-PoS parent must all be mined
/// before any of them is processed.
#[allow(clippy::too_many_arguments)]
fn mine_pos_block_on_parent(
    rng: &mut impl CryptoRng,
    tf: &mut TestFramework,
    vrf_sk: &VRFPrivateKey,
    stake_pool_outpoint: &UtxoOutPoint,
    pool_id: PoolId,
    staking_sk: &PrivateKey,
    parent_id: Id<common::chain::Block>,
    timestamp_offset_seconds: u64,
) -> common::chain::Block {
    let staking_destination = Destination::PublicKey(PublicKey::from_private_key(staking_sk));
    let reward_outputs =
        vec![TxOutput::ProduceBlockFromStake(staking_destination.clone(), pool_id)];

    // The kernel depends on the parent: a PoS parent's stake lives in its
    // `ProduceBlockFromStake` reward output (the pool creation output was
    // consumed by the first PoS block of the chain), while a non-PoS parent
    // leaves the pool creation output in place.
    let parent_reward_outpoint =
        UtxoOutPoint::new(OutPointSourceId::BlockReward(parent_id.into()), 0);
    let parent_reward_outputs = tf.outputs_from_genblock(parent_id.into());
    let parent_is_pos = parent_reward_outputs
        .get(&OutPointSourceId::BlockReward(parent_id.into()))
        .is_some_and(|outputs| !outputs.is_empty());

    let chain_config = tf.chainstate.get_chain_config();
    let parent_height = tf
        .storage
        .transaction_ro()
        .unwrap()
        .get_block_index(&parent_id)
        .unwrap()
        .expect("parent block index is present")
        .block_height();
    let new_block_height = parent_height.next_height();
    let epoch_index = chain_config.epoch_index_from_height(&new_block_height);
    let pos_randomness = tf.pos_randomness_for_height(&new_block_height);
    let current_difficulty =
        calculate_new_target_for_chain(tf, &parent_id.into(), new_block_height).unwrap();
    let final_supply = chain_config.final_supply().unwrap();
    let pos_config = get_pos_chain_config(chain_config, new_block_height);
    let initial_timestamp = BlockTimestamp::from_time(tf.current_time())
        .add_int_seconds(timestamp_offset_seconds)
        .unwrap();

    let (kernel_sig, kernel_outpoint) = if parent_is_pos {
        let kernel_sig = produce_block_reward_kernel_signature(
            tf,
            rng,
            staking_sk,
            reward_outputs.as_slice(),
            staking_destination.clone(),
            parent_id.into(),
            parent_reward_outpoint.clone(),
        );
        (kernel_sig, parent_reward_outpoint)
    } else {
        let kernel_sig = produce_kernel_signature(
            rng,
            tf,
            staking_sk,
            reward_outputs.as_slice(),
            staking_destination.clone(),
            stake_pool_outpoint.clone(),
        );
        (kernel_sig, stake_pool_outpoint.clone())
    };

    let (pos_data, block_timestamp) = pos_mine(
        rng,
        &tf.storage.transaction_ro().unwrap(),
        &pos_config,
        initial_timestamp,
        kernel_outpoint,
        InputWitness::Standard(kernel_sig),
        vrf_sk,
        pos_randomness,
        pool_id,
        final_supply,
        epoch_index,
        current_difficulty,
    )
    .expect("should be able to mine");

    tf.make_block_builder()
        .with_parent(parent_id.into())
        .with_consensus_data(ConsensusData::PoS(pos_data.into()))
        .with_block_signing_key(staking_sk.clone())
        .with_timestamp(block_timestamp)
        .with_reward(reward_outputs.clone())
        .build(rng)
}

/// Mine (`mine_pos_block_on_parent`) and process a fresh-proof PoS block on
/// top of `parent_id`. Returns the new block's id.
#[allow(clippy::too_many_arguments)]
fn mine_and_process_fresh_proof_block(
    rng: &mut impl CryptoRng,
    tf: &mut TestFramework,
    vrf_sk: &VRFPrivateKey,
    stake_pool_outpoint: &UtxoOutPoint,
    pool_id: PoolId,
    staking_sk: &PrivateKey,
    parent_id: Id<common::chain::Block>,
    timestamp_offset_seconds: u64,
) -> Id<common::chain::Block> {
    let block = mine_pos_block_on_parent(
        rng,
        tf,
        vrf_sk,
        stake_pool_outpoint,
        pool_id,
        staking_sk,
        parent_id,
        timestamp_offset_seconds,
    );
    let block_id = block.get_id();
    tf.process_block(block, BlockSource::Local).unwrap();
    block_id
}

/// A test chain with a long epoch, so the VRF transcript of a block stays
/// valid at later heights (it binds the epoch index): the proof of a block
/// mined at one height is also valid at the next one.
fn long_epoch_chain_config() -> ChainConfig {
    ConfigBuilder::test_chain()
        .consensus_upgrades(consensus_upgrades_with_pos_at_height(
            FIRST_POS_BLOCK_HEIGHT,
        ))
        .epoch_length(std::num::NonZeroU64::new(100).unwrap())
        .sealed_epoch_distance_from_tip(0)
        .build()
}

/// Mines the incumbent chain of the reused-proof scenarios on top of the pool
/// block: A at the first PoS height (search start 60 s after the current
/// time), B as its child (61 s), and the losing sibling C of B at a later
/// timestamp (100 s). B stays the tip and C is stored as a side block, the
/// so far single sighting of its seal. Returns the ids of B and C.
fn mine_incumbent_with_losing_sibling(
    rng: &mut impl CryptoRng,
    tf: &mut TestFramework,
    vrf_sk: &VRFPrivateKey,
    stake_pool_outpoint: &UtxoOutPoint,
    pool_id: PoolId,
    staking_sk: &PrivateKey,
) -> (Id<common::chain::Block>, Id<common::chain::Block>) {
    let pool_block = tf
        .best_block_id()
        .classify(tf.chainstate.get_chain_config())
        .chain_block_id()
        .unwrap();
    let block_a = mine_and_process_fresh_proof_block(
        rng,
        tf,
        vrf_sk,
        stake_pool_outpoint,
        pool_id,
        staking_sk,
        pool_block,
        60,
    );
    let block_b = mine_and_process_fresh_proof_block(
        rng,
        tf,
        vrf_sk,
        stake_pool_outpoint,
        pool_id,
        staking_sk,
        block_a,
        61,
    );
    let block_c = mine_and_process_fresh_proof_block(
        rng,
        tf,
        vrf_sk,
        stake_pool_outpoint,
        pool_id,
        staking_sk,
        block_a,
        100,
    );
    (block_b, block_c)
}

/// Gate on: a duplicate-proof side twin extended by a block with a fresh proof
/// reorganizes the chain. The candidate segment contains a fresh proof, so the
/// gate must not fire and the duplicate-proof block is activated together with
/// its fresh child under the ordinary trust comparison.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn activation_gate_does_not_block_segment_with_fresh_proof(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (mut tf, stake_pool_outpoint, pool_id, staking_sk) =
        setup_chain_with_stake_pool_with_chainstate_config(&mut rng, vrf_pk, gate_enabled_config());

    let (_, _twin_main_id, twin_side_id) = process_two_blocks_with_same_seal(
        &mut rng,
        &mut tf,
        &vrf_sk,
        &stake_pool_outpoint,
        pool_id,
        &staking_sk,
    );

    let fresh_id = mine_and_process_fresh_proof_block(
        &mut rng,
        &mut tf,
        &vrf_sk,
        &stake_pool_outpoint,
        pool_id,
        &staking_sk,
        twin_side_id,
        90,
    );

    assert_eq!(
        tf.best_block_id(),
        Id::<common::chain::GenBlock>::from(fresh_id)
    );
}

/// Gate on: after the user-initiated invalidation of the mainchain twin, the
/// recovery re-activates the best remaining chain even though its segment is a
/// single duplicate-proof block (the gate is bypassed for the invalidation
/// recovery; without the bypass this activation would be refused).
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn activation_gate_bypassed_for_invalidation_recovery(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (mut tf, stake_pool_outpoint, pool_id, staking_sk) =
        setup_chain_with_stake_pool_with_chainstate_config(&mut rng, vrf_pk, gate_enabled_config());

    let (_, twin_main_id, twin_side_id) = process_two_blocks_with_same_seal(
        &mut rng,
        &mut tf,
        &vrf_sk,
        &stake_pool_outpoint,
        pool_id,
        &staking_sk,
    );

    tf.chainstate.invalidate_block(&twin_main_id).unwrap();

    assert_eq!(
        tf.best_block_id(),
        Id::<common::chain::GenBlock>::from(twin_side_id)
    );
}

// ---------------------------------------------------------------
// Containment suite for the PoS seal activation gate
//
// Reuse scenarios: tip equivocation races, withheld-variant release,
// partition halves, honest resealing, and the variant cap. The gate never
// fires on segments that contain at least one fresh proof, never prevents
// the storage or retrieval of any variant, and leaves the ordinary trust
// comparison in charge of every race that contains a fresh proof.
// ---------------------------------------------------------------

/// Tip equivocation race: the pool equivocates at two consecutive heights and
/// both branches grow. The branch that collects a fresh proof first wins, the
/// loser's twin becomes a side block, and the gate never fires (every winning
/// segment contains the fresh proof that decided the race). Evidence is
/// recorded for both equivocated proofs.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn equivocation_race_converges_via_fresh_proofs(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (mut tf, stake_pool_outpoint, pool_id, staking_sk) =
        setup_chain_with_stake_pool_with_chainstate_config(&mut rng, vrf_pk, gate_enabled_config());

    let (seal2, _twin_main, twin_side) = process_two_blocks_with_same_seal(
        &mut rng,
        &mut tf,
        &vrf_sk,
        &stake_pool_outpoint,
        pool_id,
        &staking_sk,
    );

    // The side branch collects a fresh proof and wins the race.
    let fresh_on_side = mine_and_process_fresh_proof_block(
        &mut rng,
        &mut tf,
        &vrf_sk,
        &stake_pool_outpoint,
        pool_id,
        &staking_sk,
        twin_side,
        60,
    );
    assert_eq!(
        tf.best_block_id(),
        Id::<common::chain::GenBlock>::from(fresh_on_side)
    );

    // The pool equivocates again on the new tip: the first-processed twin wins
    // the next round under the ordinary trust comparison.
    let (seal3, twin3_main, _twin3_side, _unprocessed3) =
        mine_and_process_same_seal_twins_on_parent(
            &mut rng,
            &mut tf,
            &vrf_sk,
            &stake_pool_outpoint,
            pool_id,
            &staking_sk,
            fresh_on_side,
            100,
            true,
        );
    assert_eq!(
        tf.best_block_id(),
        Id::<common::chain::GenBlock>::from(twin3_main)
    );

    // Both equivocated proofs carry their own evidence record.
    let db_tx = tf.storage.transaction_ro().unwrap();
    assert_eq!(
        db_tx.get_seal_index_entry(&seal2).unwrap().unwrap().blocks().len(),
        2
    );
    assert_eq!(
        db_tx.get_seal_index_entry(&seal3).unwrap().unwrap().blocks().len(),
        2
    );
    assert!(db_tx.get_duplicate_seal_evidence(&seal2).unwrap().is_some());
    assert!(db_tx.get_duplicate_seal_evidence(&seal3).unwrap().is_some());
}

/// Withheld-variant release: a duplicate variant released after the incumbent
/// chain has moved on never displaces the incumbent (its segment has lower
/// trust), stays stored, and keeps its evidence record.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn withheld_variant_release_keeps_incumbent_stable(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (mut tf, stake_pool_outpoint, pool_id, staking_sk) =
        setup_chain_with_stake_pool_with_chainstate_config(&mut rng, vrf_pk, gate_enabled_config());

    // Mine the twins, but withhold the second one (do not process it yet).
    let withheld_parent = tf
        .best_block_id()
        .classify(tf.chainstate.get_chain_config())
        .chain_block_id()
        .unwrap();
    let (seal, twin_main, _twin_side, withheld_block) = mine_and_process_same_seal_twins_on_parent(
        &mut rng,
        &mut tf,
        &vrf_sk,
        &stake_pool_outpoint,
        pool_id,
        &staking_sk,
        withheld_parent,
        0,
        false,
    );
    let withheld_block = withheld_block.expect("the second twin is withheld, not processed");
    let withheld_id = withheld_block.get_id();

    // The incumbent chain extends with a fresh proof.
    let fresh_id = mine_and_process_fresh_proof_block(
        &mut rng,
        &mut tf,
        &vrf_sk,
        &stake_pool_outpoint,
        pool_id,
        &staking_sk,
        twin_main,
        60,
    );

    // The withheld variant is released: it is stored and its evidence exists,
    // but it never displaces the incumbent chain.
    tf.process_block(withheld_block, BlockSource::Local).unwrap();

    assert_eq!(
        tf.best_block_id(),
        Id::<common::chain::GenBlock>::from(fresh_id)
    );

    let db_tx = tf.storage.transaction_ro().unwrap();
    let index_entry = db_tx.get_seal_index_entry(&seal).unwrap().unwrap();
    assert_eq!(index_entry.blocks().len(), 2);
    let stored = db_tx.get_block(&withheld_id).unwrap().unwrap();
    assert_eq!(stored.get_id(), withheld_id);
    assert!(db_tx.get_duplicate_seal_evidence(&seal).unwrap().is_some());
}

/// Partition halves: two identical nodes (same keys, same pool, same chain)
/// receive the two variants of an equivocation in opposite orders. Each node
/// keeps the variant it saw first as its tip (there is no content-based
/// canonicalization), every variant stays stored in both halves (no first-seen
/// drop), both halves record the evidence, and the index retains the arrival
/// order of the sightings. The halves keep their own valid chains:
/// convergence comes from fresh proofs of other pools (see
/// `equivocation_race_converges_via_fresh_proofs`).
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn partition_halves_stay_valid_without_canonicalization(#[case] seed: Seed) {
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(
        &mut test_utils::random::make_seedable_rng(seed),
        VRFKeyKind::Schnorrkel,
    );

    // Two identical setups (same seed, same keys, same pool).
    let mut rng1 = make_seedable_rng(seed);
    let mut rng2 = make_seedable_rng(seed);
    let (mut tf1, stake_pool_outpoint1, pool_id1, staking_sk1) =
        setup_chain_with_stake_pool_with_chainstate_config(
            &mut rng1,
            vrf_pk.clone(),
            gate_enabled_config(),
        );
    let (mut tf2, ..) = setup_chain_with_stake_pool_with_chainstate_config(
        &mut rng2,
        vrf_pk,
        gate_enabled_config(),
    );

    // The two variants are mined on the first node, the second one withheld.
    // They share the seal (the VRF output, whose transcript binds the pool,
    // the epoch randomness and the timestamp but not the signing RNG) and
    // differ in their VRF proof bytes, so they are distinct blocks. Both
    // halves share the pool block, so the same blocks are valid on both.
    let parent = tf1
        .best_block_id()
        .classify(tf1.chainstate.get_chain_config())
        .chain_block_id()
        .unwrap();
    assert_eq!(
        tf2.best_block_id(),
        Id::<common::chain::GenBlock>::from(parent),
        "the two halves must share the pool block"
    );
    let mut rng = make_seedable_rng(seed);
    let (seal, variant_1, variant_2, withheld) = mine_and_process_same_seal_twins_on_parent(
        &mut rng,
        &mut tf1,
        &vrf_sk,
        &stake_pool_outpoint1,
        pool_id1,
        &staking_sk1,
        parent,
        0,
        false,
    );
    assert_ne!(variant_1, variant_2);
    let variant_2_block = withheld.expect("the second twin is withheld, not processed");

    // Half 1 receives the second variant after the first one; half 2 receives
    // it first and the first variant after it.
    tf1.process_block(variant_2_block.clone(), BlockSource::Local).unwrap();
    tf2.process_block(variant_2_block, BlockSource::Local).unwrap();
    let variant_1_block =
        tf1.storage.transaction_ro().unwrap().get_block(&variant_1).unwrap().unwrap();
    tf2.process_block(variant_1_block, BlockSource::Local).unwrap();

    // Each half keeps the variant it saw first as the tip: the choice is
    // arrival-order based, never content-based.
    assert_eq!(
        tf1.best_block_id(),
        Id::<common::chain::GenBlock>::from(variant_1)
    );
    assert_eq!(
        tf2.best_block_id(),
        Id::<common::chain::GenBlock>::from(variant_2)
    );

    // Both halves recorded the evidence and stored every variant, with the
    // index retaining the arrival order of the sightings.
    for (db_tx, first, second) in [
        (tf1.storage.transaction_ro().unwrap(), variant_1, variant_2),
        (tf2.storage.transaction_ro().unwrap(), variant_2, variant_1),
    ] {
        let index_entry = db_tx.get_seal_index_entry(&seal).unwrap().unwrap();
        assert_eq!(index_entry.blocks().len(), 2);
        assert_eq!(index_entry.blocks()[0].0, first);
        assert_eq!(index_entry.blocks()[1].0, second);
        assert!(db_tx.get_block(&first).unwrap().is_some());
        assert!(db_tx.get_block(&second).unwrap().is_some());
        assert!(db_tx.get_duplicate_seal_evidence(&seal).unwrap().is_some());
    }
}

/// Honest resealing: the same pool produces blocks for consecutive heights with
/// different timestamps (e.g. after one of its blocks was orphaned). The two
/// blocks carry different proofs, are not duplicates of each other, produce no
/// evidence, and are both accepted on the main chain.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn honest_reseal_at_consecutive_heights_is_not_flagged(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (mut tf, stake_pool_outpoint, pool_id, staking_sk) =
        setup_chain_with_stake_pool_with_chainstate_config(&mut rng, vrf_pk, gate_enabled_config());

    // First reseal: the pool creation output is still unspent (no PoS block
    // has been produced yet), so the block is mined with the tx-based kernel.
    let parent = tf
        .best_block_id()
        .classify(tf.chainstate.get_chain_config())
        .chain_block_id()
        .unwrap();
    let staking_destination = Destination::PublicKey(PublicKey::from_private_key(&staking_sk));
    let reward_outputs =
        vec![TxOutput::ProduceBlockFromStake(staking_destination.clone(), pool_id)];
    let kernel_sig = produce_kernel_signature(
        &mut rng,
        &tf,
        &staking_sk,
        reward_outputs.as_slice(),
        staking_destination,
        stake_pool_outpoint.clone(),
    );
    let chain_config = tf.chainstate.get_chain_config();
    let reseal_height = FIRST_POS_BLOCK_HEIGHT;
    let current_difficulty = calculate_new_target(&tf, reseal_height).unwrap();
    let final_supply = chain_config.final_supply().unwrap();
    let pos_config = get_pos_chain_config(chain_config, reseal_height);
    let pos_randomness = tf.pos_randomness_for_height(&reseal_height);
    let (pos_data, block_timestamp) = pos_mine(
        &mut rng,
        &tf.storage.transaction_ro().unwrap(),
        &pos_config,
        BlockTimestamp::from_time(tf.current_time()).add_int_seconds(90).unwrap(),
        stake_pool_outpoint.clone(),
        InputWitness::Standard(kernel_sig),
        &vrf_sk,
        pos_randomness,
        pool_id,
        final_supply,
        1,
        current_difficulty,
    )
    .expect("should be able to mine");
    let first_reseal = tf
        .make_block_builder()
        .with_parent(parent.into())
        .with_consensus_data(ConsensusData::PoS(pos_data.into()))
        .with_block_signing_key(staking_sk.clone())
        .with_timestamp(block_timestamp)
        .with_reward(reward_outputs.clone())
        .build(&mut rng);
    let first_reseal_id = first_reseal.get_id();
    let first_reseal_seal =
        BlockSeal::from_consensus_data(first_reseal.header().consensus_data()).unwrap();
    tf.process_block(first_reseal, BlockSource::Local).unwrap();

    // Second reseal: two minutes later, on top of the first reseal, with the
    // kernel taken from the first reseal's stake reward. A different
    // timestamp gives a different proof, so the two blocks are not duplicates.
    tf.progress_time_seconds_since_epoch(120);
    let second_reseal_id = mine_and_process_fresh_proof_block(
        &mut rng,
        &mut tf,
        &vrf_sk,
        &stake_pool_outpoint,
        pool_id,
        &staking_sk,
        first_reseal_id,
        90,
    );
    let second_reseal = tf
        .storage
        .transaction_ro()
        .unwrap()
        .get_block(&second_reseal_id)
        .unwrap()
        .unwrap();
    let second_reseal_seal =
        BlockSeal::from_consensus_data(second_reseal.header().consensus_data()).unwrap();

    // Both blocks are on the main chain and carry different proofs, each with
    // a single sighting, and no duplicate evidence.
    assert_ne!(first_reseal_seal, second_reseal_seal);
    let db_tx = tf.storage.transaction_ro().unwrap();
    for (height, expected_id, expected_seal) in [
        (reseal_height, first_reseal_id, &first_reseal_seal),
        (
            reseal_height.next_height(),
            second_reseal_id,
            &second_reseal_seal,
        ),
    ] {
        let id_at_height = db_tx.get_block_id_by_height(height).unwrap().unwrap();
        assert_eq!(
            Id::<common::chain::GenBlock>::from(expected_id),
            id_at_height
        );
        let entry = db_tx
            .get_seal_index_entry(expected_seal)
            .unwrap()
            .expect("indexing precedes activation, so the seal of a main chain block is indexed");
        assert_eq!(entry.blocks(), &[(expected_id, height)]);
        assert!(db_tx.get_duplicate_seal_evidence(expected_seal).unwrap().is_none());
    }
}

/// Honest same-timestamp re-seal after an orphan. The pool's block O (slot
/// T_B) is displaced by W (slot T_A < T_B), whose denser timestamp gives it
/// the higher chain trust. The pool's next job starts at the tip's timestamp
/// plus one, and since the VRF output binds the epoch randomness and the
/// timestamp but not the parent, the search from T_A+1 lands on T_B again:
/// the new block N carries O's seal. On every node that saw O the segment [N]
/// is all-duplicate, so its activation is refused once (the tip stays on W
/// while N stays stored), and the chain recovers with its next fresh-seal
/// block.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn honest_same_timestamp_reseal_after_an_orphan_is_refused_once(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

    // A chain with a long epoch, so the orphan (height h+1) and the re-seal
    // (height h+2) share the epoch index and randomness of the VRF transcript.
    let chain_config = long_epoch_chain_config();
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config)
        .with_chainstate_config(gate_enabled_config())
        .build();

    let (stake_pool_data, staking_sk) =
        chainstate_test_framework::create_stake_pool_data_with_all_reward_to_staker(
            &mut rng,
            tf.chainstate.get_chain_config().min_stake_pool_pledge(),
            vrf_pk,
        );
    let (stake_pool_outpoint, pool_id) =
        add_block_with_stake_pool(&mut rng, &mut tf, stake_pool_data);

    let parent = tf
        .best_block_id()
        .classify(tf.chainstate.get_chain_config())
        .chain_block_id()
        .unwrap();
    let now_secs = tf.current_time().as_duration_since_epoch().as_secs();
    // The mining helpers start the timestamp search at the current framework
    // time plus an offset; convert a slot back into that offset.
    let offset_of = |timestamp: BlockTimestamp| timestamp.as_int_seconds() - now_secs;

    // Both siblings are mined before either is processed: the kernel of a
    // sibling of the non-PoS parent is signed against the pool creation
    // output, which the first processed sibling consumes.
    // The orphan O is mined for T_B and the winner W for T_A < T_B.
    let orphan = mine_pos_block_on_parent(
        &mut rng,
        &mut tf,
        &vrf_sk,
        &stake_pool_outpoint,
        pool_id,
        &staking_sk,
        parent,
        1,
    );
    let winner = mine_pos_block_on_parent(
        &mut rng,
        &mut tf,
        &vrf_sk,
        &stake_pool_outpoint,
        pool_id,
        &staking_sk,
        parent,
        0,
    );
    let orphan_id = orphan.get_id();
    let winner_id = winner.get_id();
    let t_b = orphan.header().timestamp();
    let t_a = winner.header().timestamp();
    assert!(
        t_a < t_b,
        "the orphan's slot must be later than the winner's"
    );
    let orphan_seal = BlockSeal::from_consensus_data(orphan.header().consensus_data()).unwrap();

    // O arrives first and is the tip until W arrives.
    tf.process_block(orphan, BlockSource::Local).unwrap();
    assert_eq!(
        tf.best_block_id(),
        Id::<common::chain::GenBlock>::from(orphan_id)
    );

    // W takes over: its denser timestamp gives it the higher chain trust, so
    // O becomes an orphan. The segment [W] carries a fresh proof, so the gate
    // lets the reorg through.
    tf.process_block(winner, BlockSource::Local).unwrap();
    assert_eq!(
        tf.best_block_id(),
        Id::<common::chain::GenBlock>::from(winner_id)
    );

    let db_tx = tf.storage.transaction_ro().unwrap();
    assert_eq!(
        db_tx.get_seal_index_entry(&orphan_seal).unwrap().unwrap().blocks(),
        &[(orphan_id, FIRST_POS_BLOCK_HEIGHT)]
    );
    drop(db_tx);

    // The pool's next block N on top of W, with the search started at T_A+1:
    // it lands on the orphan's slot T_B again, so it carries O's seal.
    let reseal_id = mine_and_process_fresh_proof_block(
        &mut rng,
        &mut tf,
        &vrf_sk,
        &stake_pool_outpoint,
        pool_id,
        &staking_sk,
        winner_id,
        offset_of(t_a) + 1,
    );
    let db_tx = tf.storage.transaction_ro().unwrap();
    let reseal = db_tx.get_block(&reseal_id).unwrap().unwrap();
    assert_eq!(reseal.header().timestamp(), t_b);
    let reseal_seal = BlockSeal::from_consensus_data(reseal.header().consensus_data()).unwrap();
    assert_eq!(reseal_seal, orphan_seal);

    // The activation of [N] is refused: the tip stays on W, N stays stored and
    // its sighting joined the orphan's in the seal index.
    assert_eq!(
        tf.best_block_id(),
        Id::<common::chain::GenBlock>::from(winner_id)
    );
    assert_eq!(
        db_tx.get_seal_index_entry(&reseal_seal).unwrap().unwrap().blocks(),
        &[
            (orphan_id, FIRST_POS_BLOCK_HEIGHT),
            (reseal_id, FIRST_POS_BLOCK_HEIGHT.next_height()),
        ]
    );
    drop(db_tx);

    // The refused chain recovers with its next fresh-seal block: the segment
    // [N, child] contains a fresh proof and activates.
    let fresh_id = mine_and_process_fresh_proof_block(
        &mut rng,
        &mut tf,
        &vrf_sk,
        &stake_pool_outpoint,
        pool_id,
        &staking_sk,
        reseal_id,
        offset_of(t_b) + 1,
    );
    assert_eq!(
        tf.best_block_id(),
        Id::<common::chain::GenBlock>::from(fresh_id)
    );
}

/// Variant cap: a pool reusing one proof across many variants.
/// The index entry stops at the cap, the evidence record stays bounded, every
/// variant stays stored and fully valid, and the first-processed variant is
/// never displaced.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn duplicate_proof_variants_are_capped_but_all_stored(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (mut tf, stake_pool_outpoint, pool_id, staking_sk) =
        setup_chain_with_stake_pool_with_chainstate_config(&mut rng, vrf_pk, gate_enabled_config());

    let staking_destination = Destination::PublicKey(PublicKey::from_private_key(&staking_sk));
    let reward_outputs =
        vec![TxOutput::ProduceBlockFromStake(staking_destination.clone(), pool_id)];

    let kernel_sig = produce_kernel_signature(
        &mut rng,
        &tf,
        &staking_sk,
        reward_outputs.as_slice(),
        staking_destination,
        stake_pool_outpoint.clone(),
    );

    let chain_config = tf.chainstate.get_chain_config();
    let initial_randomness = chain_config.initial_randomness();
    let new_block_height = tf.best_block_index().block_height().next_height();
    let current_difficulty = calculate_new_target(&tf, new_block_height).unwrap();
    let final_supply = chain_config.final_supply().unwrap();
    let pos_config = get_pos_chain_config(chain_config, new_block_height);
    let initial_timestamp = BlockTimestamp::from_time(tf.current_time());
    let parent_id = tf
        .best_block_id()
        .classify(tf.chainstate.get_chain_config())
        .chain_block_id()
        .unwrap();

    // Mine and process one more variant than the cap (the seal index cap is 8
    // entries per proof; see `MAX_BLOCKS_PER_SEAL` in the chainstate crate).
    let variant_count = 8 + 1;
    let mut variant_ids = Vec::new();
    let mut seal = None;
    for _ in 0..variant_count {
        let (pos_data, block_timestamp) = pos_mine(
            &mut rng,
            &tf.storage.transaction_ro().unwrap(),
            &pos_config,
            initial_timestamp,
            stake_pool_outpoint.clone(),
            InputWitness::Standard(kernel_sig.clone()),
            &vrf_sk,
            PoSRandomness::new(initial_randomness),
            pool_id,
            final_supply,
            1,
            current_difficulty,
        )
        .expect("should be able to mine");

        let consensus_data = ConsensusData::PoS(pos_data.into());
        let this_seal = BlockSeal::from_consensus_data(&consensus_data).unwrap();
        match &seal {
            Some(s) => assert_eq!(s, &this_seal),
            None => seal = Some(this_seal),
        }

        let block = tf
            .make_block_builder()
            .with_parent(parent_id.into())
            .with_consensus_data(consensus_data)
            .with_block_signing_key(staking_sk.clone())
            .with_timestamp(block_timestamp)
            .with_reward(reward_outputs.clone())
            .build(&mut rng);
        let block_id = block.get_id();
        tf.process_block(block, BlockSource::Local).unwrap();
        variant_ids.push(block_id);
    }
    let seal = seal.unwrap();

    // The first-processed variant remains the best chain.
    assert_eq!(
        tf.best_block_id(),
        Id::<common::chain::GenBlock>::from(variant_ids[0])
    );

    // The index entry is capped; every variant is stored; the evidence exists.
    let db_tx = tf.storage.transaction_ro().unwrap();
    let index_entry = db_tx.get_seal_index_entry(&seal).unwrap().unwrap();
    assert_eq!(index_entry.blocks().len(), 8);
    // The index retains the first 8 variants in arrival order; the ninth stays
    // stored but is no longer indexed.
    assert_eq!(
        index_entry.blocks().iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        variant_ids[..8].to_vec(),
    );
    for block_id in &variant_ids {
        assert!(
            db_tx.get_block(block_id).unwrap().is_some(),
            "variant {block_id} must be stored",
        );
    }
    let evidence = db_tx.get_duplicate_seal_evidence(&seal).unwrap().unwrap();
    // Sightings 2..=8 extend the evidence to exactly the cap; the ninth
    // sighting is log-only.
    assert_eq!(evidence.headers().len(), 8);
}

/// A same-pool chain keeps progressing (with decayed trust): the asymptote
/// weights each block by its timestamp gap, so sparse same-pool progress adds
/// less trust but never makes such blocks invalid or their chains stuck.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn same_pool_chain_keeps_progressing(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
    let (mut tf, stake_pool_outpoint, pool_id, staking_sk) =
        setup_chain_with_stake_pool_with_chainstate_config(&mut rng, vrf_pk, gate_enabled_config());

    let (_, twin_main, _twin_side) = process_two_blocks_with_same_seal(
        &mut rng,
        &mut tf,
        &vrf_sk,
        &stake_pool_outpoint,
        pool_id,
        &staking_sk,
    );

    // Two consecutive same-pool blocks on the winning branch: the tip advances
    // with each one.
    let h3 = mine_and_process_fresh_proof_block(
        &mut rng,
        &mut tf,
        &vrf_sk,
        &stake_pool_outpoint,
        pool_id,
        &staking_sk,
        twin_main,
        1,
    );
    assert_eq!(tf.best_block_id(), Id::<common::chain::GenBlock>::from(h3));

    let h4 = mine_and_process_fresh_proof_block(
        &mut rng,
        &mut tf,
        &vrf_sk,
        &stake_pool_outpoint,
        pool_id,
        &staking_sk,
        h3,
        2,
    );
    assert_eq!(tf.best_block_id(), Id::<common::chain::GenBlock>::from(h4));

    // The reseals carry distinct proofs: each seal has a single sighting and
    // no evidence record (honest same-pool progress is never flagged).
    let db_tx_seals = tf.storage.transaction_ro().unwrap();
    let seal_h3 = BlockSeal::from_consensus_data(
        db_tx_seals.get_block(&h3).unwrap().unwrap().header().consensus_data(),
    )
    .unwrap();
    let seal_h4 = BlockSeal::from_consensus_data(
        db_tx_seals.get_block(&h4).unwrap().unwrap().header().consensus_data(),
    )
    .unwrap();
    assert_ne!(seal_h3, seal_h4);
    let db_tx = tf.storage.transaction_ro().unwrap();
    for (block_id, seal) in [(h3, &seal_h3), (h4, &seal_h4)] {
        let entry = db_tx
            .get_seal_index_entry(seal)
            .unwrap()
            .expect("indexing precedes activation, so the seal of a main chain block is indexed");
        assert_eq!(
            entry.blocks().len(),
            1,
            "a single same-pool block must not be a duplicate sighting"
        );
        assert_eq!(entry.blocks()[0].0, block_id);
        assert!(db_tx.get_duplicate_seal_evidence(seal).unwrap().is_none());
    }
}

// Note on mining-based constructions: a twin-only chain has trust exactly
// equal to the incumbent (the strict trust comparison never attempts it), so
// twins alone never reach the gate. The refusal is reached by a grafted
// copied proof: a block whose consensus data re-uses the VRF data of an
// already-sighted block (the seal binds the pool, the epoch randomness and
// the timestamp, not the parent or the block content), built as an
// extension of the incumbent chain (see the test below); or by an honest
// same-slot re-seal (see the test above).

/// The gate's refusal in normal block processing. The seal binds the pool,
/// the epoch randomness and the block timestamp, but not the parent or the
/// block content, so a block whose consensus data re-uses the VRF data of an
/// already-sighted block extends the incumbent chain with a strictly higher
/// trust while carrying a duplicate proof. The epoch length of this chain is
/// large enough that the copied block's transcript (epoch, randomness,
/// timestamp) is also valid at the new height.
///
/// With the gate enabled, the activation of this chain is refused: the tip
/// stays on the incumbent, the reworked block stays stored, and the reused
/// proof carries its evidence record. With the gate disabled, the same block
/// activates and becomes the new tip.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn activation_gate_refuses_reused_proof_extension(#[case] seed: Seed) {
    // Gate on: the extension is refused; the incumbent stays the best chain.
    let (best_with_gate, reworked_id, incumbent_id) =
        run_reused_proof_extension_scenario(seed, true);
    assert_eq!(
        best_with_gate,
        Id::<common::chain::GenBlock>::from(incumbent_id)
    );
    assert_ne!(incumbent_id, reworked_id);

    // Gate off: the same extension activates and becomes the best chain (the
    // refusal above is the gate's doing, not a validation failure).
    let (best_without_gate, reworked_id_off, incumbent_id_off) =
        run_reused_proof_extension_scenario(seed, false);
    assert_eq!(reworked_id_off, reworked_id);
    assert_eq!(incumbent_id_off, incumbent_id);
    assert_eq!(
        best_without_gate,
        Id::<common::chain::GenBlock>::from(reworked_id)
    );
}

/// Gate on, node in the initial block download: the gate is not bypassed
/// while syncing. A node restarted from a storage whose tip is older than
/// `max_tip_age` is back in the initial block download; the reused-proof
/// extension of the incumbent chain is refused there exactly as it is outside
/// of the initial block download (the tip does not move), and a fresh-seal
/// child then activates the chain, its fresh tip ending the initial block
/// download with it.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn activation_gate_is_not_bypassed_during_initial_block_download(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

    let chain_config = long_epoch_chain_config();
    // A tip older than one second is stale, so a node whose tip is not within
    // the last second stays in the initial block download.
    let chainstate_config = ChainstateConfig {
        max_tip_age: Duration::from_secs(1).into(),
        ..gate_enabled_config()
    };
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config)
        .with_chainstate_config(chainstate_config)
        .with_initial_time_since_genesis(2)
        .build();
    // Two seconds after genesis the genesis tip is stale: the node starts in
    // the initial block download.
    assert!(tf.chainstate.is_initial_block_download());

    let (stake_pool_data, staking_sk) =
        chainstate_test_framework::create_stake_pool_data_with_all_reward_to_staker(
            &mut rng,
            tf.chainstate.get_chain_config().min_stake_pool_pledge(),
            vrf_pk,
        );
    let (stake_pool_outpoint, pool_id) =
        add_block_with_stake_pool(&mut rng, &mut tf, stake_pool_data);
    // The pool block is mined at the current mock time, so its tip is fresh
    // and already ends the initial block download.
    assert!(!tf.chainstate.is_initial_block_download());

    let staking_destination = Destination::PublicKey(PublicKey::from_private_key(&staking_sk));
    let reward_outputs =
        vec![TxOutput::ProduceBlockFromStake(staking_destination.clone(), pool_id)];

    // The incumbent chain A, B and the losing sibling C, as in the
    // reused-proof-extension scenario.
    let (block_b, block_c) = mine_incumbent_with_losing_sibling(
        &mut rng,
        &mut tf,
        &vrf_sk,
        &stake_pool_outpoint,
        pool_id,
        &staking_sk,
    );
    assert_eq!(
        tf.best_block_id(),
        Id::<common::chain::GenBlock>::from(block_b)
    );

    // The node is restarted from its storage once its tip has gone stale: the
    // recreated node is in the initial block download again.
    let tip_timestamp = tf
        .storage
        .transaction_ro()
        .unwrap()
        .get_block(&block_b)
        .unwrap()
        .unwrap()
        .header()
        .timestamp();
    let now_secs = tf.current_time().as_duration_since_epoch().as_secs();
    tf.progress_time_seconds_since_epoch(tip_timestamp.as_int_seconds() - now_secs + 2);
    let mut tf = TestFrameworkBuilder::from_existing_framework(tf).build();
    assert!(tf.chainstate.is_initial_block_download());

    // The reused-proof extension D of the incumbent chain is refused while the
    // node is in the initial block download: the tip stays on B, D is stored,
    // and the stale tip keeps the node in the initial block download.
    let reworked_id = graft_reused_proof_block(
        &mut rng,
        &mut tf,
        &staking_sk,
        staking_destination,
        reward_outputs,
        block_b,
        block_c,
        pool_id,
    );
    assert_eq!(
        tf.best_block_id(),
        Id::<common::chain::GenBlock>::from(block_b)
    );
    assert!(tf.storage.transaction_ro().unwrap().get_block(&reworked_id).unwrap().is_some());
    assert!(tf.chainstate.is_initial_block_download());

    // A fresh-seal child activates the refused chain, and its fresh tip ends
    // the initial block download.
    let fresh_id = mine_and_process_fresh_proof_block(
        &mut rng,
        &mut tf,
        &vrf_sk,
        &stake_pool_outpoint,
        pool_id,
        &staking_sk,
        reworked_id,
        110,
    );
    assert_eq!(
        tf.best_block_id(),
        Id::<common::chain::GenBlock>::from(fresh_id)
    );
    assert!(!tf.chainstate.is_initial_block_download());
}

/// Sightings are permanent: invalidating one of the twin blocks does not
/// launder the reused seal. After the operator invalidates the side block
/// whose VRF proof the reworked block re-uses, a further reworked block
/// re-using the same proof still forms an all-duplicate segment, and its
/// chain activation stays refused.
///
/// This pins the deliberate fail-closed semantics of the gate: the seal
/// index is a historical sighting record, so entries are not pruned (and
/// invalid partners are not skipped in the classification). Counting only
/// valid partners would let an attacker make a reused seal look unique
/// again by having one of its twins invalidated, re-opening the
/// trust-inflation construction the gate exists to refuse. Honest chains
/// are affected only by the one-block same-slot re-seal refusal (see
/// `honest_same_timestamp_reseal_after_an_orphan_is_refused_once`), which
/// self-heals with the next fresh-seal block.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn invalidated_partner_does_not_launder_a_reused_seal(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

    let chain_config = long_epoch_chain_config();
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config)
        .with_chainstate_config(gate_enabled_config())
        .build();

    let (stake_pool_data, staking_sk) =
        chainstate_test_framework::create_stake_pool_data_with_all_reward_to_staker(
            &mut rng,
            tf.chainstate.get_chain_config().min_stake_pool_pledge(),
            vrf_pk,
        );
    let (stake_pool_outpoint, pool_id) =
        add_block_with_stake_pool(&mut rng, &mut tf, stake_pool_data);

    let staking_destination = Destination::PublicKey(PublicKey::from_private_key(&staking_sk));
    let reward_outputs =
        vec![TxOutput::ProduceBlockFromStake(staking_destination.clone(), pool_id)];

    // The incumbent chain: the pool block, then A, then B on top of it, and
    // the losing sibling C of B, the first sighting of the seal that gets
    // reused.
    let (block_b, block_c) = mine_incumbent_with_losing_sibling(
        &mut rng,
        &mut tf,
        &vrf_sk,
        &stake_pool_outpoint,
        pool_id,
        &staking_sk,
    );

    // The first reworked block: B's child re-using C's VRF data. It is
    // fully valid and has strictly higher trust than the incumbent, but its
    // segment is all-duplicate, so the gate refuses the activation.
    let reworked_id = graft_reused_proof_block(
        &mut rng,
        &mut tf,
        &staking_sk,
        staking_destination.clone(),
        reward_outputs.clone(),
        block_b,
        block_c,
        pool_id,
    );
    assert_eq!(
        tf.best_block_id(),
        Id::<common::chain::GenBlock>::from(block_b)
    );

    // The operator invalidates the side block C -- the only other sighting
    // of the reworked block's seal apart from the reworked blocks
    // themselves.
    tf.chainstate.invalidate_block(&block_c).unwrap();

    // The seal index is not pruned by the invalidation: the sightings are a
    // historical record.
    let reused_seal = {
        let db_tx = tf.storage.transaction_ro().unwrap();
        let c_block = db_tx.get_block(&block_c).unwrap().unwrap();
        BlockSeal::from_consensus_data(c_block.header().consensus_data()).unwrap()
    };
    {
        let db_tx = tf.storage.transaction_ro().unwrap();
        let entry = db_tx.get_seal_index_entry(&reused_seal).unwrap().unwrap();
        assert!(entry.blocks().iter().any(|(id, _)| id == &block_c));
    }

    // A second reworked block: another child of B, re-using the same VRF
    // data again (a distinct block via its reward outputs). Even though the
    // invalidated C can no longer be part of any acceptable chain, the new
    // segment consists of reused proofs only, and its activation stays
    // refused.
    let alternate_reward_outputs =
        vec![TxOutput::ProduceBlockFromStake(Destination::AnyoneCanSpend, pool_id)];
    let reworked_id_2 = graft_reused_proof_block(
        &mut rng,
        &mut tf,
        &staking_sk,
        staking_destination,
        alternate_reward_outputs,
        block_b,
        block_c,
        pool_id,
    );
    assert_eq!(
        tf.best_block_id(),
        Id::<common::chain::GenBlock>::from(block_b)
    );
    // The second reworked block is fully valid and stays stored; only its
    // activation was refused.
    assert!(
        tf.storage
            .transaction_ro()
            .unwrap()
            .get_block(&reworked_id_2)
            .unwrap()
            .is_some()
    );

    // The refused chain recovers as usual as soon as it gains a block with a
    // fresh seal: the gate never permanently strands a chain.
    let fresh_extension = mine_and_process_fresh_proof_block(
        &mut rng,
        &mut tf,
        &vrf_sk,
        &stake_pool_outpoint,
        pool_id,
        &staking_sk,
        reworked_id,
        110,
    );
    assert_eq!(
        tf.best_block_id(),
        Id::<common::chain::GenBlock>::from(fresh_extension)
    );
}

/// Builds and processes a block that is a child of `parent` and whose
/// consensus data re-uses the VRF data of `proof_source` (a stored side
/// block), with the target required at the new height. Returns the new
/// block's id.
#[allow(clippy::too_many_arguments)]
fn graft_reused_proof_block(
    rng: &mut impl CryptoRng,
    tf: &mut TestFramework,
    staking_sk: &PrivateKey,
    staking_destination: Destination,
    reward_outputs: Vec<TxOutput>,
    parent: Id<common::chain::Block>,
    proof_source: Id<common::chain::Block>,
    pool_id: PoolId,
) -> Id<common::chain::Block> {
    let source_block =
        tf.storage.transaction_ro().unwrap().get_block(&proof_source).unwrap().unwrap();
    let source_pos_data = match source_block.header().consensus_data() {
        ConsensusData::PoS(data) => data,
        _ => panic!("the proof source is a PoS block"),
    };
    let source_timestamp = source_block.header().timestamp();

    let kernel_outpoint = UtxoOutPoint::new(OutPointSourceId::BlockReward(parent.into()), 0);
    let kernel_sig = produce_block_reward_kernel_signature(
        tf,
        rng,
        staking_sk,
        reward_outputs.as_slice(),
        staking_destination,
        parent.into(),
        kernel_outpoint.clone(),
    );

    let parent_height = tf
        .storage
        .transaction_ro()
        .unwrap()
        .get_block_index(&parent)
        .unwrap()
        .unwrap()
        .block_height();
    let next_height = parent_height.next_height();
    let required_target = calculate_new_target_for_chain(tf, &parent.into(), next_height).unwrap();

    let pos_data = PoSData::new(
        vec![TxInput::from_utxo(kernel_outpoint.source_id(), kernel_outpoint.output_index())],
        vec![InputWitness::Standard(kernel_sig)],
        pool_id,
        source_pos_data.vrf_data().clone(),
        required_target,
    );

    let block = tf
        .make_block_builder()
        .with_parent(parent.into())
        .with_consensus_data(ConsensusData::PoS(pos_data.into()))
        .with_block_signing_key(staking_sk.clone())
        .with_timestamp(source_timestamp)
        .with_reward(reward_outputs)
        .build(rng);
    let block_id = block.get_id();

    tf.process_block(block, BlockSource::Local).unwrap();
    block_id
}

/// Runs the reused-proof-extension scenario deterministically: mines the
/// incumbent chain (A, then B on A), a losing sibling C of B at a later
/// timestamp, and the reworked block D (B's child carrying C's VRF data).
/// Returns the best block id, the reworked block id and the incumbent tip id.
fn run_reused_proof_extension_scenario(
    seed: Seed,
    gate_enabled: bool,
) -> (
    Id<common::chain::GenBlock>,
    Id<common::chain::Block>,
    Id<common::chain::Block>,
) {
    let mut rng = make_seedable_rng(seed);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

    let chain_config = long_epoch_chain_config();
    let chainstate_config = if gate_enabled {
        gate_enabled_config()
    } else {
        ChainstateConfig {
            pos_seal_duplication_tracking: true.into(),
            // Explicitly disabled: the unit-test chain builder uses the testnet
            // chain type, where the gate now defaults to enabled.
            pos_seal_activation_gate: Some(false),
            ..Default::default()
        }
    };
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config)
        .with_chainstate_config(chainstate_config)
        .build();

    let (stake_pool_data, staking_sk) =
        chainstate_test_framework::create_stake_pool_data_with_all_reward_to_staker(
            &mut rng,
            tf.chainstate.get_chain_config().min_stake_pool_pledge(),
            vrf_pk,
        );
    let (stake_pool_outpoint, pool_id) =
        add_block_with_stake_pool(&mut rng, &mut tf, stake_pool_data);

    let staking_destination = Destination::PublicKey(PublicKey::from_private_key(&staking_sk));
    let reward_outputs =
        vec![TxOutput::ProduceBlockFromStake(staking_destination.clone(), pool_id)];

    // The incumbent chain: A at the first PoS height, B as its child, and the
    // losing sibling C of B at a later timestamp (stored as a side block, and
    // its proof is the so far single sighting of its seal).
    let (block_b, block_c) = mine_incumbent_with_losing_sibling(
        &mut rng,
        &mut tf,
        &vrf_sk,
        &stake_pool_outpoint,
        pool_id,
        &staking_sk,
    );
    assert_eq!(
        tf.best_block_id(),
        Id::<common::chain::GenBlock>::from(block_b)
    );

    // The reworked block: B's child whose consensus data re-uses the VRF data
    // of the side block (the transcript does not bind the parent, the height
    // or the block content), with the target required at the new height. It is
    // a fully valid block that carries strictly higher trust than the
    // incumbent chain; it is accepted, and whether its chain is activated
    // depends on the gate.
    let reworked_id = graft_reused_proof_block(
        &mut rng,
        &mut tf,
        &staking_sk,
        staking_destination,
        reward_outputs,
        block_b,
        block_c,
        pool_id,
    );

    // The reworked block stays stored either way, its seal is the side
    // block's, and the reused proof carries its evidence record with both
    // signed headers.
    let db_tx = tf.storage.transaction_ro().unwrap();
    let reworked_block = db_tx.get_block(&reworked_id).unwrap().unwrap();
    let c_block = db_tx.get_block(&block_c).unwrap().unwrap();
    let reused_seal =
        BlockSeal::from_consensus_data(reworked_block.header().consensus_data()).unwrap();
    assert_eq!(
        Some(reused_seal.clone()),
        BlockSeal::from_consensus_data(c_block.header().consensus_data())
    );
    let index_entry = db_tx.get_seal_index_entry(&reused_seal).unwrap().unwrap();
    assert_eq!(index_entry.blocks().len(), 2);
    let evidence = db_tx.get_duplicate_seal_evidence(&reused_seal).unwrap().unwrap();
    assert_eq!(
        evidence.headers().iter().map(|header| header.get_id()).collect::<Vec<_>>(),
        vec![block_c, reworked_id],
    );
    drop(db_tx);

    (tf.best_block_id(), reworked_id, block_b)
}
