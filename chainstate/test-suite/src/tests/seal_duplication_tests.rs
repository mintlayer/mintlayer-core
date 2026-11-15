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

use rstest::rstest;

use chainstate::{BlockSource, ChainstateConfig};
use chainstate_storage::{BlockchainStorageRead, Transactional as _};
use chainstate_test_framework::{
    TestFramework, pos_mine, produce_kernel_signature as produce_block_reward_kernel_signature,
};
use chainstate_types::{BlockSeal, pos_randomness::PoSRandomness};
use common::{
    chain::{
        Destination, OutPointSourceId, PoolId, TxOutput, UtxoOutPoint,
        block::{ConsensusData, timestamp::BlockTimestamp},
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
    FIRST_POS_BLOCK_HEIGHT, calculate_new_target, get_pos_chain_config, produce_kernel_signature,
    setup_chain_with_stake_pool, setup_chain_with_stake_pool_with_chainstate_config,
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
    let current_difficulty = calculate_new_target(tf, new_block_height).unwrap();
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
// The gate (disabled by default in this release) refuses to activate a chain
// whose newly activated segment consists entirely of blocks reusing
// already-known PoS consensus proofs. It never fires on a segment that
// contains at least one block with a fresh proof, and it is bypassed for the
// initial block download and for the reorgs of the user-initiated block
// invalidation path.

fn gate_enabled_config() -> ChainstateConfig {
    ChainstateConfig {
        pos_seal_activation_gate: true.into(),
        ..Default::default()
    }
}

/// Mine and process a fresh-proof PoS block on top of `parent_id`. The block is
/// mined from a timestamp well after the current framework time, so its seal
/// (which binds the timestamp) differs from the seals of all previously
/// processed blocks.
fn mine_and_process_fresh_proof_block(
    rng: &mut impl CryptoRng,
    tf: &mut TestFramework,
    vrf_sk: &VRFPrivateKey,
    pool_id: PoolId,
    staking_sk: &PrivateKey,
    parent_id: Id<common::chain::Block>,
    timestamp_offset_seconds: u64,
) -> Id<common::chain::Block> {
    let staking_destination = Destination::PublicKey(PublicKey::from_private_key(staking_sk));
    let reward_outputs =
        vec![TxOutput::ProduceBlockFromStake(staking_destination.clone(), pool_id)];

    // The kernel of a PoS block that follows another PoS block is the
    // `ProduceBlockFromStake` reward output of that previous block, not the
    // original pool creation output (which the previous block's kernel
    // consumed).
    let kernel_outpoint = UtxoOutPoint::new(OutPointSourceId::BlockReward(parent_id.into()), 0);
    let kernel_sig = produce_block_reward_kernel_signature(
        tf,
        rng,
        staking_sk,
        reward_outputs.as_slice(),
        staking_destination,
        parent_id.into(),
        kernel_outpoint.clone(),
    );

    let chain_config = tf.chainstate.get_chain_config();
    let new_block_height = tf.best_block_index().block_height().next_height();
    let epoch_index = chain_config.epoch_index_from_height(&new_block_height);
    let pos_randomness = tf.pos_randomness_for_height(&new_block_height);
    let current_difficulty = calculate_new_target(tf, new_block_height).unwrap();
    let final_supply = chain_config.final_supply().unwrap();
    let pos_config = get_pos_chain_config(chain_config, new_block_height);
    let initial_timestamp = BlockTimestamp::from_time(tf.current_time())
        .add_int_seconds(timestamp_offset_seconds)
        .unwrap();

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

    let block = tf
        .make_block_builder()
        .with_parent(parent_id.into())
        .with_consensus_data(ConsensusData::PoS(pos_data.into()))
        .with_block_signing_key(staking_sk.clone())
        .with_timestamp(block_timestamp)
        .with_reward(reward_outputs)
        .build(rng);
    let block_id = block.get_id();
    tf.process_block(block, BlockSource::Local).unwrap();
    block_id
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
// S5 — adversarial suite for the PoS seal activation gate
//
// Scenarios derived from the design note's attack narratives: tip
// equivocation races, withheld-variant release, partition halves, honest
// resealing at the same height, and the variant cap. The gate must never
// fire on segments that contain at least one fresh proof, must never
// prevent the storage or retrieval of any variant, and must leave the
// ordinary trust comparison in charge of every race.
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
    let withheld_id = withheld_block.as_ref().map(|b| b.get_id()).unwrap();

    // The incumbent chain extends with a fresh proof.
    let fresh_id = mine_and_process_fresh_proof_block(
        &mut rng,
        &mut tf,
        &vrf_sk,
        pool_id,
        &staking_sk,
        twin_main,
        60,
    );

    // The withheld variant is released: it is stored and its evidence exists,
    // but it never displaces the incumbent chain.
    tf.process_block(withheld_block.unwrap(), BlockSource::Local).unwrap();

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

/// Partition halves: two identical nodes (same keys, same pool) process the
/// two variants of an equivocation in opposite orders, with each node's
/// variants being distinct blocks. The interim tips differ (there is no
/// content-based canonicalization), every variant stays stored in its half
/// (no first-seen drop), and both halves record the evidence. The halves keep
/// their own valid chains: convergence comes from fresh proofs of other pools
/// (see `equivocation_race_converges_via_fresh_proofs`).
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
    let (mut tf2, stake_pool_outpoint2, pool_id2, staking_sk2) =
        setup_chain_with_stake_pool_with_chainstate_config(
            &mut rng2,
            vrf_pk,
            gate_enabled_config(),
        );

    // The two equivocations use different randomness streams, so the halves
    // hold different blocks (different ids) that share the same proof.
    let _parent_1 = tf1
        .best_block_id()
        .classify(tf1.chainstate.get_chain_config())
        .chain_block_id()
        .unwrap();
    let (seal_1, main_1, side_1) = {
        let mut rng = make_seedable_rng(seed);
        let (seal, main, side) = process_two_blocks_with_same_seal(
            &mut rng,
            &mut tf1,
            &vrf_sk,
            &stake_pool_outpoint1,
            pool_id1,
            &staking_sk1,
        );
        (seal, main, side)
    };
    let _parent_2 = tf2
        .best_block_id()
        .classify(tf2.chainstate.get_chain_config())
        .chain_block_id()
        .unwrap();
    let (seal_2, main_2, side_2) = {
        // A different randomness stream: the proofs differ from half 1's, so
        // the variants are different blocks (the seal itself is identical,
        // since the transcript does not involve randomness).
        let mut rng = make_seedable_rng(Seed::from_u64(seed.0 ^ 0xA5A5_A5A5));
        let (seal, main, side) = process_two_blocks_with_same_seal(
            &mut rng,
            &mut tf2,
            &vrf_sk,
            &stake_pool_outpoint2,
            pool_id2,
            &staking_sk2,
        );
        (seal, main, side)
    };
    assert_eq!(seal_1, seal_2);
    assert_ne!(main_1, main_2);

    // Each half keeps its own first-processed variant as the tip: the choice
    // is arrival-order based, never content-based.
    assert_eq!(
        tf1.best_block_id(),
        Id::<common::chain::GenBlock>::from(main_1)
    );
    assert_eq!(
        tf2.best_block_id(),
        Id::<common::chain::GenBlock>::from(main_2)
    );

    // Both halves recorded the evidence and stored every variant, with the
    // index retaining the arrival order of the sightings.
    for (db_tx, main, side) in [
        (tf1.storage.transaction_ro().unwrap(), main_1, side_1),
        (tf2.storage.transaction_ro().unwrap(), main_2, side_2),
    ] {
        let index_entry = db_tx.get_seal_index_entry(&seal_1).unwrap().unwrap();
        assert_eq!(index_entry.blocks().len(), 2);
        assert_eq!(index_entry.blocks()[0].0, main);
        assert_eq!(index_entry.blocks()[1].0, side);
        assert!(db_tx.get_block(&main).unwrap().is_some());
        assert!(db_tx.get_block(&side).unwrap().is_some());
        assert!(db_tx.get_duplicate_seal_evidence(&seal_1).unwrap().is_some());
    }
}

/// Honest resealing: the same pool produces blocks for consecutive heights with
/// different timestamps (e.g. after one of its blocks was orphaned). The two
/// blocks carry different proofs, are not duplicates of each other, produce no
/// evidence, and are both accepted on the main chain.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn honest_reseal_at_same_height_is_not_flagged(#[case] seed: Seed) {
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

    // Both blocks are on the main chain and carry different, unindexed proofs:
    // no seal-index entries with multiplicity, and no duplicate evidence.
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
        let entry = db_tx.get_seal_index_entry(expected_seal).unwrap();
        assert!(
            entry.is_none()
                || entry.as_ref().unwrap().blocks().len() == 1
                    && entry.as_ref().unwrap().blocks()[0].0 == expected_id,
        );
        assert!(db_tx.get_duplicate_seal_evidence(expected_seal).unwrap().is_none());
    }
}

/// Variant cap: an equivocating pool floods the node with same-proof variants.
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
    assert!(evidence.headers().len() <= 8);
}

/// A same-pool chain keeps progressing (with decayed trust): the asymptote
/// penalizes same-pool repeats in the trust comparison but never makes such
/// blocks invalid or their chains stuck.
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
        pool_id,
        &staking_sk,
        twin_main,
        1,
    );
    assert_eq!(tf.best_block_id(), Id::<common::chain::GenBlock>::from(h3));

    let h4 =
        mine_and_process_fresh_proof_block(&mut rng, &mut tf, &vrf_sk, pool_id, &staking_sk, h3, 2);
    assert_eq!(tf.best_block_id(), Id::<common::chain::GenBlock>::from(h4));

    // The reseals carry distinct, unindexed proofs: no seal-index entries with
    // multiplicity and no evidence records (honest same-pool progress is never
    // flagged).
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
    for seal in [&seal_h3, &seal_h4] {
        let entry = db_tx.get_seal_index_entry(seal).unwrap();
        assert!(
            entry.is_none() || entry.as_ref().unwrap().blocks().len() == 1,
            "a single same-pool block must not be a duplicate sighting"
        );
        assert!(db_tx.get_duplicate_seal_evidence(seal).unwrap().is_none());
    }
}
