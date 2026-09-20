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
use chainstate_test_framework::{TestFramework, pos_mine};
use chainstate_types::{BlockSeal, pos_randomness::PoSRandomness};
use common::{
    chain::{
        Destination, PoolId, TxOutput, UtxoOutPoint,
        block::{ConsensusData, timestamp::BlockTimestamp},
        signature::inputsig::InputWitness,
    },
    primitives::{BlockHeight, Id, Idable},
};
use crypto::{
    key::{PrivateKey, PublicKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use randomness::CryptoRng;
use test_utils::random::{Seed, make_seedable_rng};

use super::helpers::pos::{
    calculate_new_target, get_pos_chain_config, produce_kernel_signature,
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

// Create a chain genesis <- block_1(StakePool), then process two blocks (block_2a and
// block_2b) that carry the same PoS seal (same pool and same VRF output) on top of
// block_1. Both blocks are fully valid; block_2b remains a side block.
// Check that the seal is indexed for both blocks and that the evidence recorded for the
// block on which the seal was seen for the second time retains both signed headers.
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
    let expected_block_height = BlockHeight::new(2);
    assert_eq!(
        index_entry.blocks(),
        &[(block_id_a, expected_block_height), (block_id_b, expected_block_height),]
    );

    // The evidence is recorded for the block on which the seal was seen for the second
    // time and it retains the signed headers of both blocks.
    assert!(db_tx.get_duplicate_seal_evidence(&block_id_a).unwrap().is_none());
    let evidence = db_tx.get_duplicate_seal_evidence(&block_id_b).unwrap().unwrap();
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

    let (seal, block_id_a, block_id_b) = process_two_blocks_with_same_seal(
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
    assert!(db_tx.get_duplicate_seal_evidence(&block_id_b).unwrap().is_none());
}
