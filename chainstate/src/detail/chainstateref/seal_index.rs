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

//! Indexing of PoS block seals and recording of duplicate seal evidence.
//!
//! Every block that carries a PoS seal gets its seal indexed. If a seal is seen
//! on more than one block, the signed headers of all the known blocks that carry
//! the seal are retained as a self-certifying evidence record.
//!
//! The index entry of a single seal is capped at [`MAX_BLOCKS_PER_SEAL`] blocks.
//! Once the cap is reached, neither the index entry nor the evidence records of
//! the seal are extended anymore, so the storage footprint of a single reused
//! seal stays bounded. The evidence records that were already recorded are never
//! removed by this module.

use std::num::NonZeroUsize;

use chainstate_storage::BlockchainStorageWrite;
use chainstate_types::{BlockSeal, DuplicateSealEvidence, SealIndexEntry};
use common::{
    chain::Block,
    primitives::{BlockHeight, Id, Idable, id::WithId},
};
use logging::log;
use utils::log_error;

use crate::BlockError;

/// The maximum number of blocks a single seal is indexed for.
// The cap exists to bound the storage and processing costs of seal reuse. It is
// deliberately conservative: honest blocks never share a seal, so the cap only
// matters for deliberately reused seals.
pub const MAX_BLOCKS_PER_SEAL: NonZeroUsize = NonZeroUsize::new(8).unwrap();

/// Index the seal of the given block, recording evidence if the seal was already
/// seen on another block.
///
/// This must be called for every block that has passed all checks, along with its
/// integration into the block tree, so that the seal index covers the blocks of
/// all branches, not only those of the best chain.
#[log_error]
pub fn index_block_seal<S: BlockchainStorageWrite>(
    db_tx: &mut S,
    block: &WithId<Block>,
    block_height: BlockHeight,
) -> Result<(), BlockError> {
    let Some(seal) = BlockSeal::from_consensus_data(block.header().consensus_data()) else {
        return Ok(());
    };

    let block_id: Id<Block> = block.get_id();

    let Some(mut entry) = db_tx.get_seal_index_entry(&seal)? else {
        let entry = SealIndexEntry::new(seal, vec![(block_id, block_height)]);
        db_tx.set_seal_index_entry(entry.seal(), &entry)?;
        return Ok(());
    };

    if entry.blocks().iter().any(|(existing_id, _)| existing_id == &block_id) {
        // The block is already indexed, e.g. because of a retried transaction.
        return Ok(());
    }

    if entry.blocks().len() < MAX_BLOCKS_PER_SEAL.get() {
        record_duplicate_seal_evidence(db_tx, &seal, entry.blocks(), block)?;
        entry.push_block(block_id, block_height);
        db_tx.set_seal_index_entry(entry.seal(), &entry)?;
    } else {
        // The index entry of the seal is at its cap, so the seal reuse is already
        // covered by the recorded evidence. Log the sighting, but do not extend the
        // index and do not record redundant evidence, keeping the storage footprint
        // of a single reused seal bounded.
        log::info!(
            "A PoS seal of pool {} was seen on more than one block; the evidence cap is reached (block {})",
            seal.pool_id(),
            block.get_id(),
        );
    }

    Ok(())
}

/// Retain the headers of the known blocks that carry the given seal, plus the
/// header of the newly seen block, as a duplicate seal evidence record.
fn record_duplicate_seal_evidence<S: BlockchainStorageWrite>(
    db_tx: &mut S,
    seal: &BlockSeal,
    known_blocks: &[(Id<Block>, BlockHeight)],
    block: &WithId<Block>,
) -> Result<(), BlockError> {
    let mut evidence = DuplicateSealEvidence::new(seal.clone(), Vec::new());
    for (existing_id, _) in known_blocks {
        match db_tx.get_block_header(existing_id)? {
            Some(header) => evidence.push_header(header),
            None => {
                // Unreachable in practice: indexed blocks are persisted together with
                // their headers. If it ever happens, retain the rest of the evidence,
                // but make the gap visible instead of silently writing a weak record.
                log::warn!(
                    "The header of the indexed block {} is missing while recording duplicate seal evidence",
                    existing_id
                );
            }
        }
    }
    evidence.push_header(block.header().clone());

    log::info!(
        "A PoS seal of pool {} was seen on more than one block; recorded evidence for block {}",
        seal.pool_id(),
        block.get_id(),
    );

    db_tx.set_duplicate_seal_evidence(&block.get_id(), &evidence)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use super::*;
    use chainstate_storage::mock::MockStoreTxRw;
    use chainstate_types::vrf_tools::construct_transcript;
    use common::{
        chain::{
            Destination, PoolId, TxOutput,
            block::{
                BlockReward, ConsensusData, consensus_data::PoSData, timestamp::BlockTimestamp,
            },
            config::Builder as ConfigBuilder,
            stakelock::StakePoolData,
        },
        primitives::{Amount, Compact, H256, per_thousand::PerThousand},
    };
    use crypto::vrf::{VRFKeyKind, VRFPrivateKey, VRFPublicKey};
    use mockall::predicate::eq;

    const TEST_HEIGHT: BlockHeight = BlockHeight::new(1);

    fn make_pos_block(
        prev_block_id: H256,
        vrf_sk: &VRFPrivateKey,
        vrf_pk: &VRFPublicKey,
        seed: H256,
    ) -> WithId<Block> {
        let chain_config =
            ConfigBuilder::test_chain().epoch_length(NonZeroU64::new(3).unwrap()).build();

        let timestamp = BlockTimestamp::from_int_seconds(1);
        let epoch_index = chain_config.epoch_index_from_height(&TEST_HEIGHT.next_height());
        let transcript = construct_transcript(epoch_index, &seed, timestamp);
        let vrf_data = vrf_sk.produce_vrf_data(transcript);
        let pool_id = PoolId::new(H256::zero());

        let stake_pool_data = StakePoolData::new(
            Amount::from_atoms(1),
            Destination::AnyoneCanSpend,
            vrf_pk.clone(),
            Destination::AnyoneCanSpend,
            PerThousand::new(0).unwrap(),
            Amount::ZERO,
        );
        let reward_output = TxOutput::CreateStakePool(pool_id, Box::new(stake_pool_data));
        let pos_data = PoSData::new(vec![], vec![], pool_id, vrf_data, Compact(1));
        let block = common::chain::Block::new(
            vec![],
            prev_block_id.into(),
            timestamp,
            ConsensusData::PoS(pos_data.into()),
            BlockReward::new(vec![reward_output]),
        )
        .unwrap();
        WithId::new(block)
    }

    #[test]
    fn seal_of_a_pos_block_is_indexed() {
        let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_entropy(VRFKeyKind::Schnorrkel);
        let block = make_pos_block(H256::zero(), &vrf_sk, &vrf_pk, H256::zero());
        let block_id = block.get_id();

        let mut db = MockStoreTxRw::new();
        db.expect_get_seal_index_entry().times(1).return_const(Ok(None));
        db.expect_set_seal_index_entry()
            .times(1)
            .withf(move |seal, entry| {
                entry.seal() == seal && entry.blocks() == [(block_id, TEST_HEIGHT)]
            })
            .return_const(Ok(()));
        db.expect_set_duplicate_seal_evidence().times(0);

        index_block_seal(&mut db, &block, TEST_HEIGHT).unwrap();
    }

    #[test]
    fn seal_of_a_non_pos_block_is_not_indexed() {
        let block = common::chain::Block::new(
            vec![],
            H256::zero().into(),
            BlockTimestamp::from_int_seconds(1),
            ConsensusData::None,
            BlockReward::new(vec![]),
        )
        .unwrap();
        let block = WithId::new(block);

        // No expectations: any storage access fails the test.
        let mut db = MockStoreTxRw::new();

        index_block_seal(&mut db, &block, TEST_HEIGHT).unwrap();
    }

    #[test]
    fn duplicate_seal_records_evidence() {
        let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_entropy(VRFKeyKind::Schnorrkel);
        let seed = H256::zero();
        let block_1 = make_pos_block(H256::zero(), &vrf_sk, &vrf_pk, seed);
        let block_2 = make_pos_block(H256::from([1u8; 32]), &vrf_sk, &vrf_pk, seed);

        assert_ne!(block_1.get_id(), block_2.get_id());
        assert_eq!(
            BlockSeal::from_consensus_data(block_1.header().consensus_data()),
            BlockSeal::from_consensus_data(block_2.header().consensus_data()),
        );

        let id_1 = block_1.get_id();
        let id_2 = block_2.get_id();
        let header_1 = block_1.header().clone();
        let header_2 = block_2.header().clone();
        let entry = SealIndexEntry::new(
            BlockSeal::from_consensus_data(block_1.header().consensus_data()).unwrap(),
            vec![(id_1, TEST_HEIGHT)],
        );

        let mut db = MockStoreTxRw::new();
        db.expect_get_seal_index_entry().times(1).return_const(Ok(Some(entry)));
        db.expect_get_block_header()
            .times(1)
            .with(eq(id_1))
            .return_const(Ok(Some(header_1.clone())));
        db.expect_set_duplicate_seal_evidence()
            .times(1)
            .withf(move |block_id, evidence| {
                block_id == &id_2
                    && evidence.headers().len() == 2
                    && evidence.headers()[0] == header_1
                    && evidence.headers()[1] == header_2
            })
            .return_const(Ok(()));
        db.expect_set_seal_index_entry()
            .times(1)
            .withf(|_, entry| entry.blocks().len() == 2)
            .return_const(Ok(()));

        index_block_seal(&mut db, &block_2, TEST_HEIGHT).unwrap();
    }

    #[test]
    fn already_indexed_block_is_skipped() {
        let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_entropy(VRFKeyKind::Schnorrkel);
        let block = make_pos_block(H256::zero(), &vrf_sk, &vrf_pk, H256::zero());
        let entry = SealIndexEntry::new(
            BlockSeal::from_consensus_data(block.header().consensus_data()).unwrap(),
            vec![(block.get_id(), TEST_HEIGHT)],
        );

        let mut db = MockStoreTxRw::new();
        db.expect_get_seal_index_entry().times(1).return_const(Ok(Some(entry)));

        // No write expectations: any write fails the test.
        index_block_seal(&mut db, &block, TEST_HEIGHT).unwrap();
    }

    #[test]
    fn index_entry_is_capped() {
        let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_entropy(VRFKeyKind::Schnorrkel);
        let block = make_pos_block(H256::zero(), &vrf_sk, &vrf_pk, H256::zero());

        let seal = BlockSeal::from_consensus_data(block.header().consensus_data()).unwrap();
        let known_blocks = (0..MAX_BLOCKS_PER_SEAL.get())
            .map(|i| (Id::new(H256::from([(i + 1) as u8; 32])), TEST_HEIGHT))
            .collect::<Vec<_>>();
        let entry = SealIndexEntry::new(seal, known_blocks);

        let mut db = MockStoreTxRw::new();
        db.expect_get_seal_index_entry().times(1).return_const(Ok(Some(entry)));
        // The index entry of the seal is at its cap, so the seal reuse is already
        // covered by the previously recorded evidence: no header is looked up, no
        // new evidence is written and the index entry is not extended, keeping the
        // storage footprint of a single reused seal bounded.
        db.expect_get_block_header().times(0);
        db.expect_set_duplicate_seal_evidence().times(0);
        db.expect_set_seal_index_entry().times(0);

        index_block_seal(&mut db, &block, TEST_HEIGHT).unwrap();
    }

    #[test]
    fn duplicate_seal_records_evidence_with_missing_known_block_header() {
        // Same as `duplicate_seal_records_evidence`, but the header of the known
        // block is unavailable. The evidence record still gets written, retaining
        // the header of the new block.
        let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_entropy(VRFKeyKind::Schnorrkel);
        let seed = H256::zero();
        let block_1 = make_pos_block(H256::zero(), &vrf_sk, &vrf_pk, seed);
        let block_2 = make_pos_block(H256::from([1u8; 32]), &vrf_sk, &vrf_pk, seed);

        assert_ne!(block_1.get_id(), block_2.get_id());

        let id_1 = block_1.get_id();
        let id_2 = block_2.get_id();
        let header_2 = block_2.header().clone();
        let entry = SealIndexEntry::new(
            BlockSeal::from_consensus_data(block_1.header().consensus_data()).unwrap(),
            vec![(id_1, TEST_HEIGHT)],
        );

        let mut db = MockStoreTxRw::new();
        db.expect_get_seal_index_entry().times(1).return_const(Ok(Some(entry)));
        db.expect_get_block_header().times(1).with(eq(id_1)).return_const(Ok(None));
        db.expect_set_duplicate_seal_evidence()
            .times(1)
            .withf(move |block_id, evidence| {
                block_id == &id_2
                    && evidence.headers().len() == 1
                    && evidence.headers()[0] == header_2
            })
            .return_const(Ok(()));
        db.expect_set_seal_index_entry()
            .times(1)
            .withf(|_, entry| entry.blocks().len() == 2)
            .return_const(Ok(()));

        index_block_seal(&mut db, &block_2, TEST_HEIGHT).unwrap();
    }
}
