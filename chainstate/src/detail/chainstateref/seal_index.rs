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
//! Once the cap is reached, the index entry is not extended anymore, so the
//! storage footprint of a single reused seal stays bounded. The seal is covered
//! by at most one evidence record, which is extended with the missing headers
//! on every new sighting below the cap; past the cap, the sightings are only
//! logged, except that a seal without any evidence gets its record backfilled,
//! since earlier sightings may have failed to collect corroborating headers.
//! The evidence records that were already recorded are never removed by this
//! module.

use std::num::NonZeroUsize;

use chainstate_storage::BlockchainStorageWrite;
use chainstate_types::{BlockSeal, DuplicateSealEvidence, SealIndexEntry};
use common::{
    chain::Block,
    primitives::{BlockHeight, Id, Idable, id::WithId},
};
use logging::log;

use crate::{BlockError, config::ChainstateConfig};

/// The maximum number of blocks a single seal is indexed for.
// The cap exists to bound the storage and processing costs of seal reuse. It is
// deliberately conservative: honest blocks never share a seal, so the cap only
// matters for deliberately reused seals.
pub const MAX_BLOCKS_PER_SEAL: NonZeroUsize = NonZeroUsize::new(8).unwrap();

/// Index the seal of the given block if seal duplication tracking is enabled in
/// the given config.
///
/// This is the single place where the indexing is gated on the config, so that
/// all the callers (the block integration path and the storage replication in
/// the test suite) cannot diverge on the seal tables.
pub fn index_block_seal_if_enabled<S: BlockchainStorageWrite>(
    chainstate_config: &ChainstateConfig,
    db_tx: &mut S,
    block: &WithId<Block>,
    block_height: BlockHeight,
) -> Result<(), BlockError> {
    if chainstate_config.pos_seal_duplication_tracking_enabled() {
        index_block_seal(db_tx, block, block_height)
    } else {
        Ok(())
    }
}

/// Index the seal of the given block, recording evidence if the seal was already
/// seen on another block.
///
/// This must be called for every block that has passed all checks, along with its
/// integration into the block tree, so that the seal index covers the blocks of
/// all branches, not only those of the best chain.
fn index_block_seal<S: BlockchainStorageWrite>(
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
        record_duplicate_seal_evidence(db_tx, &seal, entry.blocks(), block, None)?;
        entry.push_block(block_id, block_height);
        db_tx.set_seal_index_entry(entry.seal(), &entry)?;
    } else {
        // The index entry of the seal is at its cap, so the seal reuse is
        // already covered by the recorded evidence. Log the sighting, but do
        // not extend the index and do not extend the evidence, keeping the
        // storage footprint of a single reused seal bounded.
        //
        // The evidence is backfilled if it does not exist at all: earlier
        // sightings below the cap may have failed to collect corroborating
        // headers, and past the cap no sighting would ever fill it in. The
        // record written here is bounded by the index entry anyway, and once
        // it exists, the sightings are only logged again.
        let existing_evidence = db_tx.get_duplicate_seal_evidence(&seal)?;
        if existing_evidence.is_none() {
            log::info!(
                "A PoS seal of pool {} was seen on more than one block; the evidence cap is reached without any evidence (block {})",
                seal.pool_id(),
                block.get_id(),
            );
            // The record is known to be absent, so it is started from empty
            // instead of being loaded again.
            record_duplicate_seal_evidence(
                db_tx,
                &seal,
                entry.blocks(),
                block,
                Some(DuplicateSealEvidence::new(seal.clone(), Vec::new())),
            )?;
        } else {
            log::info!(
                "A PoS seal of pool {} was seen on more than one block; the evidence cap is reached (block {})",
                seal.pool_id(),
                block.get_id(),
            );
        }
    }

    Ok(())
}

/// Extend the evidence record of the given seal with the header of the newly
/// seen block and the headers of the known blocks that carry the seal.
///
/// The seal is covered by a single evidence record, which is extended with the
/// missing headers on every sighting below the cap and written back, so a
/// reused seal never stores more than one copy of each header. A header is only
/// retained if its consensus data carries the seal under test, so the record
/// stays self-certifying on its own.
///
/// The already loaded record of the seal can be passed as `existing_evidence`
/// (an empty record if the caller knows that no evidence exists yet);
/// otherwise it is loaded here.
fn record_duplicate_seal_evidence<S: BlockchainStorageWrite>(
    db_tx: &mut S,
    seal: &BlockSeal,
    known_blocks: &[(Id<Block>, BlockHeight)],
    block: &WithId<Block>,
    existing_evidence: Option<DuplicateSealEvidence>,
) -> Result<(), BlockError> {
    let mut evidence = match existing_evidence {
        Some(evidence) => evidence,
        None => db_tx
            .get_duplicate_seal_evidence(seal)?
            .unwrap_or_else(|| DuplicateSealEvidence::new(seal.clone(), Vec::new())),
    };

    for (existing_id, _) in known_blocks {
        // The headers of the previously seen blocks are already retained in the
        // record, so only the ones that are missing have to be collected.
        if evidence.headers().iter().any(|header| header.get_id() == *existing_id) {
            continue;
        }
        match db_tx.get_block_header(existing_id)? {
            Some(header)
                if BlockSeal::from_consensus_data(header.consensus_data()).as_ref()
                    == Some(seal) =>
            {
                evidence.push_header(header)
            }
            Some(_) => {
                // Unreachable in practice: the index entry only lists the blocks
                // that were seen carrying this seal. Skip such a header instead of
                // weakening the record with one that does not corroborate it.
                log::warn!(
                    "The header of the indexed block {} does not carry the expected seal of pool {} while recording duplicate seal evidence",
                    existing_id,
                    seal.pool_id(),
                );
            }
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

    // A single signed header proves nothing about duplication: if no headers of
    // the other blocks that carry the seal could be collected, there is no
    // evidence to record. The seal is still indexed by the caller, so the
    // evidence can be filled in by a later sighting.
    if evidence.headers().len() < 2 {
        log::warn!(
            "No corroborating headers available for the duplicate seal of pool {}; no evidence recorded",
            seal.pool_id(),
        );
        return Ok(());
    }

    log::info!(
        "A PoS seal of pool {} was seen on more than one block; recorded evidence for block {}",
        seal.pool_id(),
        block.get_id(),
    );

    db_tx.set_duplicate_seal_evidence(seal, &evidence)?;
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
        make_pos_block_with_epoch(prev_block_id, vrf_sk, vrf_pk, seed, 0)
    }

    /// Make a PoS block whose seal is derived from the given seed and the epoch
    /// index offset from the epoch of the test height, so blocks made with the
    /// same arguments share the seal, while a different epoch offset yields a
    /// different seal.
    fn make_pos_block_with_epoch(
        prev_block_id: H256,
        vrf_sk: &VRFPrivateKey,
        vrf_pk: &VRFPublicKey,
        seed: H256,
        epoch_offset: u64,
    ) -> WithId<Block> {
        let chain_config =
            ConfigBuilder::test_chain().epoch_length(NonZeroU64::new(3).unwrap()).build();

        let timestamp = BlockTimestamp::from_int_seconds(1);
        let epoch_index =
            chain_config.epoch_index_from_height(&TEST_HEIGHT.next_height()) + epoch_offset;
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
        let header_1 = block_1.header().clone();
        let header_2 = block_2.header().clone();
        let seal = BlockSeal::from_consensus_data(block_1.header().consensus_data()).unwrap();
        let entry = SealIndexEntry::new(seal.clone(), vec![(id_1, TEST_HEIGHT)]);

        let mut db = MockStoreTxRw::new();
        db.expect_get_seal_index_entry().times(1).return_const(Ok(Some(entry)));
        db.expect_get_duplicate_seal_evidence()
            .times(1)
            .with(eq(seal.clone()))
            .return_const(Ok(None));
        db.expect_get_block_header()
            .times(1)
            .with(eq(id_1))
            .return_const(Ok(Some(header_1.clone())));
        db.expect_set_duplicate_seal_evidence()
            .times(1)
            .withf(move |seal, evidence| {
                evidence.seal() == seal
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
    fn duplicate_seal_extends_the_existing_evidence_record() {
        // Same as `duplicate_seal_records_evidence`, but the seal already has an
        // evidence record from a previous sighting. The record must be extended
        // with the header of the newly seen block only, without duplicating the
        // headers it already retains and without writing a second record.
        let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_entropy(VRFKeyKind::Schnorrkel);
        let seed = H256::zero();
        let block_1 = make_pos_block(H256::zero(), &vrf_sk, &vrf_pk, seed);
        let block_2 = make_pos_block(H256::from([1u8; 32]), &vrf_sk, &vrf_pk, seed);
        let block_3 = make_pos_block(H256::from([2u8; 32]), &vrf_sk, &vrf_pk, seed);

        let id_1 = block_1.get_id();
        let id_2 = block_2.get_id();
        let header_1 = block_1.header().clone();
        let header_2 = block_2.header().clone();
        let header_3 = block_3.header().clone();
        let seal = BlockSeal::from_consensus_data(block_1.header().consensus_data()).unwrap();

        let entry =
            SealIndexEntry::new(seal.clone(), vec![(id_1, TEST_HEIGHT), (id_2, TEST_HEIGHT)]);
        let existing_evidence =
            DuplicateSealEvidence::new(seal.clone(), vec![header_1.clone(), header_2.clone()]);

        let mut db = MockStoreTxRw::new();
        db.expect_get_seal_index_entry().times(1).return_const(Ok(Some(entry)));
        db.expect_get_duplicate_seal_evidence()
            .times(1)
            .with(eq(seal.clone()))
            .return_const(Ok(Some(existing_evidence)));
        // The headers of both known blocks are already retained in the record,
        // so no header is looked up.
        db.expect_get_block_header().times(0);
        db.expect_set_duplicate_seal_evidence()
            .times(1)
            .withf(move |seal, evidence| {
                evidence.seal() == seal
                    && evidence.headers().len() == 3
                    && evidence.headers()[0] == header_1
                    && evidence.headers()[1] == header_2
                    && evidence.headers()[2] == header_3
            })
            .return_const(Ok(()));
        db.expect_set_seal_index_entry()
            .times(1)
            .withf(|_, entry| entry.blocks().len() == 3)
            .return_const(Ok(()));

        index_block_seal(&mut db, &block_3, TEST_HEIGHT).unwrap();
    }

    #[test]
    fn evidence_skips_headers_that_do_not_carry_the_seal() {
        // Same as `duplicate_seal_records_evidence`, but the header stored for one
        // of the known blocks, while available, does not carry the seal under test
        // (e.g. because of a storage inconsistency). Such a header must not weaken
        // the evidence record.
        let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_entropy(VRFKeyKind::Schnorrkel);
        let seed = H256::zero();
        let block_1 = make_pos_block(H256::zero(), &vrf_sk, &vrf_pk, seed);
        let block_2 = make_pos_block(H256::from([1u8; 32]), &vrf_sk, &vrf_pk, seed);
        let block_3 = make_pos_block(H256::from([2u8; 32]), &vrf_sk, &vrf_pk, seed);
        // A block that carries a different seal: the same seed signed for a
        // different epoch produces a different VRF output.
        let block_other_seal =
            make_pos_block_with_epoch(H256::from([3u8; 32]), &vrf_sk, &vrf_pk, seed, 1);
        assert_ne!(
            BlockSeal::from_consensus_data(block_1.header().consensus_data()),
            BlockSeal::from_consensus_data(block_other_seal.header().consensus_data()),
        );

        let id_1 = block_1.get_id();
        let id_2 = block_2.get_id();
        let header_1 = block_1.header().clone();
        let header_3 = block_3.header().clone();
        let seal = BlockSeal::from_consensus_data(block_1.header().consensus_data()).unwrap();
        let entry =
            SealIndexEntry::new(seal.clone(), vec![(id_1, TEST_HEIGHT), (id_2, TEST_HEIGHT)]);

        let mut db = MockStoreTxRw::new();
        db.expect_get_seal_index_entry().times(1).return_const(Ok(Some(entry)));
        db.expect_get_duplicate_seal_evidence()
            .times(1)
            .with(eq(seal.clone()))
            .return_const(Ok(None));
        db.expect_get_block_header()
            .times(1)
            .with(eq(id_1))
            .return_const(Ok(Some(header_1.clone())));
        db.expect_get_block_header()
            .times(1)
            .with(eq(id_2))
            .return_const(Ok(Some(block_other_seal.header().clone())));
        db.expect_set_duplicate_seal_evidence()
            .times(1)
            .withf(move |seal, evidence| {
                evidence.seal() == seal
                    && evidence.headers().len() == 2
                    && evidence.headers()[0] == header_1
                    && evidence.headers()[1] == header_3
            })
            .return_const(Ok(()));
        db.expect_set_seal_index_entry()
            .times(1)
            .withf(|_, entry| entry.blocks().len() == 3)
            .return_const(Ok(()));

        index_block_seal(&mut db, &block_3, TEST_HEIGHT).unwrap();
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
        // The index entry of the seal is at its cap and its evidence exists, so
        // the seal reuse is already covered: no header is looked up, no new
        // evidence is written and the index entry is not extended, keeping the
        // storage footprint of a single reused seal bounded.
        db.expect_get_duplicate_seal_evidence().times(1).return_const(Ok(Some(
            DuplicateSealEvidence::new(
                BlockSeal::from_consensus_data(block.header().consensus_data()).unwrap(),
                vec![block.header().clone(), block.header().clone()],
            ),
        )));
        db.expect_get_block_header().times(0);
        db.expect_set_duplicate_seal_evidence().times(0);
        db.expect_set_seal_index_entry().times(0);

        index_block_seal(&mut db, &block, TEST_HEIGHT).unwrap();
    }

    #[test]
    fn evidence_is_backfilled_when_the_cap_is_reached_without_evidence() {
        // Same as `index_entry_is_capped`, but the seal has no evidence record:
        // earlier sightings may have failed to collect corroborating headers,
        // and past the cap no sighting would ever fill it in, so the sighting
        // at the cap backfills the evidence instead of only being logged. The
        // index entry is still not extended.
        let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_entropy(VRFKeyKind::Schnorrkel);
        let block = make_pos_block(H256::zero(), &vrf_sk, &vrf_pk, H256::zero());

        let seal = BlockSeal::from_consensus_data(block.header().consensus_data()).unwrap();
        let known_blocks = (0..MAX_BLOCKS_PER_SEAL.get())
            .map(|i| (Id::new(H256::from([(i + 1) as u8; 32])), TEST_HEIGHT))
            .collect::<Vec<_>>();
        let entry = SealIndexEntry::new(seal.clone(), known_blocks);

        let mut db = MockStoreTxRw::new();
        db.expect_get_seal_index_entry().times(1).return_const(Ok(Some(entry)));
        db.expect_get_duplicate_seal_evidence()
            .times(1)
            .with(eq(seal.clone()))
            .return_const(Ok(None));
        // The headers of the known blocks are unavailable, so the backfilled
        // record would carry the new block's header alone and is not written.
        db.expect_get_block_header()
            .times(MAX_BLOCKS_PER_SEAL.get())
            .return_const(Ok(None));
        db.expect_set_duplicate_seal_evidence().times(0);
        db.expect_set_seal_index_entry().times(0);

        index_block_seal(&mut db, &block, TEST_HEIGHT).unwrap();
    }

    #[test]
    fn evidence_is_backfilled_with_the_known_headers_at_the_cap() {
        // Same as above, but the headers of the known blocks are available: the
        // backfilled evidence retains them along with the new block's header.
        let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_entropy(VRFKeyKind::Schnorrkel);
        let block = make_pos_block(H256::zero(), &vrf_sk, &vrf_pk, H256::zero());

        let seal = BlockSeal::from_consensus_data(block.header().consensus_data()).unwrap();
        let known_blocks = (0..MAX_BLOCKS_PER_SEAL.get())
            .map(|i| (Id::new(H256::from([(i + 1) as u8; 32])), TEST_HEIGHT))
            .collect::<Vec<_>>();
        let entry = SealIndexEntry::new(seal.clone(), known_blocks);

        let header = block.header().clone();
        let mut db = MockStoreTxRw::new();
        db.expect_get_seal_index_entry().times(1).return_const(Ok(Some(entry)));
        db.expect_get_duplicate_seal_evidence()
            .times(1)
            .with(eq(seal.clone()))
            .return_const(Ok(None));
        db.expect_get_block_header()
            .times(MAX_BLOCKS_PER_SEAL.get())
            .return_const(Ok(Some(header.clone())));
        db.expect_set_duplicate_seal_evidence()
            .times(1)
            .withf(move |seal, evidence| {
                evidence.seal() == seal
                    && evidence.headers().len() == MAX_BLOCKS_PER_SEAL.get() + 1
                    && evidence.headers().iter().all(|h| *h == header)
            })
            .return_const(Ok(()));
        db.expect_set_seal_index_entry().times(0);

        index_block_seal(&mut db, &block, TEST_HEIGHT).unwrap();
    }

    #[test]
    fn evidence_is_not_recorded_without_corroborating_headers() {
        // Same as `duplicate_seal_records_evidence`, but the header of the known
        // block is unavailable. A record of the new block's header alone proves
        // nothing about the duplication, so no evidence is recorded; the block is
        // still indexed, so a later sighting can fill in the evidence.
        let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_entropy(VRFKeyKind::Schnorrkel);
        let seed = H256::zero();
        let block_1 = make_pos_block(H256::zero(), &vrf_sk, &vrf_pk, seed);
        let block_2 = make_pos_block(H256::from([1u8; 32]), &vrf_sk, &vrf_pk, seed);

        assert_ne!(block_1.get_id(), block_2.get_id());

        let id_1 = block_1.get_id();
        let seal = BlockSeal::from_consensus_data(block_1.header().consensus_data()).unwrap();
        let entry = SealIndexEntry::new(seal.clone(), vec![(id_1, TEST_HEIGHT)]);

        let mut db = MockStoreTxRw::new();
        db.expect_get_seal_index_entry().times(1).return_const(Ok(Some(entry)));
        db.expect_get_duplicate_seal_evidence()
            .times(1)
            .with(eq(seal.clone()))
            .return_const(Ok(None));
        db.expect_get_block_header().times(1).with(eq(id_1)).return_const(Ok(None));
        db.expect_set_duplicate_seal_evidence().times(0);
        db.expect_set_seal_index_entry()
            .times(1)
            .withf(|_, entry| entry.blocks().len() == 2)
            .return_const(Ok(()));

        index_block_seal(&mut db, &block_2, TEST_HEIGHT).unwrap();
    }

    #[test]
    fn seal_indexing_is_gated_on_the_config() {
        let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_entropy(VRFKeyKind::Schnorrkel);
        let block = make_pos_block(H256::zero(), &vrf_sk, &vrf_pk, H256::zero());

        // Disabled: the seal is not indexed, so no storage access happens at all.
        let chainstate_config = ChainstateConfig {
            pos_seal_duplication_tracking: false.into(),
            ..Default::default()
        };
        let mut db = MockStoreTxRw::new();
        index_block_seal_if_enabled(&chainstate_config, &mut db, &block, TEST_HEIGHT).unwrap();

        // Enabled: the seal gets indexed.
        let chainstate_config = ChainstateConfig::default();
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
        index_block_seal_if_enabled(&chainstate_config, &mut db, &block, TEST_HEIGHT).unwrap();
    }
}
