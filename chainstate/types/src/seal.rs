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

//! The seal of a proof-of-stake block.

use common::{
    chain::{Block, PoolId, block::ConsensusData, block::signed_block_header::SignedBlockHeader},
    primitives::{BlockHeight, H256, Id},
};
use crypto::vrf::VRFReturn;
use serialization::{Decode, Encode};

/// The seal of a proof-of-stake block: the stake pool that produced the block and
/// the VRF output that authorized the block production for the given slot.
///
/// A VRF proof is uniquely determined by the transcript it was produced over
/// (epoch index, randomness seed, block timestamp), so all valid blocks that share
/// the same seal were authorized by the same pool for the same slot.
///
/// Note that the VRF proof is not a part of the seal: unlike the VRF output, the
/// proof bytes may differ between two signings of the same transcript, so the
/// proof cannot be used to identify a slot draw.
///
/// Note also that the seal identity is bound to the timestamp of the slot: two
/// blocks that a pool produced for different (valid) timestamps have different
/// seals. The seal index detects the reuse of a single slot draw, not every form
/// of double block production: closing that gap, e.g. by coarsening the slot
/// identity below the one-second granularity of the VRF transcript, would have
/// to be anchored in the consensus rules themselves and is out of scope for the
/// index, which only retains what the consensus rules already authorize.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct BlockSeal {
    /// Id of the stake pool that produced the block.
    pool_id: PoolId,
    /// The 32-byte VRF output from the block's consensus data.
    vrf_output: H256,
}

impl BlockSeal {
    /// Extract the seal from the block's consensus data.
    ///
    /// Returns `None` if the consensus data does not carry a proof-of-stake seal,
    /// i.e. for `ConsensusData::None` and `ConsensusData::PoW`.
    pub fn from_consensus_data(consensus_data: &ConsensusData) -> Option<Self> {
        match consensus_data {
            ConsensusData::PoS(pos_data) => {
                let vrf_output = match pos_data.vrf_data() {
                    VRFReturn::Schnorrkel(vrf_data) => vrf_data.vrf_preout().into(),
                };
                Some(Self {
                    pool_id: *pos_data.stake_pool_id(),
                    vrf_output,
                })
            }
            ConsensusData::None | ConsensusData::PoW(_) => None,
        }
    }

    pub fn pool_id(&self) -> &PoolId {
        &self.pool_id
    }

    pub fn vrf_output(&self) -> &H256 {
        &self.vrf_output
    }
}

/// An index entry of a seal: the blocks known to carry it.
///
/// The number of blocks per entry is bounded by the seal indexing logic, so the
/// index stays bounded even if a seal is deliberately reused on many blocks.
///
/// Note: the entry is stored as the value of the seal index, so, like the seal
/// key itself, any change to its encoding would make the previously written
/// entries unreadable.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct SealIndexEntry {
    seal: BlockSeal,
    blocks: Vec<(Id<Block>, BlockHeight)>,
}

impl SealIndexEntry {
    pub fn new(seal: BlockSeal, blocks: Vec<(Id<Block>, BlockHeight)>) -> Self {
        Self { seal, blocks }
    }

    pub fn seal(&self) -> &BlockSeal {
        &self.seal
    }

    pub fn blocks(&self) -> &[(Id<Block>, BlockHeight)] {
        &self.blocks
    }

    pub fn push_block(&mut self, block_id: Id<Block>, block_height: BlockHeight) {
        self.blocks.push((block_id, block_height));
    }
}

/// Evidence that a single seal was seen on more than one block.
///
/// The record is self-certifying: each header carries the block signature of the
/// pool and its own VRF data, so a third party can verify that the same pool
/// produced all the listed blocks for the same slot. The headers are retained in
/// the record itself, so the evidence stays verifiable even if the blocks are
/// later removed from storage.
///
/// Note: the record is stored as the value of the duplicate seal evidence map,
/// so, like the seal key itself, any change to its encoding would make the
/// previously written records unreadable.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct DuplicateSealEvidence {
    seal: BlockSeal,
    headers: Vec<SignedBlockHeader>,
}

impl DuplicateSealEvidence {
    pub fn new(seal: BlockSeal, headers: Vec<SignedBlockHeader>) -> Self {
        Self { seal, headers }
    }

    pub fn seal(&self) -> &BlockSeal {
        &self.seal
    }

    pub fn headers(&self) -> &[SignedBlockHeader] {
        &self.headers
    }

    pub fn push_header(&mut self, header: SignedBlockHeader) {
        self.headers.push(header);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::chain::{
        GenBlock,
        block::{
            BlockHeader, consensus_data::PoSData, consensus_data::PoWData,
            signed_block_header::BlockHeaderSignature, timestamp::BlockTimestamp,
        },
        config::EpochIndex,
    };
    use common::primitives::Compact;
    use crypto::vrf::{VRFKeyKind, VRFPrivateKey};

    fn make_pos_consensus_data(
        vrf_sk: &VRFPrivateKey,
        pool_id: PoolId,
        epoch_index: EpochIndex,
        seed: H256,
    ) -> ConsensusData {
        let timestamp = BlockTimestamp::from_int_seconds(1);
        let transcript = crate::vrf_tools::construct_transcript(epoch_index, &seed, timestamp);
        let vrf_data = vrf_sk.produce_vrf_data(transcript);
        ConsensusData::PoS(PoSData::new(vec![], vec![], pool_id, vrf_data, Compact(1)).into())
    }

    fn make_seal(epoch_index: EpochIndex, seed: H256) -> (VRFPrivateKey, BlockSeal) {
        let vrf_sk = VRFPrivateKey::new_from_entropy(VRFKeyKind::Schnorrkel).0;
        let consensus_data =
            make_pos_consensus_data(&vrf_sk, PoolId::new(H256::zero()), epoch_index, seed);
        let seal = BlockSeal::from_consensus_data(&consensus_data).unwrap();
        (vrf_sk, seal)
    }

    #[test]
    fn seal_extraction_from_pos_consensus_data() {
        let (vrf_sk, seal) = make_seal(0, H256::zero());
        let consensus_data = make_pos_consensus_data(&vrf_sk, *seal.pool_id(), 0, H256::zero());

        assert_eq!(BlockSeal::from_consensus_data(&consensus_data), Some(seal));
    }

    #[test]
    fn seal_extraction_from_non_pos_consensus_data() {
        assert_eq!(BlockSeal::from_consensus_data(&ConsensusData::None), None);

        let pow_data = PoWData::new(Compact(1), 0);
        assert_eq!(
            BlockSeal::from_consensus_data(&ConsensusData::PoW(pow_data.into())),
            None
        );
    }

    #[test]
    fn seal_codec_roundtrip() {
        let (_, seal) = make_seal(0, H256::zero());

        // The exact encoding is pinned by `seal_encoding_is_stable`; here we only
        // verify that decoding recovers the encoded seal.
        let decoded = BlockSeal::decode(&mut &seal.encode()[..]).unwrap();
        assert_eq!(decoded, seal);
    }

    #[test]
    fn seal_encoding_is_stable() {
        // The seal is used as a database key: any change to the encoding would make
        // previously written entries unreadable, so pin the exact encoding here.
        let seal = BlockSeal {
            pool_id: PoolId::new(H256::from([1u8; 32])),
            vrf_output: H256::from([2u8; 32]),
        };

        let expected_encoded = {
            let mut encoded = Vec::new();
            encoded.extend_from_slice(H256::from([1u8; 32]).as_bytes());
            encoded.extend_from_slice(H256::from([2u8; 32]).as_bytes());
            encoded
        };
        assert_eq!(seal.encode(), expected_encoded);
    }

    #[test]
    fn same_slot_draw_produces_same_seal() {
        let pool_id = PoolId::new(H256::zero());
        let (vrf_sk, seal_1) = make_seal(0, H256::zero());

        // The VRF output is deterministic over the transcript even though the proof
        // bytes are not, so two signings of the same transcript yield the same seal.
        let consensus_data = make_pos_consensus_data(&vrf_sk, pool_id, 0, H256::zero());
        let seal_2 = BlockSeal::from_consensus_data(&consensus_data).unwrap();
        assert_eq!(seal_1, seal_2);

        // A different epoch means a different transcript and thus a different seal.
        let consensus_data_other = make_pos_consensus_data(&vrf_sk, pool_id, 1, H256::zero());
        let seal_other = BlockSeal::from_consensus_data(&consensus_data_other).unwrap();
        assert_ne!(seal_1, seal_other);
    }

    #[test]
    fn seal_index_entry_codec_roundtrip() {
        let (_, seal) = make_seal(0, H256::zero());
        let entry = SealIndexEntry::new(
            seal,
            vec![
                (Id::new(H256::from([3u8; 32])), BlockHeight::new(7)),
                (Id::new(H256::from([4u8; 32])), BlockHeight::new(8)),
            ],
        );

        // The entry is stored as the value of the seal index: like the seal key,
        // its encoding must stay readable (see `seal_encoding_is_stable`).
        let decoded = SealIndexEntry::decode(&mut &entry.encode()[..]).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn duplicate_seal_evidence_codec_roundtrip() {
        let (vrf_sk, seal) = make_seal(0, H256::zero());
        let block_header = BlockHeader::new(
            Id::<GenBlock>::new(H256::from([1u8; 32])),
            H256::from([2u8; 32]),
            H256::from([3u8; 32]),
            BlockTimestamp::from_int_seconds(1),
            make_pos_consensus_data(&vrf_sk, *seal.pool_id(), 0, H256::zero()),
        );
        let evidence = DuplicateSealEvidence::new(
            seal,
            vec![
                SignedBlockHeader::new(BlockHeaderSignature::None, block_header),
                SignedBlockHeader::new(
                    BlockHeaderSignature::None,
                    BlockHeader::new(
                        Id::<GenBlock>::new(H256::from([5u8; 32])),
                        H256::from([6u8; 32]),
                        H256::from([7u8; 32]),
                        BlockTimestamp::from_int_seconds(2),
                        ConsensusData::None,
                    ),
                ),
            ],
        );

        // The record is stored as the value of the duplicate seal evidence map:
        // like the seal key, its encoding must stay readable (see
        // `seal_encoding_is_stable`).
        let decoded = DuplicateSealEvidence::decode(&mut &evidence.encode()[..]).unwrap();
        assert_eq!(decoded, evidence);
    }
}
