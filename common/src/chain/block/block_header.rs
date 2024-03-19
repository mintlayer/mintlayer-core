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

use serialization::{Decode, Encode};

use super::signed_block_header::{BlockHeaderSignature, SignedBlockHeader};
use super::timestamp::BlockTimestamp;
use crate::chain::{block::ConsensusData, Block, GenBlock};
use crate::primitives::id::{Id, Idable, IdableWithParent, H256};
use crate::primitives::{id, VersionTag};

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, serialization::Tagged, serde::Serialize)]
pub struct BlockHeader {
    pub(super) version: VersionTag<1>,
    pub(super) prev_block_id: Id<GenBlock>,
    pub(super) tx_merkle_root: H256,
    pub(super) witness_merkle_root: H256,
    pub(super) timestamp: BlockTimestamp,
    pub(super) consensus_data: ConsensusData,
}

impl BlockHeader {
    pub fn new(
        prev_block_id: Id<GenBlock>,
        tx_merkle_root: H256,
        witness_merkle_root: H256,
        timestamp: BlockTimestamp,
        consensus_data: ConsensusData,
    ) -> Self {
        Self {
            version: VersionTag::default(),
            prev_block_id,
            tx_merkle_root,
            witness_merkle_root,
            timestamp,
            consensus_data,
        }
    }

    pub fn consensus_data(&self) -> &ConsensusData {
        &self.consensus_data
    }

    pub fn block_id(&self) -> Id<Block> {
        Id::new(id::hash_encoded(self))
    }

    pub fn prev_block_id(&self) -> &Id<GenBlock> {
        &self.prev_block_id
    }

    pub fn timestamp(&self) -> BlockTimestamp {
        self.timestamp
    }

    pub fn update_timestamp(&mut self, timestamp: BlockTimestamp) {
        self.timestamp = timestamp;
    }

    pub fn update_consensus_data(&mut self, consensus_data: ConsensusData) {
        self.consensus_data = consensus_data;
    }

    pub fn with_signature(self, signature: BlockHeaderSignature) -> SignedBlockHeader {
        SignedBlockHeader::new(signature, self)
    }

    pub fn with_no_signature(self) -> SignedBlockHeader {
        SignedBlockHeader::new(BlockHeaderSignature::None, self)
    }
}

impl Idable for BlockHeader {
    type Tag = Block;
    fn get_id(&self) -> Id<Block> {
        Id::new(id::hash_encoded(self))
    }
}

impl IdableWithParent for BlockHeader {
    type ParentTag = GenBlock;
    fn get_parent_id(&self) -> &Id<GenBlock> {
        self.prev_block_id()
    }
}
