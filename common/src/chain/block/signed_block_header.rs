// Copyright (c) 2023 RBB S.r.l
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

use crypto::key::Signature;
use serialization::{Decode, Encode};
use typename::TypeName;

use crate::primitives::id::{Id, Idable};

use super::{timestamp::BlockTimestamp, Block, BlockHeader, ConsensusData, GenBlock};

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TypeName)]
pub enum BlockHeaderSignature {
    None,
    PoSBlock(Signature),
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TypeName, serialization::Tagged)]
pub struct SignedBlockHeader {
    block_header: BlockHeader,
    // TODO: Do we want to include the public key to make it possible to cross-check with the spent kernel?
    signature: BlockHeaderSignature,
}

impl SignedBlockHeader {
    pub fn new(signature: BlockHeaderSignature, block_header: BlockHeader) -> Self {
        Self {
            signature,
            block_header,
        }
    }

    pub fn signature(&self) -> &BlockHeaderSignature {
        &self.signature
    }

    pub fn header(&self) -> &BlockHeader {
        &self.block_header
    }

    pub fn header_mut(&mut self) -> &mut BlockHeader {
        &mut self.block_header
    }

    pub fn take_block_header(self) -> BlockHeader {
        self.block_header
    }

    pub fn consensus_data(&self) -> &ConsensusData {
        &self.header().consensus_data
    }

    pub fn block_id(&self) -> Id<Block> {
        self.header().get_id()
    }

    pub fn prev_block_id(&self) -> &Id<GenBlock> {
        &self.header().prev_block_id
    }

    pub fn timestamp(&self) -> BlockTimestamp {
        self.header().timestamp
    }

    pub fn header_size(&self) -> usize {
        self.encoded_size()
    }
}

impl Idable for SignedBlockHeader {
    type Tag = Block;

    fn get_id(&self) -> Id<Self::Tag> {
        self.header().get_id()
    }
}
