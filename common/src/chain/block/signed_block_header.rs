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

use serialization::{Decode, Encode};
use typename::TypeName;

use crate::primitives::id::{Id, Idable};

use super::{timestamp::BlockTimestamp, Block, BlockHeader, ConsensusData, GenBlock};

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum SignedHeaderError {
    #[error("Attempted to mutate a header that is already signed")]
    AttemptedMutatingSignedHeader,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TypeName)]
pub struct BlockHeaderSignatureData {
    // TODO: determine the proper types for these fields.
    //       So far, the plan is to make the public key match
    //       the kernel input destination and hence it should
    //       be able to verify it too.
    public_key: Vec<u8>,
    signature: Vec<u8>,
}

impl BlockHeaderSignatureData {
    pub fn new(public_key: Vec<u8>, signature: Vec<u8>) -> Self {
        Self {
            public_key,
            signature,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TypeName)]
pub enum BlockHeaderSignature {
    None,
    PoSBlock(BlockHeaderSignatureData),
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TypeName, serialization::Tagged)]
pub struct SignedBlockHeader {
    block_header: BlockHeader,
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

    /// Returns the inner header as mutable reference.
    /// If the header is already signed, it will return None, to enforce immutability.
    /// To mutate the header, first use `take_header()` to take ownership of the unsigned header.
    pub fn header_mut(&mut self) -> Option<&mut BlockHeader> {
        match self.signature() {
            BlockHeaderSignature::None => Some(&mut self.block_header),
            BlockHeaderSignature::PoSBlock(_) => None,
        }
    }

    pub fn take_header(self) -> BlockHeader {
        self.block_header
    }

    pub fn consensus_data(&self) -> &ConsensusData {
        &self.header().consensus_data
    }

    /// Consensus data can be only updated if the header is not signed.
    /// Keep in mind that this doesn't necessitate a valid header. For example,
    /// Mutating a header can ruin proof of work consensus as the nonce is not valid.
    pub fn try_update_consensus_data(
        &mut self,
        consensus_data: ConsensusData,
    ) -> Result<(), SignedHeaderError> {
        self.header_mut()
            .ok_or(SignedHeaderError::AttemptedMutatingSignedHeader)?
            .consensus_data = consensus_data;
        Ok(())
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
