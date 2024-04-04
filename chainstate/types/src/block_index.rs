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

use common::chain::block::signed_block_header::SignedBlockHeader;
use common::chain::block::timestamp::BlockTimestamp;
use common::chain::{Block, GenBlock};
use common::primitives::{BlockHeight, Id, Idable, H256};
use common::Uint256;
use serialization::{Decode, Encode};

use crate::{BlockStatus, GenBlockIndex};

#[derive(Debug, Clone, Encode, Decode)]
pub struct BlockIndex {
    block_id: Id<Block>,
    block_header: SignedBlockHeader,
    /// One ancestor in the past that can make looping faster
    some_ancestor: Id<GenBlock>,
    /// The total chain trust up to this point
    chain_trust: H256,
    height: BlockHeight,
    /// The highest timestamp in this chain up to this block
    chain_time_max: BlockTimestamp,
    #[codec(compact)]
    /// The total number of transactions up to this block
    chain_transaction_count: u128,
    /// The block status.
    status: BlockStatus,
    /// If true, the corresponding block has been persisted in the db.
    /// This also means that the block index object can't be deleted from the db (unless the
    /// block gets purged).
    is_persisted: bool,
}

impl BlockIndex {
    pub fn new(
        block: &Block,
        chain_trust: Uint256,
        some_ancestor: Id<GenBlock>,
        height: BlockHeight,
        chain_time_max: BlockTimestamp,
        chain_transaction_count: u128,
        status: BlockStatus,
    ) -> Self {
        // We have to use the whole block because we are not able to take block_hash from the header
        Self {
            block_header: block.header().clone(),
            block_id: block.get_id(),
            some_ancestor,
            chain_trust: chain_trust.into(),
            height,
            chain_time_max,
            chain_transaction_count,
            status,
            is_persisted: false,
        }
    }

    pub fn block_id(&self) -> &Id<Block> {
        &self.block_id
    }

    pub fn prev_block_id(&self) -> &Id<GenBlock> {
        self.block_header.header().prev_block_id()
    }

    pub fn block_timestamp(&self) -> BlockTimestamp {
        self.block_header.header().timestamp()
    }

    pub fn chain_timestamps_max(&self) -> BlockTimestamp {
        self.chain_time_max
    }

    pub fn block_height(&self) -> BlockHeight {
        self.height
    }

    pub fn chain_trust(&self) -> Uint256 {
        self.chain_trust.into()
    }

    pub fn chain_transaction_count(&self) -> u128 {
        self.chain_transaction_count
    }

    pub fn block_header(&self) -> &SignedBlockHeader {
        &self.block_header
    }

    pub fn some_ancestor(&self) -> &Id<GenBlock> {
        &self.some_ancestor
    }

    pub fn status(&self) -> BlockStatus {
        self.status
    }

    pub fn set_status(&mut self, status: BlockStatus) {
        self.status = status;
    }

    pub fn with_status(mut self, status: BlockStatus) -> Self {
        self.status = status;
        self
    }

    pub fn is_persisted(&self) -> bool {
        self.is_persisted
    }

    pub fn make_persisted(mut self) -> Self {
        self.is_persisted = true;
        self
    }

    pub fn into_block_header(self) -> SignedBlockHeader {
        self.block_header
    }

    pub fn into_gen_block_index(self) -> GenBlockIndex {
        self.into()
    }

    /// Return true if all fields of this BlockIndex are exactly the same as other's.
    /// Note that we don't call this relation "equality" (and don't implement Eq/PartialEq)
    /// because it's ambiguous what "equality" should mean for a BlockIndex.
    pub fn is_identical_to<'a>(&'a self, other: &'a BlockIndex) -> bool {
        let as_ref_tuple = |bi: &'a BlockIndex| {
            let BlockIndex {
                block_id,
                block_header,
                some_ancestor,
                chain_trust,
                height,
                chain_time_max,
                chain_transaction_count,
                status,
                is_persisted,
            } = bi;
            (
                block_id,
                block_header,
                some_ancestor,
                chain_trust,
                height,
                chain_time_max,
                chain_transaction_count,
                status,
                is_persisted,
            )
        };

        as_ref_tuple(self) == as_ref_tuple(other)
    }
}
