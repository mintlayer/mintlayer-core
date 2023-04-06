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

use common::{
    chain::{Block, GenBlock},
    primitives::{BlockHeight, Id},
};

use crate::node_traits::NodeInterface;

use super::{NodeRpcClient, NodeRpcError};

#[async_trait::async_trait]
impl NodeInterface for NodeRpcClient {
    type Error = NodeRpcError;

    async fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, Self::Error> {
        let block = self.get_block(block_id)?;
        Ok(block)
    }

    async fn get_best_block_id(&self) -> Result<Id<GenBlock>, Self::Error> {
        let best_block_id = self.get_best_block_id()?;
        Ok(best_block_id)
    }

    async fn get_best_block_height(&self) -> Result<common::primitives::BlockHeight, Self::Error> {
        let best_block_height = self.get_best_block_height()?;
        Ok(best_block_height)
    }

    async fn get_block_id_at_height(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, Self::Error> {
        let block_id_at_height = self.get_block_id_at_height(height)?;
        Ok(block_id_at_height)
    }
}
