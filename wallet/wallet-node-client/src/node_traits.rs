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

#[async_trait::async_trait]
pub trait NodeInterface {
    type Error: std::error::Error;

    async fn get_best_block_id(&self) -> Result<Id<GenBlock>, Self::Error>;
    async fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, Self::Error>;
    async fn get_best_block_height(&self) -> Result<BlockHeight, Self::Error>;
    async fn get_block_id_at_height(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, Self::Error>;
    async fn submit_block(&self, block_hex: String) -> Result<(), Self::Error>;
}
