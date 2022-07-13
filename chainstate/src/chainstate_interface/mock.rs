// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::sync::Arc;

use common::{
    chain::block::{Block, BlockHeader},
    primitives::{BlockHeight, Id},
};

use crate::{detail::BlockSource, ChainstateError, ChainstateEvent};

use super::ChainstateInterface;

mockall::mock! {
    pub ChainstateInterfaceMock {}

    impl ChainstateInterface for ChainstateInterfaceMock {
        fn subscribe_to_events(&mut self, handler: Arc<dyn Fn(ChainstateEvent) + Send + Sync>);
        fn process_block(&mut self, block: Block, source: BlockSource) -> Result<(), ChainstateError>;
        fn preliminary_block_check(&self, block: Block) -> Result<Block, ChainstateError>;
        fn get_best_block_id(&self) -> Result<Id<Block>, ChainstateError>;
        fn get_best_block_height(&self) -> Result<BlockHeight, ChainstateError>;
        fn is_block_in_main_chain(&self, block_id: &Id<Block>) -> Result<bool, ChainstateError>;
        fn get_block_height_in_main_chain(
            &self,
            block_id: &Id<Block>,
        ) -> Result<Option<BlockHeight>, ChainstateError>;
        fn get_block_id_from_height(
            &self,
            height: &BlockHeight,
        ) -> Result<Option<Id<Block>>, ChainstateError>;
        fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, ChainstateError>;
        fn get_locator(&self) -> Result<Vec<BlockHeader>, ChainstateError>;
        fn get_headers(
            &self,
            locator: Vec<BlockHeader>,
        ) -> Result<Vec<BlockHeader>, ChainstateError>;
        fn filter_already_existing_blocks(
            &self,
            headers: Vec<BlockHeader>,
        ) -> Result<Vec<BlockHeader>, ChainstateError>;
    }
}
