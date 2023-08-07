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

use api_server_common::storage::storage_api::{ApiStorage, ApiStorageError};
use blockchain_scanner_lib::sync::local_state::LocalBlockchainState;
use common::{
    chain::{Block, GenBlock},
    primitives::{BlockHeight, Id},
};

#[derive(Debug, thiserror::Error)]
pub enum BlockchainStateError {
    #[error("Unexpected storage error: {0}")]
    StorageError(#[from] ApiStorageError),
}

pub struct BlockchainState<B: ApiStorage> {
    storage: B,
}

impl<B: ApiStorage> LocalBlockchainState for BlockchainState<B> {
    type Error = BlockchainStateError;

    fn best_block(&self) -> Result<(BlockHeight, Id<GenBlock>), Self::Error> {
        let best_block = self.storage.get_best_block()?;
        Ok(best_block)
    }

    fn scan_blocks(
        &mut self,
        _common_block_height: BlockHeight,
        _blocks: Vec<Block>,
    ) -> Result<(), Self::Error> {
        unimplemented!()
    }
}
