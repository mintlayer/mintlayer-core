// Copyright (c) 2021 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): S. Afach, A. Sinitsyn

mod detail;

pub mod rpc;

use std::sync::Arc;

use common::{
    chain::{block::Block, ChainConfig},
    primitives::{BlockHeight, Id},
};
pub use detail::BlockError;
use detail::{BlockSource, Consensus};

#[derive(Debug)]
pub enum ConsensusEvent {
    NewTip(Arc<Id<Block>>, Arc<BlockHeight>),
}

pub struct ConsensusInterface {
    consensus: detail::Consensus,
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum ConsensusError {
    #[error("Initialization error")]
    FailedToInitializeConsensus(String),
    #[error("Block processing failed: `{0}`")]
    ProcessBlockError(BlockError),
    #[error("Property read error: `{0}`")]
    FailedToReadProperty(BlockError),
}

impl ConsensusInterface {
    pub fn subscribe_to_events(&mut self, handler: Arc<dyn Fn(ConsensusEvent) + Send + Sync>) {
        self.consensus.subscribe_to_events(handler)
    }

    pub fn process_block(
        &mut self,
        block: Block,
        source: BlockSource,
    ) -> Result<(), ConsensusError> {
        self.consensus
            .process_block(block, source)
            .map_err(ConsensusError::ProcessBlockError)?;
        Ok(())
    }

    pub fn get_best_block_id(&self) -> Result<Id<Block>, ConsensusError> {
        Ok(self
            .consensus
            .get_best_block_id()
            .map_err(ConsensusError::FailedToReadProperty)?
            .expect("There always must be a best block"))
    }

    pub fn is_block_in_main_chain(&self, block_id: &Id<Block>) -> Result<bool, ConsensusError> {
        Ok(self
            .consensus
            .get_block_height_in_main_chain(block_id)
            .map_err(ConsensusError::FailedToReadProperty)?
            .is_some())
    }

    pub fn get_block_height_in_main_chain(
        &self,
        block_id: &Id<Block>,
    ) -> Result<Option<BlockHeight>, ConsensusError> {
        self.consensus
            .get_block_height_in_main_chain(block_id)
            .map_err(ConsensusError::FailedToReadProperty)
    }

    pub fn get_block_id_from_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<Id<Block>>, ConsensusError> {
        self.consensus
            .get_block_id_from_height(height)
            .map_err(ConsensusError::FailedToReadProperty)
    }

    pub fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, ConsensusError> {
        self.consensus.get_block(block_id).map_err(ConsensusError::FailedToReadProperty)
    }
}

pub fn make_consensus(
    chain_config: ChainConfig,
    blockchain_storage: blockchain_storage::Store,
) -> Result<ConsensusInterface, ConsensusError> {
    let cons = Consensus::new(chain_config, blockchain_storage)?;
    let cons_interface = ConsensusInterface { consensus: cons };
    Ok(cons_interface)
}

#[cfg(test)]
mod test;
