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

pub mod consensus_interface_impl;

use std::sync::Arc;

use common::{
    chain::{block::Block, ChainConfig},
    primitives::{BlockHeight, Id},
};
pub use consensus_interface_impl::ConsensusInterfaceImpl;
pub use detail::BlockError;
use detail::{BlockSource, Consensus};

#[derive(Debug)]
pub enum ConsensusEvent {
    NewTip(Id<Block>, BlockHeight),
}

pub trait ConsensusInterface: Send {
    fn subscribe_to_events(&mut self, handler: Arc<dyn Fn(ConsensusEvent) + Send + Sync>);
    fn process_block(&mut self, block: Block, source: BlockSource) -> Result<(), ConsensusError>;
    fn get_best_block_id(&self) -> Result<Id<Block>, ConsensusError>;
    fn is_block_in_main_chain(&self, block_id: &Id<Block>) -> Result<bool, ConsensusError>;
    fn get_block_height_in_main_chain(
        &self,
        block_id: &Id<Block>,
    ) -> Result<Option<BlockHeight>, ConsensusError>;
    fn get_block_id_from_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<Id<Block>>, ConsensusError>;
    fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, ConsensusError>;
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

impl subsystem::Subsystem for Box<dyn ConsensusInterface> {}

type ConsensusHandle = subsystem::Handle<Box<dyn ConsensusInterface>>;

pub fn make_consensus(
    chain_config: Arc<ChainConfig>,
    blockchain_storage: blockchain_storage::Store,
) -> Result<Box<dyn ConsensusInterface>, ConsensusError> {
    let cons = Consensus::new(chain_config, blockchain_storage)?;
    let cons_interface = ConsensusInterfaceImpl::new(cons);
    Ok(Box::new(cons_interface))
}

#[cfg(test)]
mod test;
