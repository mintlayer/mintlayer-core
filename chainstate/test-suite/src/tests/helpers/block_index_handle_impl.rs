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

use std::sync::Arc;

use chainstate::PropertyQueryError;
use chainstate_storage::BlockchainStorageRead;
use chainstate_types::{BlockIndex, BlockIndexHandle, GenBlockIndex};
use common::{
    chain::{Block, ChainConfig, GenBlockId},
    primitives::Id,
};

pub struct TestBlockIndexHandle<'a, S> {
    db_tx: S,
    chain_config: &'a ChainConfig,
}

impl<'a, S: BlockchainStorageRead> TestBlockIndexHandle<'a, S> {
    pub fn new(storage: S, chain_config: &'a ChainConfig) -> Self {
        Self {
            db_tx: storage,
            chain_config,
        }
    }
}

impl<'a, S: BlockchainStorageRead> BlockIndexHandle for TestBlockIndexHandle<'a, S> {
    fn get_block_index(
        &self,
        block_id: &Id<Block>,
    ) -> Result<Option<BlockIndex>, PropertyQueryError> {
        self.db_tx.get_block_index(&block_id).map_err(PropertyQueryError::StorageError)
    }

    fn get_gen_block_index(
        &self,
        block_id: &Id<common::chain::GenBlock>,
    ) -> Result<Option<GenBlockIndex>, PropertyQueryError> {
        match block_id.classify(&self.chain_config) {
            GenBlockId::Genesis(_id) => Ok(Some(GenBlockIndex::Genesis(Arc::clone(
                self.chain_config.genesis_block(),
            )))),
            GenBlockId::Block(id) => self
                .db_tx
                .get_block_index(&id)
                .map(|b| b.map(GenBlockIndex::Block))
                .map_err(PropertyQueryError::StorageError),
        }
    }

    fn get_ancestor(
        &self,
        _block_index: &BlockIndex,
        _ancestor_height: common::primitives::BlockHeight,
    ) -> Result<GenBlockIndex, PropertyQueryError> {
        unimplemented!()
    }

    fn get_block_reward(
        &self,
        _block_index: &BlockIndex,
    ) -> Result<Option<common::chain::block::BlockReward>, PropertyQueryError> {
        unimplemented!()
    }

    fn get_epoch_data(
        &self,
        _epoch_index: u64,
    ) -> Result<Option<chainstate_types::EpochData>, PropertyQueryError> {
        unimplemented!()
    }
}
