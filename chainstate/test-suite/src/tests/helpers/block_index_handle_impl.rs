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

use chainstate::PropertyQueryError;
use chainstate_storage::BlockchainStorageRead;
use chainstate_types::{storage_result, BlockIndex, BlockIndexHandle, GenBlockIndex};
use common::{
    chain::{Block, ChainConfig, GenBlock, GenBlockId},
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

    fn gen_block_index_getter(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, storage_result::Error> {
        match block_id.classify(self.chain_config) {
            GenBlockId::Genesis(_id) => Ok(Some(GenBlockIndex::genesis(self.chain_config))),
            GenBlockId::Block(id) => {
                self.db_tx.get_block_index(&id).map(|b| b.map(GenBlockIndex::Block))
            }
        }
    }
}

impl<S: BlockchainStorageRead> BlockIndexHandle for TestBlockIndexHandle<'_, S> {
    fn get_block_index(
        &self,
        block_id: &Id<Block>,
    ) -> Result<Option<BlockIndex>, PropertyQueryError> {
        self.db_tx.get_block_index(block_id).map_err(PropertyQueryError::StorageError)
    }

    fn get_gen_block_index(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, PropertyQueryError> {
        self.gen_block_index_getter(block_id).map_err(PropertyQueryError::StorageError)
    }

    fn get_ancestor(
        &self,
        block_index: &BlockIndex,
        ancestor_height: common::primitives::BlockHeight,
    ) -> Result<GenBlockIndex, PropertyQueryError> {
        let block_index_getter = |_db_tx: &S, _chain_config: &ChainConfig, id: &Id<GenBlock>| {
            self.gen_block_index_getter(id)
        };

        let get_block_id = Id::<GenBlock>::from(*block_index.block_id());
        chainstate_types::block_index_ancestor_getter(
            block_index_getter,
            &self.db_tx,
            self.chain_config,
            (&get_block_id).into(),
            ancestor_height,
        )
        .map_err(PropertyQueryError::GetAncestorError)
    }

    fn get_block_reward(
        &self,
        _block_index: &BlockIndex,
    ) -> Result<Option<common::chain::block::BlockReward>, PropertyQueryError> {
        unimplemented!()
    }
}
