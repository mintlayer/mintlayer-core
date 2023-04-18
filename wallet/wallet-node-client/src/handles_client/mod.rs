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

use chainstate::{ChainstateError, ChainstateHandle};
use common::{
    chain::{Block, GenBlock},
    primitives::{BlockHeight, Id},
};

use crate::node_traits::NodeInterface;

pub struct WalletHandlesClient {
    chainstate_handle: ChainstateHandle,
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum WalletHandlesClientError {
    #[error("Call error: {0}")]
    CallError(#[from] subsystem::subsystem::CallError),
    #[error("Chainstate error: {0}")]
    ChainstateError(#[from] ChainstateError),
}

impl WalletHandlesClient {
    pub async fn new(
        chainstate_handle: ChainstateHandle,
    ) -> Result<Self, WalletHandlesClientError> {
        let result = Self { chainstate_handle };
        result.basic_start_test().await?;
        Ok(result)
    }

    async fn basic_start_test(&self) -> Result<(), WalletHandlesClientError> {
        // Call an arbitrary function to make sure that connection is established
        let _best_block =
            self.chainstate_handle.call(move |this| this.get_best_block_id()).await??;

        Ok(())
    }
}

#[async_trait::async_trait]
impl NodeInterface for WalletHandlesClient {
    type Error = WalletHandlesClientError;

    async fn get_best_block_id(&self) -> Result<Id<GenBlock>, Self::Error> {
        let result = self.chainstate_handle.call(move |this| this.get_best_block_id()).await??;
        Ok(result)
    }

    async fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, Self::Error> {
        let result = self.chainstate_handle.call(move |this| this.get_block(block_id)).await??;
        Ok(result)
    }

    async fn get_best_block_height(&self) -> Result<BlockHeight, Self::Error> {
        let result =
            self.chainstate_handle.call(move |this| this.get_best_block_height()).await??;
        Ok(result)
    }

    async fn get_block_id_at_height(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, Self::Error> {
        let result = self
            .chainstate_handle
            .call(move |this| this.get_block_id_from_height(&height))
            .await??;
        Ok(result)
    }
}
