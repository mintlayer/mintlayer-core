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

use chainstate::{BlockSource, ChainInfo, ChainstateError, ChainstateHandle};
use common::{
    chain::{Block, GenBlock},
    primitives::{BlockHeight, Id},
};
use p2p::{interface::types::ConnectedPeer, types::peer_id::PeerId};
use serialization::hex::{HexDecode, HexError};

use crate::node_traits::NodeInterface;

#[derive(Clone)]
pub struct WalletHandlesClient {
    chainstate_handle: ChainstateHandle,
}

#[derive(thiserror::Error, Debug, Clone, PartialEq)]
pub enum WalletHandlesClientError {
    #[error("Call error: {0}")]
    CallError(#[from] subsystem::subsystem::CallError),
    #[error("Chainstate error: {0}")]
    ChainstateError(#[from] ChainstateError),
    #[error("Decode error: {0}")]
    HexError(#[from] HexError),
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

    async fn chainstate_info(&self) -> Result<ChainInfo, Self::Error> {
        let result = self.chainstate_handle.call(move |this| this.info()).await??;
        Ok(result)
    }

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

    async fn get_last_common_block(
        &self,
        first_block: Id<GenBlock>,
        second_block: Id<GenBlock>,
    ) -> Result<Option<(Id<GenBlock>, BlockHeight)>, Self::Error> {
        let result = self
            .chainstate_handle
            .call(move |this| this.last_common_block(&first_block, &second_block))
            .await??;
        Ok(result)
    }

    async fn submit_block(&self, block_hex: String) -> Result<(), Self::Error> {
        let block = Block::hex_decode_all(&block_hex)?;
        self.chainstate_handle
            .call_mut(move |this| this.process_block(block, BlockSource::Local))
            .await??;
        Ok(())
    }

    async fn submit_transaction(&self, _transaction_hex: String) -> Result<(), Self::Error> {
        unimplemented!()
    }

    async fn node_shutdown(&self) -> Result<(), Self::Error> {
        unimplemented!()
    }
    async fn node_version(&self) -> Result<String, Self::Error> {
        unimplemented!()
    }

    async fn p2p_connect(&self, _address: String) -> Result<(), Self::Error> {
        unimplemented!()
    }
    async fn p2p_disconnect(&self, _peer_id: PeerId) -> Result<(), Self::Error> {
        unimplemented!()
    }
    async fn p2p_get_peer_count(&self) -> Result<usize, Self::Error> {
        unimplemented!()
    }
    async fn p2p_get_connected_peers(&self) -> Result<Vec<ConnectedPeer>, Self::Error> {
        unimplemented!()
    }
    async fn p2p_add_reserved_node(&self, _address: String) -> Result<(), Self::Error> {
        unimplemented!()
    }
    async fn p2p_remove_reserved_node(&self, _address: String) -> Result<(), Self::Error> {
        unimplemented!()
    }
}
