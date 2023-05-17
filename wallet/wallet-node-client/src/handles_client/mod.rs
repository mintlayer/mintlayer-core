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

use blockprod::{BlockProductionError, BlockProductionHandle};
use chainstate::{BlockSource, ChainInfo, ChainstateError, ChainstateHandle};
use common::{
    chain::{Block, GenBlock, SignedTransaction},
    primitives::{BlockHeight, Id},
};
use mempool::MempoolHandle;
use p2p::{error::P2pError, interface::types::ConnectedPeer, types::peer_id::PeerId, P2pHandle};
use serialization::hex::{HexDecode, HexEncode, HexError};

use crate::node_traits::NodeInterface;

#[derive(Clone)]
pub struct WalletHandlesClient {
    chainstate: ChainstateHandle,
    _mempool: MempoolHandle,
    block_prod: BlockProductionHandle,
    p2p: P2pHandle,
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum WalletHandlesClientError {
    #[error("Call error: {0}")]
    CallError(#[from] subsystem::subsystem::CallError),
    #[error("Chainstate error: {0}")]
    Chainstate(#[from] ChainstateError),
    #[error("P2p error: {0}")]
    P2p(#[from] P2pError),
    #[error("Block production error: {0}")]
    BlockProduction(#[from] BlockProductionError),
    #[error("Decode error: {0}")]
    Hex(#[from] HexError),
}

impl WalletHandlesClient {
    pub async fn new(
        chainstate: ChainstateHandle,
        mempool: MempoolHandle,
        block_prod: BlockProductionHandle,
        p2p: P2pHandle,
    ) -> Result<Self, WalletHandlesClientError> {
        let result = Self {
            chainstate,
            _mempool: mempool,
            block_prod,
            p2p,
        };
        result.basic_start_test().await?;
        Ok(result)
    }

    async fn basic_start_test(&self) -> Result<(), WalletHandlesClientError> {
        // Call an arbitrary function to make sure that connection is established
        let _best_block = self.chainstate.call(move |this| this.get_best_block_id()).await??;

        Ok(())
    }
}

#[async_trait::async_trait]
impl NodeInterface for WalletHandlesClient {
    type Error = WalletHandlesClientError;

    async fn chainstate_info(&self) -> Result<ChainInfo, Self::Error> {
        let result = self.chainstate.call(move |this| this.info()).await??;
        Ok(result)
    }

    async fn get_best_block_id(&self) -> Result<Id<GenBlock>, Self::Error> {
        let result = self.chainstate.call(move |this| this.get_best_block_id()).await??;
        Ok(result)
    }

    async fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, Self::Error> {
        let result = self.chainstate.call(move |this| this.get_block(block_id)).await??;
        Ok(result)
    }

    async fn get_best_block_height(&self) -> Result<BlockHeight, Self::Error> {
        let result = self.chainstate.call(move |this| this.get_best_block_height()).await??;
        Ok(result)
    }

    async fn get_block_id_at_height(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, Self::Error> {
        let result = self
            .chainstate
            .call(move |this| this.get_block_id_from_height(&height))
            .await??;
        Ok(result)
    }

    async fn get_last_common_ancestor(
        &self,
        first_block: Id<GenBlock>,
        second_block: Id<GenBlock>,
    ) -> Result<Option<(Id<GenBlock>, BlockHeight)>, Self::Error> {
        let result = self
            .chainstate
            .call(move |this| this.last_common_ancestor_by_id(&first_block, &second_block))
            .await??;
        Ok(result)
    }

    async fn generate_block(
        &self,
        reward_destination_hex: String,
        transactions_hex: Option<Vec<String>>,
    ) -> Result<String, Self::Error> {
        let reward_destination =
            common::chain::Destination::hex_decode_all(reward_destination_hex)?;
        let signed_transactions = transactions_hex
            .map(|txs| {
                txs.into_iter()
                    .map(SignedTransaction::hex_decode_all)
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;

        let block = self
            .block_prod
            .call_async_mut(move |this| {
                this.generate_block(reward_destination, signed_transactions)
            })
            .await??;

        Ok(block.hex_encode())
    }

    async fn submit_block(&self, block_hex: String) -> Result<(), Self::Error> {
        let block = Block::hex_decode_all(&block_hex)?;
        self.chainstate
            .call_mut(move |this| this.process_block(block, BlockSource::Local))
            .await??;
        Ok(())
    }

    async fn submit_transaction(&self, transaction_hex: String) -> Result<(), Self::Error> {
        let tx = SignedTransaction::hex_decode_all(&transaction_hex)?;
        self.p2p.call_async_mut(move |this| this.submit_transaction(tx)).await??;
        Ok(())
    }

    async fn node_shutdown(&self) -> Result<(), Self::Error> {
        unimplemented!()
    }
    async fn node_version(&self) -> Result<String, Self::Error> {
        unimplemented!()
    }

    async fn p2p_connect(&self, address: String) -> Result<(), Self::Error> {
        self.p2p.call_async_mut(move |this| this.connect(address)).await??;
        Ok(())
    }
    async fn p2p_disconnect(&self, peer_id: PeerId) -> Result<(), Self::Error> {
        self.p2p.call_async_mut(move |this| this.disconnect(peer_id)).await??;
        Ok(())
    }
    async fn p2p_get_peer_count(&self) -> Result<usize, Self::Error> {
        let count = self.p2p.call_async_mut(move |this| this.get_peer_count()).await??;
        Ok(count)
    }
    async fn p2p_get_connected_peers(&self) -> Result<Vec<ConnectedPeer>, Self::Error> {
        let peers = self.p2p.call_async_mut(move |this| this.get_connected_peers()).await??;
        Ok(peers)
    }
    async fn p2p_add_reserved_node(&self, address: String) -> Result<(), Self::Error> {
        self.p2p.call_async_mut(move |this| this.add_reserved_node(address)).await??;
        Ok(())
    }
    async fn p2p_remove_reserved_node(&self, address: String) -> Result<(), Self::Error> {
        self.p2p
            .call_async_mut(move |this| this.remove_reserved_node(address))
            .await??;
        Ok(())
    }
}
