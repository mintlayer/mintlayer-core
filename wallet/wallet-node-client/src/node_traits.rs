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

use chainstate::ChainInfo;
use common::{
    chain::{Block, GenBlock},
    primitives::{BlockHeight, Id},
};

pub use p2p::{interface::types::ConnectedPeer, types::peer_id::PeerId};

#[async_trait::async_trait]
pub trait NodeInterface {
    type Error: std::error::Error + Send + Sync;

    async fn chainstate_info(&self) -> Result<ChainInfo, Self::Error>;
    async fn get_best_block_id(&self) -> Result<Id<GenBlock>, Self::Error>;
    async fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, Self::Error>;
    async fn get_best_block_height(&self) -> Result<BlockHeight, Self::Error>;
    async fn get_block_id_at_height(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, Self::Error>;
    async fn get_last_common_ancestor(
        &self,
        first_block: Id<GenBlock>,
        second_block: Id<GenBlock>,
    ) -> Result<Option<(Id<GenBlock>, BlockHeight)>, Self::Error>;
    async fn submit_block(&self, block_hex: String) -> Result<(), Self::Error>;
    async fn submit_transaction(&self, transaction_hex: String) -> Result<(), Self::Error>;

    async fn node_shutdown(&self) -> Result<(), Self::Error>;
    async fn node_version(&self) -> Result<String, Self::Error>;

    async fn p2p_connect(&self, address: String) -> Result<(), Self::Error>;
    async fn p2p_disconnect(&self, peer_id: PeerId) -> Result<(), Self::Error>;
    async fn p2p_get_peer_count(&self) -> Result<usize, Self::Error>;
    async fn p2p_get_connected_peers(&self) -> Result<Vec<ConnectedPeer>, Self::Error>;
    async fn p2p_add_reserved_node(&self, address: String) -> Result<(), Self::Error>;
    async fn p2p_remove_reserved_node(&self, address: String) -> Result<(), Self::Error>;
}
