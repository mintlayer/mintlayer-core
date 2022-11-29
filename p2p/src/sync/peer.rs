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

use crate::{
    error::{P2pError, ProtocolError},
    net::NetworkingService,
};
use chainstate::Locator;
use common::{
    chain::block::{Block, BlockHeader},
    primitives::{Id, Idable},
};
use std::collections::VecDeque;
use utils::ensure;

/// State of the peer
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerSyncState {
    /// Peer state is unknown
    Unknown,

    /// Peer is uploading blocks to local node
    UploadingBlocks(Id<Block>),

    /// Peer is uploading headers to local node
    UploadingHeaders(Locator),

    /// Peer is idling and can be used for block requests
    Idle,
}

/// Syncing-related context of the peer
pub struct PeerContext<T>
where
    T: NetworkingService,
{
    /// Unique peer ID
    _peer_id: T::PeerId,

    /// State of the peer
    state: PeerSyncState,

    /// List of block headers indicating which blocks
    /// still need to be downloaded from the remote peer
    work: VecDeque<BlockHeader>,
}

impl<T: NetworkingService> PeerContext<T> {
    pub fn new(_peer_id: T::PeerId) -> Self {
        Self {
            _peer_id,
            state: PeerSyncState::Unknown,
            work: VecDeque::new(),
        }
    }

    pub fn new_with_locator(_peer_id: T::PeerId, locator: Locator) -> Self {
        Self {
            _peer_id,
            state: PeerSyncState::UploadingHeaders(locator),
            work: VecDeque::new(),
        }
    }

    pub fn register_header_response(&mut self, headers: &[BlockHeader]) {
        self.state = PeerSyncState::Idle;
        self.work = VecDeque::from(headers.to_vec());
    }

    pub fn get_header_for_download(&mut self) -> Option<BlockHeader> {
        self.get_next_block()
    }

    pub fn register_block_response(
        &mut self,
        header: &BlockHeader,
    ) -> crate::Result<Option<BlockHeader>> {
        match &self.state {
            PeerSyncState::UploadingBlocks(expected) => {
                ensure!(
                    expected == &header.get_id(),
                    P2pError::ProtocolError(ProtocolError::InvalidMessage),
                );

                Ok(self.get_next_block())
            }
            PeerSyncState::Idle | PeerSyncState::Unknown | PeerSyncState::UploadingHeaders(_) => {
                Err(P2pError::ProtocolError(ProtocolError::InvalidMessage))
            }
        }
    }

    fn get_next_block(&mut self) -> Option<BlockHeader> {
        self.work.pop_front()
    }

    /// Set peer state
    pub fn set_state(&mut self, state: PeerSyncState) {
        self.state = state;
    }

    /// Get peer state
    pub fn state(&self) -> &PeerSyncState {
        &self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::mock::{transport::TcpTransportSocket, types, MockService};
    use common::chain::block::{
        consensus_data::ConsensusData, timestamp::BlockTimestamp, BlockReward,
    };
    use std::net::SocketAddr;

    fn new_mock_peersyncstate() -> PeerContext<MockService<TcpTransportSocket>> {
        let addr: SocketAddr = "[::1]:8888".parse().unwrap();
        PeerContext::<MockService<TcpTransportSocket>>::new(
            types::MockPeerId::from_socket_address::<TcpTransportSocket>(&addr),
        )
    }

    #[test]
    fn create_new_peersyncstate() {
        let peer = new_mock_peersyncstate();
        assert_eq!(peer.state, PeerSyncState::Unknown);
    }

    #[test]
    fn test_set_state() {
        let mut peer = new_mock_peersyncstate();
        let header = Block::new(
            vec![],
            Id::new(common::primitives::H256([0x07; 32])),
            BlockTimestamp::from_int_seconds(1337u64),
            ConsensusData::None,
            BlockReward::new(Vec::new()),
        )
        .unwrap()
        .header()
        .clone();

        assert_eq!(peer.state, PeerSyncState::Unknown);
        peer.set_state(PeerSyncState::UploadingBlocks(header.get_id()));
        assert_eq!(peer.state, PeerSyncState::UploadingBlocks(header.get_id()));
    }
}
