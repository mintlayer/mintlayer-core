// Copyright (c) 2022 RBB S.r.l
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
// Author(s): A. Altonen
use crate::{
    error::{P2pError, ProtocolError},
    net::NetworkingService,
};
use common::{
    chain::block::{Block, BlockHeader},
    primitives::{Id, Idable},
};
use logging::log;
use std::collections::VecDeque;

/// State of the peer
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerSyncState {
    /// Peer state is unknown
    Unknown,

    /// Peer is uploading blocks to local node
    UploadingBlocks(Id<Block>),

    /// Peer is uploading headers to local node
    UploadingHeaders(Vec<BlockHeader>),

    /// Peer is idling and can be used for block requests
    Idle,
}

/// Syncing-related context of the peer
pub struct PeerContext<T>
where
    T: NetworkingService,
{
    /// Unique peer ID
    peer_id: T::PeerId,

    /// State of the peer
    state: PeerSyncState,

    /// Locator that was sent to the peer
    /// Used to verify header response and pick unknown headers
    locator: Vec<BlockHeader>,

    /// List of block headers indicating which blocks
    /// still need to be downloaded from the remote peer
    work: VecDeque<BlockHeader>,
}

impl<T> PeerContext<T>
where
    T: NetworkingService,
{
    pub fn new(peer_id: T::PeerId, locator: Vec<BlockHeader>) -> Self {
        Self {
            peer_id,
            locator,
            state: PeerSyncState::Unknown,
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
                if expected != &header.get_id() {
                    log::error!(
                        "peer {:?} sent us the wrong header, expected {:?}, got {:?}",
                        self.peer_id,
                        expected,
                        header
                    );
                    // TODO: this is a protocol error
                    return Err(P2pError::ProtocolError(ProtocolError::InvalidMessage));
                }
            }
            _ => {
                // TODO: this is a protocol error
                log::error!(
                    "received a header from peer {:?} while not expecting it",
                    self.peer_id
                );
                return Err(P2pError::ProtocolError(ProtocolError::InvalidMessage));
            }
        }

        Ok(self.get_next_block())
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

    pub fn set_locator(&mut self, locator: Vec<BlockHeader>) {
        self.locator = locator;
    }

    pub fn locator(&self) -> &Vec<BlockHeader> {
        &self.locator
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::mock::MockService;
    use common::chain::block::{consensus_data::ConsensusData, timestamp::BlockTimestamp};
    use std::net::SocketAddr;

    fn new_mock_peersyncstate() -> PeerContext<MockService> {
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        PeerContext::<MockService>::new(addr, vec![])
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
            None,
            BlockTimestamp::from_int_seconds(1337u32),
            ConsensusData::None,
        )
        .unwrap()
        .header()
        .clone();

        assert_eq!(peer.state, PeerSyncState::Unknown);
        peer.set_state(PeerSyncState::UploadingBlocks(header.get_id()));
        assert_eq!(peer.state, PeerSyncState::UploadingBlocks(header.get_id()));
    }
}
