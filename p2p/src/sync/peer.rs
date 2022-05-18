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
#![allow(unused)]

use crate::{
    error::{self, P2pError},
    event,
    net::{self, NetworkingService},
    sync,
};
use common::chain::block::{Block, BlockHeader};
use logging::log;
use std::collections::{HashSet, VecDeque};
use tokio::sync::mpsc;

/// State of the peer
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerSyncState {
    /// Peer state is unknown
    Unknown,

    /// Peer is uploading blocks to local node
    UploadingBlocks(BlockHeader),

    /// Peer is uploading headers to local node
    UploadingHeaders,

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

    /// List of block headers indicating which blocks
    /// still need to be downloaded from the remote peer
    work: VecDeque<BlockHeader>,
}

impl<T> PeerContext<T>
where
    T: NetworkingService,
{
    pub fn new(peer_id: T::PeerId) -> Self {
        Self {
            peer_id,
            state: PeerSyncState::Unknown,
            work: VecDeque::new(),
        }
    }

    pub fn register_headers(&mut self, headers: &[BlockHeader]) -> Option<BlockHeader> {
        self.state = PeerSyncState::Idle;
        self.work = VecDeque::from(headers.to_vec());
        self.get_next_block()
    }

    pub fn register_block_response(
        &mut self,
        header: &BlockHeader,
    ) -> error::Result<Option<BlockHeader>> {
        match &self.state {
            PeerSyncState::UploadingBlocks(expected) => {
                if expected != header {
                    log::error!(
                        "peer sent us the wrong header, expected {:?}, got {:?}",
                        expected,
                        header
                    );
                    return Err(P2pError::InvalidData);
                }
            }
            _ => {
                log::error!("received a header from peer while not expecting it");
                return Err(P2pError::InvalidData);
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{error::P2pError, net::mock::MockService};
    use common::chain::block::consensus_data::ConsensusData;
    use std::net::SocketAddr;

    fn new_mock_peersyncstate() -> PeerContext<MockService> {
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        PeerContext::<MockService>::new(addr)
    }

    #[test]
    fn create_new_peersyncstate() {
        let peer = new_mock_peersyncstate();
        assert_eq!(peer.state, PeerSyncState::Unknown);
    }

    #[test]
    fn test_set_state() {
        let mut peer = new_mock_peersyncstate();
        let header =
            Block::new(vec![], None, 1337u32, ConsensusData::None).unwrap().header().clone();

        assert_eq!(peer.state, PeerSyncState::Unknown);
        peer.set_state(PeerSyncState::UploadingBlocks(header.clone()));
        assert_eq!(peer.state, PeerSyncState::UploadingBlocks(header));
    }
}
