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
#![cfg(not(loom))]
#![allow(unused)]
use crate::{
    error::{self, P2pError},
    event,
    net::{self, FloodsubService, NetworkService},
    sync::{self, blkidx, mock_consensus},
};
use tokio::sync::mpsc;

pub struct PeerSyncState<T>
where
    T: NetworkService,
{
    /// Unique peer ID
    peer_id: T::PeerId,

    // State of the peer
    state: sync::SyncState,

    /// TX channel for sending syncing messages to remote peer
    tx: mpsc::Sender<event::PeerEvent<T>>,

    /// Peer block index
    blkidx: Option<blkidx::PeerBlockIndex>,
}

impl<T> PeerSyncState<T>
where
    T: NetworkService,
{
    pub fn new(peer_id: T::PeerId, tx: mpsc::Sender<event::PeerEvent<T>>) -> Self {
        Self {
            peer_id,
            state: sync::SyncState::Idle,
            tx,
            blkidx: None,
        }
    }

    pub fn add_blkidx(&mut self, blkidx: blkidx::PeerBlockIndex) {
        self.blkidx = Some(blkidx);
    }

    pub fn set_state(&mut self, state: sync::SyncState) {
        self.state = state;
    }

    pub async fn get_headers(
        &mut self,
        locator: Vec<mock_consensus::BlockHeader>,
    ) -> error::Result<()> {
        self.tx
            .send(event::PeerEvent::Syncing(
                event::PeerSyncEvent::GetHeaders {
                    peer_id: None,
                    locator,
                },
            ))
            .await
            .map_err(|_| P2pError::ChannelClosed)
    }

    pub async fn send_headers(
        &mut self,
        headers: Vec<mock_consensus::BlockHeader>,
    ) -> error::Result<()> {
        self.tx
            .send(event::PeerEvent::Syncing(event::PeerSyncEvent::Headers {
                peer_id: None,
                headers,
            }))
            .await
            .map_err(|_| P2pError::ChannelClosed)
    }

    pub async fn get_blocks(
        &mut self,
        headers: Vec<mock_consensus::BlockHeader>,
    ) -> error::Result<()> {
        if headers.is_empty() {
            return Ok(());
        }

        self.tx
            .send(event::PeerEvent::Syncing(event::PeerSyncEvent::GetBlocks {
                peer_id: None,
                headers,
            }))
            .await
            .map_err(|_| P2pError::ChannelClosed)
    }

    pub async fn send_blocks(&mut self, blocks: Vec<mock_consensus::Block>) -> error::Result<()> {
        self.tx
            .send(event::PeerEvent::Syncing(event::PeerSyncEvent::Blocks {
                peer_id: None,
                blocks,
            }))
            .await
            .map_err(|_| P2pError::ChannelClosed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::P2pError,
        event::{PeerEvent, PeerSyncEvent},
        net::mock::MockService,
    };
    use std::net::SocketAddr;

    fn new_mock_peersyncstate() -> (
        PeerSyncState<MockService>,
        mpsc::Receiver<event::PeerEvent<MockService>>,
    ) {
        let (tx, rx) = mpsc::channel(1);
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        (PeerSyncState::<MockService>::new(addr, tx), rx)
    }

    #[test]
    fn create_new_peersyncstate() {
        let (peer, rx) = new_mock_peersyncstate();

        assert_eq!(peer.blkidx, None);
        assert_eq!(peer.state, sync::SyncState::Idle);
    }

    #[test]
    fn test_add_block_index() {
        let (mut peer, rx) = new_mock_peersyncstate();

        assert_eq!(peer.blkidx, None);
        assert_eq!(peer.state, sync::SyncState::Idle);

        let blkidx = blkidx::PeerBlockIndex::new();
        peer.add_blkidx(blkidx.clone());

        assert_ne!(peer.blkidx, None);
        assert_eq!(peer.blkidx, Some(blkidx));
    }

    #[test]
    fn test_set_state() {
        let (mut peer, rx) = new_mock_peersyncstate();

        assert_eq!(peer.state, sync::SyncState::Idle);
        peer.set_state(sync::SyncState::DownloadingBlocks);
        assert_eq!(peer.state, sync::SyncState::DownloadingBlocks);
    }

    impl PartialEq for MockService {
        fn eq(&self, _: &Self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn test_get_headers() {
        let (mut peer, mut rx) = new_mock_peersyncstate();

        let locator = vec![mock_consensus::BlockHeader::new(None)];
        assert_eq!(peer.get_headers(locator.clone()).await, Ok(()));
        assert_eq!(
            rx.try_recv(),
            Ok(PeerEvent::Syncing(PeerSyncEvent::GetHeaders {
                peer_id: None,
                locator,
            }))
        );

        drop(rx);
        let headers = vec![mock_consensus::BlockHeader::new(None)];
        assert_eq!(
            peer.get_headers(headers.clone()).await,
            Err(P2pError::ChannelClosed)
        );
    }

    #[tokio::test]
    async fn test_send_headers() {
        let (mut peer, mut rx) = new_mock_peersyncstate();

        let headers = vec![mock_consensus::BlockHeader::new(None)];
        assert_eq!(peer.send_headers(headers.clone()).await, Ok(()));
        assert_eq!(
            rx.try_recv(),
            Ok(PeerEvent::Syncing(PeerSyncEvent::Headers {
                peer_id: None,
                headers,
            }))
        );

        drop(rx);
        let headers = vec![mock_consensus::BlockHeader::new(None)];
        assert_eq!(
            peer.send_headers(headers.clone()).await,
            Err(P2pError::ChannelClosed)
        );
    }

    #[tokio::test]
    async fn test_get_blocks() {
        let (mut peer, mut rx) = new_mock_peersyncstate();

        let headers = vec![mock_consensus::BlockHeader::new(None)];
        assert_eq!(peer.get_blocks(headers.clone()).await, Ok(()));
        assert_eq!(
            rx.try_recv(),
            Ok(PeerEvent::Syncing(PeerSyncEvent::GetBlocks {
                peer_id: None,
                headers,
            }))
        );

        // no block headers
        assert_eq!(peer.get_blocks(vec![]).await, Ok(()));
        assert_eq!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        );

        drop(rx);
        let headers = vec![mock_consensus::BlockHeader::new(None)];
        assert_eq!(
            peer.get_blocks(headers.clone()).await,
            Err(P2pError::ChannelClosed)
        );
    }

    #[tokio::test]
    async fn test_send_blocks() {
        let (mut peer, mut rx) = new_mock_peersyncstate();

        let blocks = vec![mock_consensus::Block::new(None)];
        assert_eq!(peer.send_blocks(blocks.clone()).await, Ok(()));
        assert_eq!(
            rx.try_recv(),
            Ok(PeerEvent::Syncing(PeerSyncEvent::Blocks {
                peer_id: None,
                blocks,
            }))
        );

        drop(rx);
        let blocks = vec![mock_consensus::Block::new(None)];
        assert_eq!(
            peer.send_blocks(blocks.clone()).await,
            Err(P2pError::ChannelClosed)
        );
    }
}
