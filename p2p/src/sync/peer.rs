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
    sync::{self, index, mock_consensus},
};
use logging::log;
use tokio::sync::mpsc;

/// State of the peer
#[derive(Debug, PartialEq, Eq)]
pub enum PeerSyncState {
    /// Peer state is unknown
    Unknown,

    /// Peer is uploading blocks to local node
    UploadingBlocks,

    /// Peer is uploading headers to local node
    UploadingHeaders,

    /// Peer is idling and can be used for block requests
    Idle,
}

/// Syncing-related context of the peer
pub struct PeerContext<T>
where
    T: NetworkService,
{
    /// Unique peer ID
    peer_id: T::PeerId,

    /// State of the peer
    state: PeerSyncState,

    /// TX channel for sending syncing messages to remote peer
    tx: mpsc::Sender<event::PeerEvent<T>>,

    /// Peer block index
    index: index::PeerIndex,
}

impl<T> PeerContext<T>
where
    T: NetworkService,
{
    pub fn new(peer_id: T::PeerId, tx: mpsc::Sender<event::PeerEvent<T>>) -> Self {
        Self {
            peer_id,
            state: PeerSyncState::Unknown,
            tx,
            index: index::PeerIndex::new(),
        }
    }

    /// Set peer state
    pub fn set_state(&mut self, state: PeerSyncState) {
        self.state = state;
    }

    /// Get peer state
    pub fn state(&self) -> &PeerSyncState {
        &self.state
    }

    /// Get the intermediary index of the peer
    pub fn index(&self) -> &index::PeerIndex {
        &self.index
    }

    /// Initialize the intermediary index with headers
    pub fn initialize_index(&mut self, headers: &[mock_consensus::BlockHeader]) {
        self.index.initialize(headers);
    }

    // TODO: rename `add_block()` -> `register_block()`

    /// Register block to the intermediary index of the peer
    pub fn add_block(
        &mut self,
        block: &mock_consensus::Block,
    ) -> error::Result<index::PeerIndexState> {
        log::trace!(
            "block ({:?}) accepted to peer's ({:?}) intermediary index",
            block,
            self.peer_id
        );

        self.index.add_block(block.header).map_err(|e| {
            log::error!(
                "failed to add block to peer's ({:#?}) intermediary index",
                self.peer_id
            );
            e
        })
    }

    /// Requests headers from remote using `locator`
    pub async fn get_headers(
        &mut self,
        locator: Vec<mock_consensus::BlockHeader>,
    ) -> error::Result<()> {
        log::trace!(
            "send header request {:#?} to remote peer {:?}",
            locator,
            self.peer_id
        );

        self.state = PeerSyncState::UploadingHeaders;
        self.tx
            .send(event::PeerEvent::Syncing(event::SyncEvent::GetHeaders {
                locator,
            }))
            .await
            .map_err(|_| P2pError::ChannelClosed)
    }

    /// Send `headers` to remote node
    pub async fn send_headers(
        &mut self,
        headers: Vec<mock_consensus::BlockHeader>,
    ) -> error::Result<()> {
        log::trace!(
            "send headers {:#?} to remote peer {:?}",
            headers,
            self.peer_id
        );

        // TODO: race condition here?
        self.state = PeerSyncState::Idle;
        self.tx
            .send(event::PeerEvent::Syncing(event::SyncEvent::Headers {
                headers,
            }))
            .await
            .map_err(|_| P2pError::ChannelClosed)
    }

    /// Request `blocks` from remote node
    pub async fn get_blocks(
        &mut self,
        headers: Vec<mock_consensus::BlockHeader>,
    ) -> error::Result<()> {
        if headers.is_empty() {
            return Ok(());
        }

        log::trace!(
            "send block request {:#?} to remote peer {:?}",
            headers,
            self.peer_id
        );

        self.state = PeerSyncState::UploadingBlocks;
        self.tx
            .send(event::PeerEvent::Syncing(event::SyncEvent::GetBlocks {
                headers,
            }))
            .await
            .map_err(|_| P2pError::ChannelClosed)
    }

    /// Send `blocks` to remote node
    pub async fn send_blocks(&mut self, blocks: Vec<mock_consensus::Block>) -> error::Result<()> {
        log::trace!(
            "send blocks {:#?} to remote peer {:?}",
            blocks,
            self.peer_id
        );

        self.state = PeerSyncState::Idle;
        self.tx
            .send(event::PeerEvent::Syncing(event::SyncEvent::Blocks {
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
        event::{PeerEvent, PeerSyncEvent, SyncEvent},
        net::mock::MockService,
    };
    use std::net::SocketAddr;

    fn new_mock_peersyncstate() -> (
        PeerContext<MockService>,
        mpsc::Receiver<event::PeerEvent<MockService>>,
    ) {
        let (tx, rx) = mpsc::channel(1);
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        (PeerContext::<MockService>::new(addr, tx), rx)
    }

    #[test]
    fn create_new_peersyncstate() {
        let (peer, rx) = new_mock_peersyncstate();
        assert_eq!(peer.state, PeerSyncState::Unknown);
    }

    #[test]
    fn test_set_state() {
        let (mut peer, rx) = new_mock_peersyncstate();

        assert_eq!(peer.state, PeerSyncState::Unknown);
        peer.set_state(PeerSyncState::UploadingBlocks);
        assert_eq!(peer.state, PeerSyncState::UploadingBlocks);
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
            Ok(PeerEvent::Syncing(SyncEvent::GetHeaders { locator }))
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
            Ok(PeerEvent::Syncing(SyncEvent::Headers { headers }))
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
            Ok(PeerEvent::Syncing(SyncEvent::GetBlocks { headers }))
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
            Ok(PeerEvent::Syncing(SyncEvent::Blocks { blocks }))
        );

        drop(rx);
        let blocks = vec![mock_consensus::Block::new(None)];
        assert_eq!(
            peer.send_blocks(blocks.clone()).await,
            Err(P2pError::ChannelClosed)
        );
    }

    #[tokio::test]
    async fn add_blocks_before_headers() {
        let (mut peer, mut rx) = new_mock_peersyncstate();
        let block1 = mock_consensus::Block::new(Some(444));
        let block1_1 = mock_consensus::Block::new(Some(block1.header.id));
        let block1_1_1 = mock_consensus::Block::new(Some(block1_1.header.id));

        assert_eq!(peer.add_block(&block1), Ok(index::PeerIndexState::Queued));
        assert_eq!(peer.add_block(&block1_1), Ok(index::PeerIndexState::Queued));
        assert_eq!(
            peer.add_block(&block1_1_1),
            Ok(index::PeerIndexState::Queued)
        );

        assert_eq!(peer.index.queue().num_chains(), 1);
        assert_eq!(peer.index.queue().num_queued(), 3);

        let headers = &[
            mock_consensus::BlockHeader::with_id(444, Some(333)),
            mock_consensus::BlockHeader::with_id(666, Some(555)),
            mock_consensus::BlockHeader::with_id(777, Some(666)),
        ];
        peer.initialize_index(headers);
        assert_eq!(peer.index.queue().num_chains(), 0);
        assert_eq!(peer.index.queue().num_queued(), 0);
    }

    // TODO: add more tests
}
