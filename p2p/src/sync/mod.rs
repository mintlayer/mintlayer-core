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
    net::{self, NetworkService, SyncingService},
};
use common::chain::ChainConfig;
use futures::FutureExt;
use logging::log;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::mpsc;

/// State of the peer
enum PeerState {
    /// No activity with the peer
    Idle,
}

struct PeerSyncState<T>
where
    T: NetworkService,
{
    /// Unique peer ID
    peer_id: T::PeerId,

    /// State of the peer
    state: PeerState,
}

/// Sync manager is responsible for syncing the local blockchain to the chain with most trust
/// and keeping up with updates to different branches of the blockchain.
///
/// It keeps track of the state of each individual peer and holds an intermediary block index
/// which represents the local block index of every peer it's connected to.
///
/// Currently its only mode of operation is greedy so it will download all changes from every
/// peer it's connected to and actively keep track of the peer's state.
pub struct SyncManager<T>
where
    T: NetworkService,
{
    /// Handle for sending/receiving connectivity events
    handle: T::SyncingHandle,

    /// RX channel for receiving syncing-related control events
    rx_sync: mpsc::Receiver<event::SyncControlEvent<T>>,

    /// Hashmap of connected peers
    peers: HashMap<T::PeerId, PeerSyncState<T>>,
}

impl<T> SyncManager<T>
where
    T: NetworkService,
    T::SyncingHandle: SyncingService<T>,
{
    pub fn new(
        handle: T::SyncingHandle,
        rx_sync: mpsc::Receiver<event::SyncControlEvent<T>>,
    ) -> Self {
        Self {
            handle,
            rx_sync,
            peers: Default::default(),
        }
    }

    /// Handle incoming block/header request/response
    fn on_syncing_event(&mut self, event: net::SyncingMessage<T>) -> error::Result<()> {
        todo!();
    }

    /// Handle control-related sync event from P2P/SwarmManager
    async fn on_sync_event(&mut self, event: event::SyncControlEvent<T>) -> error::Result<()> {
        match event {
            event::SyncControlEvent::Connected { peer_id } => {
                log::debug!("create new entry for peer {:?}", peer_id);

                if let std::collections::hash_map::Entry::Vacant(e) = self.peers.entry(peer_id) {
                    e.insert(PeerSyncState {
                        peer_id,
                        state: PeerState::Idle,
                    });
                } else {
                    log::error!("peer {:?} already known by sync manager", peer_id);
                }
            }
            event::SyncControlEvent::Disconnected { peer_id } => {
                self.peers
                    .remove(&peer_id)
                    .ok_or_else(|| P2pError::Unknown("Peer does not exist".to_string()))
                    .map(|_| log::debug!("remove peer {:?}", peer_id))
                    .map_err(|_| log::error!("peer {:?} not known by sync manager", peer_id));
            }
        }

        Ok(())
    }

    /// Run SyncManager event loop
    pub async fn run(&mut self) -> error::Result<()> {
        log::info!("starting sync manager event loop");

        loop {
            tokio::select! {
                res = self.handle.poll_next() => {
                    self.on_syncing_event(res?)?;
                }
                res = self.rx_sync.recv().fuse() => {
                    self.on_sync_event(res.ok_or(P2pError::ChannelClosed)?).await?;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{mock::MockService, SyncingService};
    use common::chain::config;
    use std::net::SocketAddr;

    async fn make_sync_manager<T>(
        addr: T::Address,
    ) -> (
        SyncManager<T>,
        mpsc::Sender<event::SyncControlEvent<T>>,
        mpsc::Sender<event::PeerSyncEvent<T>>,
    )
    where
        T: NetworkService,
        T::SyncingHandle: SyncingService<T>,
    {
        let config = Arc::new(config::create_mainnet());
        let (_, _, sync) = T::start(
            addr,
            &[],
            &[],
            Arc::clone(&config),
            std::time::Duration::from_secs(10),
        )
        .await
        .unwrap();

        let (tx_sync, rx_sync) = tokio::sync::mpsc::channel(16);
        let (tx_peer, rx_peer) = tokio::sync::mpsc::channel(16);

        (SyncManager::<T>::new(sync, rx_sync), tx_sync, tx_peer)
    }

    // handle peer connection event
    #[tokio::test]
    async fn test_peer_connected() {
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        let (mut mgr, mut tx_sync, mut tx_peer) = make_sync_manager::<MockService>(addr).await;

        // send Connected event to SyncManager
        let peer_id: SocketAddr = test_utils::make_address("[::1]:");

        assert_eq!(
            mgr.on_sync_event(event::SyncControlEvent::Connected { peer_id }).await,
            Ok(())
        );
        assert_eq!(mgr.peers.len(), 1);
    }

    // handle peer disconnection event
    #[tokio::test]
    async fn test_peer_disconnected() {
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        let (mut mgr, mut tx_sync, mut tx_peer) = make_sync_manager::<MockService>(addr).await;

        // send Connected event to SyncManager
        let peer_id: SocketAddr = test_utils::make_address("[::1]:");

        assert_eq!(
            mgr.on_sync_event(event::SyncControlEvent::Connected { peer_id }).await,
            Ok(())
        );
        assert_eq!(mgr.peers.len(), 1);

        // no peer with this id exist, nothing happens
        assert_eq!(
            mgr.on_sync_event(event::SyncControlEvent::Disconnected { peer_id: addr }).await,
            Ok(())
        );
        assert_eq!(mgr.peers.len(), 1);

        assert_eq!(
            mgr.on_sync_event(event::SyncControlEvent::Disconnected { peer_id }).await,
            Ok(())
        );
        assert!(mgr.peers.is_empty());
    }
}
