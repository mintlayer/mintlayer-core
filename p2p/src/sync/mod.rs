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

    // State of the peer
    state: PeerState,

    /// TX channel for sending syncing messages to remote peer
    tx: mpsc::Sender<event::PeerEvent<T>>,
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
    /// Chain config
    config: Arc<ChainConfig>,

    /// Handle for sending/receiving connectivity events
    handle: T::FloodsubHandle,

    /// RX channel for receiving syncing-related control events
    rx_sync: mpsc::Receiver<event::SyncControlEvent<T>>,

    /// RX channel for receiving syncing events from peers
    rx_peer: mpsc::Receiver<event::PeerSyncEvent<T>>,

    /// Hashmap of connected peers
    peers: HashMap<T::PeerId, PeerSyncState<T>>,
}

impl<T> SyncManager<T>
where
    T: NetworkService,
    T::FloodsubHandle: FloodsubService<T>,
{
    pub fn new(
        config: Arc<ChainConfig>,
        handle: T::FloodsubHandle,
        rx_sync: mpsc::Receiver<event::SyncControlEvent<T>>,
        rx_peer: mpsc::Receiver<event::PeerSyncEvent<T>>,
    ) -> Self {
        Self {
            config,
            handle,
            rx_sync,
            rx_peer,
            peers: Default::default(),
        }
    }

    /// Handle floodsub event
    fn on_floodsub_event(&mut self, event: net::FloodsubEvent<T>) -> error::Result<()> {
        let net::FloodsubEvent::MessageReceived {
            peer_id: _,
            topic,
            message,
        } = event;

        match topic {
            net::FloodsubTopic::Transactions => {
                log::debug!("received new transaction: {:#?}", message);
            }
            net::FloodsubTopic::Blocks => {
                log::debug!("received new block: {:#?}", message);
            }
        }

        Ok(())
    }

    /// Handle control-related sync event from P2P/SwarmManager
    async fn on_sync_event(&mut self, event: event::SyncControlEvent<T>) -> error::Result<()> {
        todo!();
    }

    /// Handle syncing-related event received from a remote peer
    async fn on_peer_event(&mut self, event: event::PeerSyncEvent<T>) -> error::Result<()> {
        todo!();
    }

    /// Run SyncManager event loop
    pub async fn run(&mut self) -> error::Result<()> {
        log::info!("starting sync manager event loop");

        loop {
            tokio::select! {
                res = self.handle.poll_next() => {
                    self.on_floodsub_event(res?)?;
                }
                res = self.rx_sync.recv().fuse() => {
                    self.on_sync_event(res.ok_or(P2pError::ChannelClosed)?).await?;
                }
                res = self.rx_peer.recv().fuse() => {
                    self.on_peer_event(res.ok_or(P2pError::ChannelClosed)?).await?;
                }
            }
        }
    }
}
