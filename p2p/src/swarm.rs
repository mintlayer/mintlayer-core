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
#![allow(unused, dead_code)]

///! Swarm manager
///!
///! Swarm manager is responsible for handling all peer- and connectivity-related tasks
///! of the P2P subsystem. By swarm, we mean a collection of peers we know about or are
///! connected to. All connectivity-related events (incoming connections, peer discovery
///! and expiration) are received from the network service provider and the swarm manager
///! then decided when it needs to establish new outbound connctions and who are the peers
///! it tries to connect to. It also accepts or rejects new incoming connections based on
///! the number of active connections it has.
///!
///! After a connection has been received/established, the swarm manager creates a Peer object
///! and spawns a task for that peer. The first thing the task does is handshake with the remote
///! peer and the result of that handshake (success/failure) is reported to the swarm manager
///! which then either reports that information to other subsystems of P2P that need that
///! information or considers the peer invalid and destroys any context it had.
use crate::{
    error::{self, P2pError},
    event::{self, PeerEvent, PeerSwarmEvent},
    net::{self, ConnectivityService, NetworkService},
    peer::{Peer, PeerRole},
};
use common::chain::ChainConfig;
use futures::FutureExt;
use logging::log;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::mpsc;

const MAX_ACTIVE_CONNECTIONS: usize = 32;

#[allow(unused)]
#[derive(Debug, PartialEq, Eq)]
enum PeerState {
    /// Peer is handshaking
    Handshaking,

    /// Peer is ready for flooding/syncing
    Active,
}

#[allow(unused)]
#[derive(Debug)]
struct PeerContext<T>
where
    T: NetworkService,
{
    /// Unique peer ID
    id: T::PeerId,

    /// Peer sta
    state: PeerState,

    /// Channel for communication with the peer
    tx: mpsc::Sender<event::PeerEvent<T>>,
}

#[allow(unused)]
enum PeerAddrInfo<T>
where
    T: NetworkService,
{
    Raw {
        /// Hashset of IPv4 addresses
        ip4: HashSet<Arc<T::Address>>,

        /// Hashset of IPv6 addresses
        ip6: HashSet<Arc<T::Address>>,
    },
}

pub struct SwarmManager<T>
where
    T: NetworkService,
{
    /// Chain config
    config: Arc<ChainConfig>,

    /// Handle for sending/receiving connectivity events
    handle: T::ConnectivityHandle,

    /// Hashmap for peer information
    peers: HashMap<T::PeerId, PeerContext<T>>,

    /// Hashmap of discovered peers we don't have an active connection with
    discovered: HashMap<T::PeerId, PeerAddrInfo<T>>,

    /// Peer backlog maximum size
    peer_backlock: usize,

    /// RX channel for receiving control events
    rx_swarm: mpsc::Receiver<event::SwarmControlEvent<T>>,

    /// TX channel for sending events to SyncManager
    tx_sync: mpsc::Sender<event::SyncControlEvent<T>>,

    /// TX channel given to Peer objects for communication with SyncManager
    tx_peer_sync: mpsc::Sender<event::PeerSyncEvent<T>>,

    /// Channel for p2p<->peers communication
    mgr_chan: (
        mpsc::Sender<event::PeerSwarmEvent<T>>,
        mpsc::Receiver<event::PeerSwarmEvent<T>>,
    ),
}

impl<T> SwarmManager<T>
where
    T: NetworkService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    pub fn new(
        config: Arc<ChainConfig>,
        handle: T::ConnectivityHandle,
        rx_swarm: mpsc::Receiver<event::SwarmControlEvent<T>>,
        tx_sync: mpsc::Sender<event::SyncControlEvent<T>>,
        tx_peer_sync: mpsc::Sender<event::PeerSyncEvent<T>>,
        mgr_backlog: usize,
        peer_backlock: usize,
    ) -> Self {
        Self {
            config,
            handle,
            peer_backlock,
            rx_swarm,
            tx_sync,
            tx_peer_sync,
            peers: HashMap::with_capacity(MAX_ACTIVE_CONNECTIONS),
            discovered: HashMap::new(),
            mgr_chan: tokio::sync::mpsc::channel(mgr_backlog),
        }
    }

    /// SwarmManager event loop
    pub async fn run(&mut self) -> error::Result<()> {
        loop {
            tokio::select! {
                event = self.rx_swarm.recv().fuse() => {
                    self.on_swarm_control_event(event).await?;
                }
                event = self.mgr_chan.1.recv().fuse() => {
                    self.on_peer_event(event).await?;
                }
                event = self.handle.poll_next() => match event {
                    Ok(event) => self.on_network_event(event).await?,
                    Err(e) => {
                        log::error!("failed to read network event: {:?}", e);
                        return Err(e);
                    }
                }
            }
        }
    }

    /// Handle an event coming from peer
    ///
    /// This may be an incoming message from remote peer or it may be event
    /// notifying us that the remote peer has disconnected and P2P can destroy
    /// whatever peer context it is holding
    ///
    /// The event is wrapped in an `Option` because the peer might have ungracefully
    /// failed and reading from the closed channel might gives a `None` value, indicating
    /// a protocol error which should be handled accordingly.
    async fn on_peer_event(
        &mut self,
        event: Option<event::PeerSwarmEvent<T>>,
    ) -> error::Result<()> {
        let event = event.ok_or(P2pError::ChannelClosed)?;
        match event {
            PeerSwarmEvent::HandshakeFailed { peer_id } => {
                log::error!("handshake failed, peer id {:?}", peer_id);
                self.peers
                    .remove(&peer_id)
                    .map(|_| ())
                    .ok_or_else(|| P2pError::Unknown("Peer does not exist".to_string()))
            }
            PeerSwarmEvent::HandshakeSucceeded { peer_id } => {
                log::info!("new peer joined, peer id {:?}", peer_id);

                let tx = self
                    .peers
                    .get_mut(&peer_id)
                    .ok_or_else(|| P2pError::Unknown("Peer does not exist".to_string()))
                    .map(|peer| {
                        (*peer).state = PeerState::Active;
                        peer.tx.clone()
                    })?;

                if !std::matches!(
                    tokio::join!(
                        self.handle.register_peer(peer_id),
                        self.tx_sync.send(event::SyncControlEvent::Connected { peer_id, tx })
                    ),
                    (Ok(_), Ok(_))
                ) {
                    return Err(P2pError::ChannelClosed);
                }

                Ok(())
            }
            PeerSwarmEvent::Disconnected { peer_id } => {
                log::debug!("peer {:?} disconnected", peer_id);

                if !std::matches!(
                    tokio::join!(
                        self.handle.unregister_peer(peer_id),
                        self.tx_sync.send(event::SyncControlEvent::Disconnected { peer_id })
                    ),
                    (Ok(_), Ok(_))
                ) {
                    return Err(P2pError::ChannelClosed);
                }

                Ok(())
            }
            PeerSwarmEvent::Message {
                peer_id: _,
                message: _,
            } => {
                todo!();
            }
        }
    }

    /// Handle swarm control event
    async fn on_swarm_control_event(
        &mut self,
        event: Option<event::SwarmControlEvent<T>>,
    ) -> error::Result<()> {
        match event.ok_or(P2pError::ChannelClosed)? {
            event::SwarmControlEvent::Connect { addr } => {
                log::debug!(
                    "try to establish outbound connection to peer at address {:?}",
                    addr
                );

                match self.handle.connect(addr).await {
                    Ok((peer_id, socket)) => {
                        self.create_peer(peer_id, socket, PeerRole::Outbound);
                        Ok(())
                    }
                    Err(e) => {
                        log::error!("failed to establish outbound connection: {:?}", e);
                        Err(e)
                    }
                }
            }
        }
    }

    /// Try to establish new outbound connections if the total number of
    /// active connections the local node has is below threshold
    ///
    // TODO: ugly, refactor
    async fn auto_connect(&mut self) -> error::Result<()> {
        // we have enough active connections
        if self.peers.len() >= MAX_ACTIVE_CONNECTIONS {
            return Ok(());
        }
        log::debug!("try to establish more outbound connections");

        // we don't know of any peers
        if self.discovered.is_empty() {
            log::error!(
                "# of connections below threshold ({} < {}) but no peers",
                self.peers.len(),
                MAX_ACTIVE_CONNECTIONS,
            );
            return Err(P2pError::NoPeers);
        }

        let npeers = std::cmp::min(
            self.discovered.len(),
            MAX_ACTIVE_CONNECTIONS - self.peers.len(),
        );

        // TODO: improve peer selection
        let mut iter = self.discovered.iter();

        #[allow(clippy::needless_collect)]
        let peers: Vec<(T::PeerId, Arc<T::Address>)> = (0..npeers)
            .map(|i| {
                let peer_info = iter.nth(i).expect("Peer to exist");

                let (ip4, ip6) = match peer_info.1 {
                    PeerAddrInfo::Raw { ip4, ip6 } => (ip4, ip6),
                };
                assert!(!ip4.is_empty() || !ip6.is_empty());

                // TODO: let user specify their preference?
                let addr = if ip6.is_empty() {
                    Arc::clone(ip4.iter().next().unwrap())
                } else {
                    Arc::clone(ip6.iter().next().unwrap())
                };

                (*peer_info.0, addr)
            })
            .collect::<_>();

        for (id, addr) in peers.into_iter() {
            log::trace!("try to connect to peer {:?}, address {:?}", id, addr);

            self.discovered.remove(&id);
            if let Ok((peer_id, socket)) = self.handle.connect((*addr).clone()).await {
                self.create_peer(peer_id, socket, PeerRole::Outbound)
            }
        }

        Ok(())
    }

    /// Update the list of peers we know about or update a known peers list of addresses
    fn peer_discovered(&mut self, peers: &[net::AddrInfo<T>]) -> error::Result<()> {
        log::info!("discovered {} new peers", peers.len());

        for info in peers.iter() {
            if self.peers.contains_key(&info.id) {
                continue;
            }

            match self.discovered.entry(info.id).or_insert_with(|| PeerAddrInfo::Raw {
                ip4: HashSet::new(),
                ip6: HashSet::new(),
            }) {
                PeerAddrInfo::Raw { ip4, ip6 } => {
                    log::trace!("discovered ipv4 {:#?}, ipv6 {:#?}", ip4, ip6);

                    ip4.extend(info.ip4.clone());
                    ip6.extend(info.ip6.clone());
                }
            }
        }

        Ok(())
    }

    fn peer_expired(&mut self, peers: &[net::AddrInfo<T>]) -> error::Result<()> {
        Ok(())
    }

    /// Handle network event received from the network service provider
    async fn on_network_event(&mut self, event: net::ConnectivityEvent<T>) -> error::Result<()> {
        match event {
            net::ConnectivityEvent::IncomingConnection { peer_id, socket } => {
                log::debug!("accept incoming connection, peer id {:?}", peer_id);
                self.create_peer(peer_id, socket, PeerRole::Inbound);
                Ok(())
            }
            net::ConnectivityEvent::PeerDiscovered { peers } => self.peer_discovered(&peers),
            net::ConnectivityEvent::PeerExpired { peers } => self.peer_expired(&peers),
        }
    }

    /// Create `Peer` object from a socket object and spawn task for it
    fn create_peer(&mut self, id: T::PeerId, socket: T::Socket, role: PeerRole) {
        let config = self.config.clone();
        let mgr_tx = self.mgr_chan.0.clone();
        let sync_tx = self.tx_peer_sync.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(self.peer_backlock);

        self.peers.insert(
            id,
            PeerContext {
                id,
                state: PeerState::Handshaking,
                tx,
            },
        );
        log::debug!("spawning a task for peer {:?}, role {:?}", id, role);

        tokio::spawn(async move {
            Peer::<T>::new(id, role, config, socket, mgr_tx, sync_tx, rx).run().await;
        });
    }
}

#[cfg(test)]
mod tests {
    #![allow(unused)]
    use super::*;
    use crate::error::P2pError;
    use crate::event;
    use crate::peer;
    use common::chain::config;
    use libp2p::Multiaddr;
    use net::{libp2p::Libp2pService, mock::MockService, ConnectivityService};
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    async fn make_swarm_manager<T>(addr: T::Address) -> SwarmManager<T>
    where
        T: NetworkService + 'static,
        T::ConnectivityHandle: ConnectivityService<T>,
    {
        let config = Arc::new(config::create_mainnet());
        let (conn, _) = T::start(addr, &[], &[]).await.unwrap();
        let (_, rx) = tokio::sync::mpsc::channel(16);
        let (tx_sync, mut rx_sync) = tokio::sync::mpsc::channel(16);
        let (tx_peer, _) = tokio::sync::mpsc::channel(16);

        tokio::spawn(async move {
            loop {
                let _ = rx_sync.recv().await;
            }
        });

        SwarmManager::<T>::new(Arc::clone(&config), conn, rx, tx_sync, tx_peer, 256, 32)
    }

    // try to connect to an address that no one listening on and verify it fails
    #[tokio::test]
    async fn test_swarm_connect_mock() {
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        let mut swarm = make_swarm_manager::<MockService>(addr).await;

        let addr: SocketAddr = "[::1]:6666".parse().unwrap();
        assert_eq!(
            swarm
                .on_swarm_control_event(Some(event::SwarmControlEvent::Connect { addr }))
                .await,
            Err(P2pError::SocketError(std::io::ErrorKind::ConnectionRefused))
        );
    }

    // try to connect to an address that no one listening on and verify it fails
    #[tokio::test]
    async fn test_swarm_connect_libp2p() {
        let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let mut swarm = make_swarm_manager::<Libp2pService>(addr).await;

        let addr: Multiaddr =
            "/ip6/::1/tcp/6666/p2p/12D3KooWRn14SemPVxwzdQNg8e8Trythiww1FWrNfPbukYBmZEbJ"
                .parse()
                .unwrap();
        assert_eq!(
            swarm
                .on_swarm_control_event(Some(event::SwarmControlEvent::Connect { addr }))
                .await,
            Err(P2pError::SocketError(std::io::ErrorKind::ConnectionRefused))
        );
    }

    // verify that if handshake succeeds, peer state is set to `Active`
    #[tokio::test]
    async fn test_on_peer_event_handshake_success() {
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        let mut swarm = make_swarm_manager::<MockService>(addr).await;
        let (tx, _) = tokio::sync::mpsc::channel(16);

        swarm.peers.insert(
            addr,
            PeerContext {
                id: addr,
                state: PeerState::Handshaking,
                tx: tx.clone(),
            },
        );

        assert_eq!(swarm.peers.len(), 1);
        assert_eq!(
            swarm
                .on_peer_event(Some(event::PeerSwarmEvent::HandshakeSucceeded {
                    peer_id: addr
                }))
                .await,
            Ok(())
        );
        assert_eq!(swarm.peers.len(), 1);
        match swarm.peers.get(&addr) {
            Some(peer) => assert_eq!(peer.state, PeerState::Active),
            None => {
                panic!("peer not found");
            }
        }
    }

    // verify that if handshake fails, peer context is destroyed
    #[tokio::test]
    async fn test_on_peer_event_handshake_failure() {
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        let mut swarm = make_swarm_manager::<MockService>(addr).await;
        let (tx, _) = tokio::sync::mpsc::channel(16);

        swarm.peers.insert(
            addr,
            PeerContext {
                id: addr,
                state: PeerState::Handshaking,
                tx: tx.clone(),
            },
        );

        assert_eq!(swarm.peers.len(), 1);
        assert_eq!(
            swarm
                .on_peer_event(Some(event::PeerSwarmEvent::HandshakeFailed {
                    peer_id: addr
                }))
                .await,
            Ok(())
        );
        assert_eq!(swarm.peers.len(), 0);
    }

    // verify that handshake event for unknown peer results in error
    #[tokio::test]
    async fn test_on_peer_event_unknown_peer() {
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        let mut swarm = make_swarm_manager::<MockService>(addr).await;

        assert_eq!(
            swarm
                .on_peer_event(Some(event::PeerSwarmEvent::HandshakeSucceeded {
                    peer_id: addr
                }))
                .await,
            Err(P2pError::Unknown("Peer does not exist".to_string())),
        );

        assert_eq!(
            swarm
                .on_peer_event(Some(event::PeerSwarmEvent::HandshakeFailed {
                    peer_id: addr
                }))
                .await,
            Err(P2pError::Unknown("Peer does not exist".to_string())),
        );
    }

    #[tokio::test]
    async fn test_peer_discovered_libp2p() {
        let config = Arc::new(config::create_mainnet());
        let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let mut swarm = make_swarm_manager::<Libp2pService>(addr).await;

        let id_1: libp2p::PeerId =
            "12D3KooWRn14SemPVxwzdQNg8e8Trythiww1FWrNfPbukYBmZEbJ".parse().unwrap();
        let id_2: libp2p::PeerId =
            "12D3KooWE3kBRAnn6jxZMdK1JMWx1iHtR1NKzXSRv5HLTmfD9u9c".parse().unwrap();
        let id_3: libp2p::PeerId =
            "12D3KooWGK4RzvNeioS9aXdzmYXU3mgDrRPjQd8SVyXCkHNxLbWN".parse().unwrap();

        // check that peer with `id` has the correct ipv4 and ipv6 addresses
        let check_peer =
            |discovered: &HashMap<
                <Libp2pService as NetworkService>::PeerId,
                PeerAddrInfo<Libp2pService>,
            >,
             id: libp2p::PeerId,
             ip4: Vec<Arc<<Libp2pService as NetworkService>::Address>>,
             ip6: Vec<Arc<<Libp2pService as NetworkService>::Address>>| {
                let (p_ip4, p_ip6) = match discovered.get(&id).unwrap() {
                    PeerAddrInfo::Raw { ip4, ip6 } => (ip4, ip6),
                };

                assert_eq!(ip4.len(), p_ip4.len());
                assert_eq!(ip6.len(), p_ip6.len());

                for ip in ip4.iter() {
                    assert!(p_ip4.contains(ip));
                }

                for ip in ip6.iter() {
                    assert!(p_ip6.contains(ip));
                }
            };

        // first add two new peers, both with ipv4 and ipv6 address
        swarm
            .peer_discovered(&[
                net::AddrInfo {
                    id: id_1,
                    ip4: vec![Arc::new("/ip4/127.0.0.1/tcp/9090".parse().unwrap())],
                    ip6: vec![Arc::new("/ip6/::1/tcp/9091".parse().unwrap())],
                },
                net::AddrInfo {
                    id: id_2,
                    ip4: vec![Arc::new("/ip4/127.0.0.1/tcp/9092".parse().unwrap())],
                    ip6: vec![Arc::new("/ip6/::1/tcp/9093".parse().unwrap())],
                },
            ])
            .unwrap();

        assert_eq!(swarm.peers.len(), 0);
        assert_eq!(swarm.discovered.len(), 2);

        check_peer(
            &swarm.discovered,
            id_1,
            vec![Arc::new("/ip4/127.0.0.1/tcp/9090".parse().unwrap())],
            vec![Arc::new("/ip6/::1/tcp/9091".parse().unwrap())],
        );

        check_peer(
            &swarm.discovered,
            id_2,
            vec![Arc::new("/ip4/127.0.0.1/tcp/9092".parse().unwrap())],
            vec![Arc::new("/ip6/::1/tcp/9093".parse().unwrap())],
        );

        // then discover one new peer and two additional ipv6 addresses for peer 1
        swarm
            .peer_discovered(&[
                net::AddrInfo {
                    id: id_1,
                    ip4: vec![],
                    ip6: vec![
                        Arc::new("/ip6/::1/tcp/9094".parse().unwrap()),
                        Arc::new("/ip6/::1/tcp/9095".parse().unwrap()),
                    ],
                },
                net::AddrInfo {
                    id: id_3,
                    ip4: vec![Arc::new("/ip4/127.0.0.1/tcp/9096".parse().unwrap())],
                    ip6: vec![Arc::new("/ip6/::1/tcp/9097".parse().unwrap())],
                },
            ])
            .unwrap();

        check_peer(
            &swarm.discovered,
            id_1,
            vec![Arc::new("/ip4/127.0.0.1/tcp/9090".parse().unwrap())],
            vec![
                Arc::new("/ip6/::1/tcp/9091".parse().unwrap()),
                Arc::new("/ip6/::1/tcp/9094".parse().unwrap()),
                Arc::new("/ip6/::1/tcp/9095".parse().unwrap()),
            ],
        );

        check_peer(
            &swarm.discovered,
            id_3,
            vec![Arc::new("/ip4/127.0.0.1/tcp/9096".parse().unwrap())],
            vec![Arc::new("/ip6/::1/tcp/9097".parse().unwrap())],
        );

        // move peer with `id_2` to active list, try to add new address to it
        // and verify that nothing is added
        let (tx, _) = tokio::sync::mpsc::channel(1);
        let _ = 32;
        swarm.peers.insert(
            id_3,
            PeerContext {
                id: id_3,
                state: PeerState::Handshaking,
                tx,
            },
        );

        swarm
            .peer_discovered(&[net::AddrInfo {
                id: id_3,
                ip4: vec![Arc::new("/ip4/127.0.0.1/tcp/9098".parse().unwrap())],
                ip6: vec![Arc::new("/ip6/::1/tcp/9099".parse().unwrap())],
            }])
            .unwrap();

        check_peer(
            &swarm.discovered,
            id_3,
            vec![Arc::new("/ip4/127.0.0.1/tcp/9096".parse().unwrap())],
            vec![Arc::new("/ip6/::1/tcp/9097".parse().unwrap())],
        );
    }

    // verify that if the node is aware of any peers on the network,
    // call to `auto_connect()` will establish a connection with them
    #[tokio::test]
    async fn test_auto_connect_mock() {
        let config = Arc::new(config::create_mainnet());
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        let mut swarm = make_swarm_manager::<MockService>(addr).await;

        // spawn tcp server for auto-connect test
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        let server = TcpListener::bind(addr).await.unwrap();
        tokio::spawn(async move {
            println!("staring tcp server...");
            loop {
                assert!(server.accept().await.is_ok());
            }
        });

        // "discover" the tcp server
        swarm
            .peer_discovered(&[net::AddrInfo {
                id: addr,
                ip4: vec![],
                ip6: vec![Arc::new(addr)],
            }])
            .unwrap();
        swarm.auto_connect().await.unwrap();

        assert_eq!(swarm.peers.len(), 1);
    }
}
