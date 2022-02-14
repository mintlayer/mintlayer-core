// Copyright (c) 2021-2022 RBB S.r.l
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

use crate::{
    error::P2pError,
    event::{Event, PeerEvent, PeerEventType},
    net::NetworkService,
    peer::{Peer, PeerRole},
};
use common::chain::ChainConfig;
use futures::FutureExt;
use logging::log;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::mpsc::{Receiver, Sender};

pub mod error;
pub mod event;
pub mod message;
pub mod net;
pub mod peer;
pub mod proto;

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
struct PeerContext<NetworkingBackend>
where
    NetworkingBackend: NetworkService,
{
    /// Unique peer ID
    id: NetworkingBackend::PeerId,

    /// Peer state
    state: PeerState,

    /// Channel for communication with the peer
    tx: Sender<Event>,
}

#[allow(unused)]
pub enum ConnectivityEvent<T>
where
    T: NetworkService,
{
    Accept(T::PeerId, T::Socket),
    Connect(T::Address),
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

#[allow(unused)]
pub struct P2P<NetworkingBackend>
where
    NetworkingBackend: NetworkService,
{
    /// Network backend (libp2p, mock)
    network: NetworkingBackend,

    /// Chain config
    config: Arc<ChainConfig>,

    /// Hashmap for peer information
    peers: HashMap<NetworkingBackend::PeerId, PeerContext<NetworkingBackend>>,

    /// Hashmap of discovered peers we don't have an active connection with
    discovered: HashMap<NetworkingBackend::PeerId, PeerAddrInfo<NetworkingBackend>>,

    /// Peer backlog maximum size
    peer_backlock: usize,

    /// Channel for p2p<->peers communication
    mgr_chan: (
        Sender<PeerEvent<NetworkingBackend>>,
        Receiver<PeerEvent<NetworkingBackend>>,
    ),
}

#[allow(unused)]
impl<NetworkingBackend> P2P<NetworkingBackend>
where
    NetworkingBackend: 'static + NetworkService,
{
    /// Create new P2P
    ///
    /// # Arguments
    /// `addr` - socket address where the local node binds itself to
    pub async fn new(
        mgr_backlog: usize,
        peer_backlock: usize,
        addr: NetworkingBackend::Address,
        config: Arc<ChainConfig>,
    ) -> error::Result<Self> {
        Ok(Self {
            network: NetworkingBackend::new(addr, &[], &[]).await?,
            config,
            peer_backlock,
            peers: HashMap::with_capacity(MAX_ACTIVE_CONNECTIONS),
            discovered: HashMap::new(),
            mgr_chan: tokio::sync::mpsc::channel(mgr_backlog),
        })
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
        event: Option<PeerEvent<NetworkingBackend>>,
    ) -> error::Result<()> {
        let event = event.ok_or(P2pError::ChannelClosed)?;
        match event.event {
            PeerEventType::HandshakeFailed => {
                log::error!("handshake failed, peer id {:?}", event.peer_id);
                self.peers
                    .remove(&event.peer_id)
                    .map(|_| ())
                    .ok_or_else(|| P2pError::Unknown("Peer does not exist".to_string()))
            }
            PeerEventType::HandshakeSucceeded => match self.peers.get_mut(&event.peer_id) {
                Some(peer) => {
                    log::info!("new peer joined, peer id {:?}", event.peer_id);
                    (*peer).state = PeerState::Active;
                    Ok(())
                }
                None => Err(P2pError::Unknown("Peer does not exist".to_string())),
            },
            PeerEventType::Disconnected | PeerEventType::Message(_) => {
                todo!();
            }
        }
    }

    /// Handle a connectivity-related event
    ///
    /// This may be a socket event (new peer, `accept()` failed) or it may be
    /// a connection request from some other part of the system indicating that
    /// P2P should try to establish a connection with a specific remote peer.
    async fn on_connectivity_event(
        &mut self,
        event: ConnectivityEvent<NetworkingBackend>,
    ) -> error::Result<()> {
        match event {
            ConnectivityEvent::Accept(peer_id, socket) => {
                log::debug!("accept incoming connection, peer id {:?}", peer_id);
                self.create_peer(peer_id, socket, PeerRole::Inbound)
            }
            ConnectivityEvent::Connect(address) => {
                log::debug!(
                    "try to establish outbound connection, address {:?}",
                    address
                );

                self.network.connect(address).await.map(|(peer_id, socket)| {
                    self.create_peer(peer_id, socket, PeerRole::Outbound)
                })?
            }
        }

        Ok(())
    }

    /// Try to establish new outbound connections if the total number of
    /// active connections the local node has is below threshold
    ///
    // TODO: move all peer management to separate file
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
        let peers: Vec<(NetworkingBackend::PeerId, Arc<NetworkingBackend::Address>)> = (0..npeers)
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
            let _ = self.on_connectivity_event(ConnectivityEvent::Connect((*addr).clone())).await;
        }

        Ok(())
    }

    /// Update the list of peers we know about or update a known peers list of addresses
    fn peer_discovered(&mut self, peers: &[net::AddrInfo<NetworkingBackend>]) -> error::Result<()> {
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

    fn peer_expired(&mut self, peers: &[net::AddrInfo<NetworkingBackend>]) -> error::Result<()> {
        Ok(())
    }

    /// Handle floodsub event
    fn on_floodsub_event(
        &mut self,
        topic: net::FloodsubTopic,
        message: message::Message,
    ) -> error::Result<()> {
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

    /// Handle network event received from the network service provider
    async fn on_network_event(
        &mut self,
        event: net::Event<NetworkingBackend>,
    ) -> error::Result<()> {
        match event {
            net::Event::IncomingConnection(peer_id, socket) => {
                self.on_connectivity_event(ConnectivityEvent::Accept(peer_id, socket)).await
            }
            net::Event::PeerDiscovered(peers) => self.peer_discovered(&peers),
            net::Event::PeerExpired(peers) => self.peer_expired(&peers),
            net::Event::MessageReceived(topic, message) => self.on_floodsub_event(topic, message),
        }
    }

    /// Run the `P2P` event loop.
    pub async fn run(&mut self) -> error::Result<()> {
        log::info!("starting event loop");

        loop {
            tokio::select! {
                res = self.network.poll_next() => {
                    res.map(|event| async {
                        self.on_network_event(event).await
                    })?;
                }
                event = self.mgr_chan.1.recv().fuse() => {
                    self.on_peer_event(event).await?;
                }
            };
        }
    }

    /// Create `Peer` object from a socket object and spawn task for it
    fn create_peer(
        &mut self,
        id: NetworkingBackend::PeerId,
        socket: NetworkingBackend::Socket,
        role: PeerRole,
    ) {
        let config = self.config.clone();
        let mgr_tx = self.mgr_chan.0.clone();
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
            Peer::<NetworkingBackend>::new(id, role, config, socket, mgr_tx, rx).run().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::P2pError;
    use common::chain::config;
    use libp2p::Multiaddr;
    use net::{libp2p::Libp2pService, mock::MockService};
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    // try to connect to an address that no one listening on and verify it fails
    #[tokio::test]
    async fn test_p2p_connect_mock() {
        let config = Arc::new(config::create_mainnet());
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        let mut p2p = P2P::<MockService>::new(256, 32, addr, Arc::clone(&config)).await.unwrap();

        let remote: SocketAddr = "[::1]:6666".parse().unwrap();
        let res = p2p.on_connectivity_event(ConnectivityEvent::Connect(remote)).await;
        assert_eq!(
            res,
            Err(P2pError::SocketError(std::io::ErrorKind::ConnectionRefused))
        );
    }

    // try to connect to an address that no one listening on and verify it fails
    #[tokio::test]
    async fn test_p2p_connect_libp2p() {
        let config = Arc::new(config::create_mainnet());
        let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let mut p2p = P2P::<Libp2pService>::new(256, 32, addr, Arc::clone(&config)).await.unwrap();

        let remote: Multiaddr =
            "/ip6/::1/tcp/6666/p2p/12D3KooWRn14SemPVxwzdQNg8e8Trythiww1FWrNfPbukYBmZEbJ"
                .parse()
                .unwrap();
        let res = p2p.on_connectivity_event(ConnectivityEvent::Connect(remote)).await;
        assert_eq!(
            res,
            Err(P2pError::SocketError(std::io::ErrorKind::ConnectionRefused))
        );
    }

    // verify that if handshake succeeds, peer state is set to `Active`
    #[tokio::test]
    async fn test_on_peer_event_handshake_success() {
        let config = Arc::new(config::create_mainnet());
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        let mut p2p = P2P::<MockService>::new(256, 32, addr, Arc::clone(&config)).await.unwrap();
        let (tx, _) = tokio::sync::mpsc::channel(16);

        p2p.peers.insert(
            addr,
            PeerContext {
                id: addr,
                state: PeerState::Handshaking,
                tx: tx.clone(),
            },
        );

        assert_eq!(p2p.peers.len(), 1);
        assert_eq!(
            p2p.on_peer_event(Some(PeerEvent {
                peer_id: addr,
                event: PeerEventType::HandshakeSucceeded,
            }))
            .await,
            Ok(())
        );
        assert_eq!(p2p.peers.len(), 1);
        match p2p.peers.get(&addr) {
            Some(peer) => assert_eq!(peer.state, PeerState::Active),
            None => {
                panic!("peer not found");
            }
        }
    }

    // verify that if handshake fails, peer context is destroyed
    #[tokio::test]
    async fn test_on_peer_event_handshake_failure() {
        let config = Arc::new(config::create_mainnet());
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        let mut p2p = P2P::<MockService>::new(256, 32, addr, Arc::clone(&config)).await.unwrap();
        let (tx, _) = tokio::sync::mpsc::channel(16);

        p2p.peers.insert(
            addr,
            PeerContext {
                id: addr,
                state: PeerState::Handshaking,
                tx: tx.clone(),
            },
        );

        assert_eq!(p2p.peers.len(), 1);
        assert_eq!(
            p2p.on_peer_event(Some(PeerEvent {
                peer_id: addr,
                event: PeerEventType::HandshakeFailed,
            }))
            .await,
            Ok(())
        );
        assert_eq!(p2p.peers.len(), 0);
    }

    #[tokio::test]
    async fn test_peer_discovered_libp2p() {
        let config = Arc::new(config::create_mainnet());
        let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let mut p2p = P2P::<Libp2pService>::new(256, 32, addr, Arc::clone(&config)).await.unwrap();

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
        p2p.peer_discovered(&[
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

        assert_eq!(p2p.peers.len(), 0);
        assert_eq!(p2p.discovered.len(), 2);

        check_peer(
            &p2p.discovered,
            id_1,
            vec![Arc::new("/ip4/127.0.0.1/tcp/9090".parse().unwrap())],
            vec![Arc::new("/ip6/::1/tcp/9091".parse().unwrap())],
        );

        check_peer(
            &p2p.discovered,
            id_2,
            vec![Arc::new("/ip4/127.0.0.1/tcp/9092".parse().unwrap())],
            vec![Arc::new("/ip6/::1/tcp/9093".parse().unwrap())],
        );

        // then discover one new peer and two additional ipv6 addresses for peer 1
        p2p.peer_discovered(&[
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
            &p2p.discovered,
            id_1,
            vec![Arc::new("/ip4/127.0.0.1/tcp/9090".parse().unwrap())],
            vec![
                Arc::new("/ip6/::1/tcp/9091".parse().unwrap()),
                Arc::new("/ip6/::1/tcp/9094".parse().unwrap()),
                Arc::new("/ip6/::1/tcp/9095".parse().unwrap()),
            ],
        );

        check_peer(
            &p2p.discovered,
            id_3,
            vec![Arc::new("/ip4/127.0.0.1/tcp/9096".parse().unwrap())],
            vec![Arc::new("/ip6/::1/tcp/9097".parse().unwrap())],
        );

        // move peer with `id_2` to active list, try to add new address to it
        // and verify that nothing is added
        let (tx, _) = tokio::sync::mpsc::channel(1);
        let _ = 32;
        p2p.peers.insert(
            id_3,
            PeerContext {
                id: id_3,
                state: PeerState::Handshaking,
                tx,
            },
        );

        p2p.peer_discovered(&[net::AddrInfo {
            id: id_3,
            ip4: vec![Arc::new("/ip4/127.0.0.1/tcp/9098".parse().unwrap())],
            ip6: vec![Arc::new("/ip6/::1/tcp/9099".parse().unwrap())],
        }])
        .unwrap();

        check_peer(
            &p2p.discovered,
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
        let mut p2p = P2P::<MockService>::new(256, 32, addr, Arc::clone(&config)).await.unwrap();

        // spawn tcp server for auto-connect test
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        let server = TcpListener::bind(addr).await.unwrap();
        tokio::spawn(async move {
            loop {
                assert!(server.accept().await.is_ok());
            }
        });

        // "discover" the tcp server
        p2p.peer_discovered(&[net::AddrInfo {
            id: addr,
            ip4: vec![],
            ip6: vec![Arc::new(addr)],
        }])
        .unwrap();
        p2p.auto_connect().await.unwrap();

        assert_eq!(p2p.peers.len(), 1);
    }
}
