// Copyright (c) 2018 Parity Technologies (UK) Ltd.
// Copyright (c) 2021 Protocol Labs
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
#![allow(unused)]

use crate::{
    error::{self, Libp2pError, P2pError, ProtocolError},
    message,
    net::{
        self, ConnectivityEvent, ConnectivityService, NetworkService, PubSubEvent, PubSubService,
        PubSubTopic, SyncingMessage, SyncingService,
    },
};
use async_trait::async_trait;
use futures::prelude::*;
use itertools::*;
use libp2p::{
    core::{
        upgrade::{self, read_length_prefixed, write_length_prefixed},
        PeerId,
    },
    gossipsub::{
        Gossipsub, GossipsubConfigBuilder, GossipsubEvent, GossipsubMessage, IdentTopic as Topic,
        MessageAuthenticity, MessageId, ValidationMode,
    },
    identify::{Identify, IdentifyConfig, IdentifyInfo},
    identity,
    mdns::Mdns,
    mplex,
    multiaddr::Protocol,
    noise, ping,
    request_response::*,
    swarm::{NegotiatedSubstream, SwarmBuilder},
    tcp::TcpConfig,
    Multiaddr, Transport,
};
use logging::log;
use parity_scale_codec::{Decode, Encode};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::{io, iter};
use tokio::sync::{mpsc, oneshot};

mod backend;
mod types;

// Maximum message size of 10 MB
const MESSAGE_MAX_SIZE: u32 = 10 * 1024 * 1024;

/// libp2p-specifc peer discovery strategies
#[derive(Debug, PartialEq, Eq)]
pub enum Libp2pStrategy {
    /// Use mDNS to find peers in the local network
    MulticastDns,
}

#[derive(Debug)]
pub struct Libp2pService;

pub struct Libp2pConnectivityHandle<T>
where
    T: NetworkService,
{
    /// Address where the network services has been bound
    addr: Multiaddr,

    /// Channel for sending commands to libp2p backend
    cmd_tx: mpsc::Sender<types::Command>,

    /// Channel for receiving connectivity events from libp2p backend
    conn_rx: mpsc::Receiver<types::ConnectivityEvent>,
    _marker: std::marker::PhantomData<T>,
}

pub struct Libp2pPubSubHandle<T>
where
    T: NetworkService,
{
    /// Channel for sending commands to libp2p backend
    cmd_tx: mpsc::Sender<types::Command>,

    /// Channel for receiving pubsub events from libp2p backend
    flood_rx: mpsc::Receiver<types::PubSubEvent>,
    _marker: std::marker::PhantomData<T>,
}

pub struct Libp2pSyncHandle<T>
where
    T: NetworkService,
{
    /// Channel for sending commands to libp2p backend
    cmd_tx: mpsc::Sender<types::Command>,

    /// Channel for receiving pubsub events from libp2p backend
    sync_rx: mpsc::Receiver<types::SyncingEvent>,
    _marker: std::marker::PhantomData<T>,
}

/// Verify that the discovered multiaddress is in a format that Mintlayer supports:
///   /ip4/<IPv4 address>/tcp/<TCP port>/p2p/<PeerId multihash>
///   /ip6/<IPv6 address>/tcp/<TCP port>/p2p/<PeerId multihash>
///
/// Documentation for libp2p-mdns doesn't mention if `peer_addr` includes the PeerId
/// so if it doesn't, add it. Otherwise just return the address
fn parse_discovered_addr(peer_id: PeerId, peer_addr: Multiaddr) -> Option<Multiaddr> {
    let mut components = peer_addr.iter();

    if !std::matches!(
        components.next(),
        Some(Protocol::Ip4(_)) | Some(Protocol::Ip6(_))
    ) {
        return None;
    }

    if !std::matches!(components.next(), Some(Protocol::Tcp(_))) {
        return None;
    }

    match components.next() {
        Some(Protocol::P2p(_)) => Some(peer_addr.clone()),
        None => Some(peer_addr.with(Protocol::P2p(peer_id.into()))),
        Some(_) => None,
    }
}

/// Get the network layer protocol from `addr`
fn get_addr_from_multiaddr(addr: &Multiaddr) -> Option<Protocol> {
    addr.iter().next()
}

impl<T> FromIterator<(PeerId, Multiaddr)> for net::AddrInfo<T>
where
    T: NetworkService<PeerId = PeerId, Address = Multiaddr>,
{
    fn from_iter<I: IntoIterator<Item = (PeerId, Multiaddr)>>(iter: I) -> Self {
        let mut entry = net::AddrInfo {
            id: PeerId::random(),
            ip4: Vec::new(),
            ip6: Vec::new(),
        };

        iter.into_iter().for_each(|(id, addr)| {
            entry.id = id;
            match get_addr_from_multiaddr(&addr) {
                Some(Protocol::Ip4(_)) => entry.ip4.push(Arc::new(addr)),
                Some(Protocol::Ip6(_)) => entry.ip6.push(Arc::new(addr)),
                _ => panic!("parse_discovered_addr() failed!"),
            }
        });

        log::trace!(
            "id {:?}, ipv4 {:#?}, ipv6 {:#?}",
            entry.id,
            entry.ip4,
            entry.ip6
        );

        entry
    }
}

/// Parse all discovered addresses and group them by PeerId
fn parse_peers<T>(mut peers: Vec<(PeerId, Multiaddr)>) -> Vec<net::AddrInfo<T>>
where
    T: NetworkService<PeerId = PeerId, Address = Multiaddr>,
{
    peers.sort_by(|a, b| a.0.cmp(&b.0));
    peers
        .into_iter()
        .map(|(id, addr)| (id, parse_discovered_addr(id, addr)))
        .filter(|(_id, addr)| addr.is_some())
        .map(|(id, addr)| (id, addr.unwrap()))
        .group_by(|info| info.0)
        .into_iter()
        .map(|(_id, addrs)| net::AddrInfo::from_iter(addrs))
        .collect::<Vec<net::AddrInfo<T>>>()
}

impl<T> TryInto<net::PeerInfo<T>> for IdentifyInfo
where
    T: NetworkService<PeerId = PeerId, ProtocolId = String>,
{
    type Error = P2pError;

    // TODO: use text-io
    fn try_into(self) -> Result<net::PeerInfo<T>, Self::Error> {
        // TODO: fix this to extract the correct information
        let (net, version) = match self.protocol_version.as_str() {
            "/mintlayer/0.1.0-deadbeef" => (
                common::chain::config::ChainType::Mainnet,
                common::primitives::version::SemVer::new(0, 1, 0),
            ),
            _ => return Err(P2pError::ProtocolError(ProtocolError::DifferentNetwork)),
        };

        Ok(net::PeerInfo {
            peer_id: PeerId::from_public_key(&self.public_key),
            net,
            version,
            agent: Some(self.agent_version),
            protocols: self.protocols,
        })
    }
}

#[async_trait]
impl NetworkService for Libp2pService {
    type Address = Multiaddr;
    type Strategy = Libp2pStrategy;
    type PeerId = PeerId;
    type ProtocolId = String;
    type RequestId = RequestId;
    type MessageId = MessageId;
    type ConnectivityHandle = Libp2pConnectivityHandle<Self>;
    type PubSubHandle = Libp2pPubSubHandle<Self>;
    type SyncingHandle = Libp2pSyncHandle<Self>;

    async fn start(
        addr: Self::Address,
        strategies: &[Self::Strategy],
        topics: &[PubSubTopic],
        config: Arc<common::chain::ChainConfig>,
        timeout: std::time::Duration,
    ) -> error::Result<(
        Self::ConnectivityHandle,
        Self::PubSubHandle,
        Self::SyncingHandle,
    )> {
        let id_keys = identity::Keypair::generate_ed25519();
        let peer_id = id_keys.public().to_peer_id();
        let noise_keys = noise::Keypair::<noise::X25519Spec>::new().into_authentic(&id_keys)?;

        let transport = TcpConfig::new()
            .nodelay(true)
            .port_reuse(true)
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
            .multiplex(mplex::MplexConfig::new())
            .outbound_timeout(timeout)
            .boxed();

        let swarm = {
            // TODO: double check gossipsub configuration
            let message_id_fn = |message: &GossipsubMessage| {
                let mut s = DefaultHasher::new();
                message.data.hash(&mut s);
                MessageId::from(s.finish().to_string())
            };

            let gossipsub_config = GossipsubConfigBuilder::default()
                .heartbeat_interval(std::time::Duration::from_secs(10))
                .validation_mode(ValidationMode::Strict)
                .message_id_fn(message_id_fn)
                .validate_messages()
                .build()
                .expect("configuration to be valid");

            // TODO: configure sync protocol
            let protocols = iter::once((SyncingProtocol(), ProtocolSupport::Full));
            let cfg = RequestResponseConfig::default();
            let sync = RequestResponse::new(SyncingCodec(), protocols, cfg);

            let mut gossipsub: Gossipsub = Gossipsub::new(
                MessageAuthenticity::Signed(id_keys.clone()),
                gossipsub_config,
            )
            .expect("configuration to be valid");

            // TODO: implement `std::fmt::Display` for SemVer and magic bytes
            let version = config.version();
            let magic = config.magic_bytes();
            let mut identify = Identify::new(IdentifyConfig::new(
                "/mintlayer/0.1.0-deadbeef".into(),
                id_keys.public(),
            ));
            // TODO: fix this
            // let mut identify = Identify::new(IdentifyConfig::new(
            //     format!(
            //         "/mintlayer/{}.{}.{}-{}",
            //         version.major,
            //         version.minor,
            //         version.patch,
            //         ((magic[3] << 24) as u32)
            //             | ((magic[2] << 16) as u32)
            //             | ((magic[1] << 8) as u32)
            //             | ((magic[0] << 0) as u32)
            //     )
            //     .into(),
            //     id_keys.public(),
            // ));

            // TODO: configure ping
            let mut behaviour = types::ComposedBehaviour {
                mdns: Mdns::new(Default::default()).await?,
                ping: ping::Behaviour::new(ping::Config::new()),
                gossipsub,
                identify,
                sync,
            };

            for topic in topics.iter() {
                log::debug!("subscribing to gossipsub topic {:?}", topic);
                behaviour.gossipsub.subscribe(&topic.into()).unwrap(); // TODO: remove unwrap
            }

            // subscribes to our topic
            SwarmBuilder::new(transport, behaviour, peer_id).build()
        };

        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (flood_tx, flood_rx) = mpsc::channel(64);
        let (conn_tx, conn_rx) = mpsc::channel(64);
        let (sync_tx, sync_rx) = mpsc::channel(64);

        // If mDNS has been specified as a peer discovery strategy for this Libp2pService,
        // pass that information to the backend so it knows to relay the mDNS events to P2P
        let relay_mdns = strategies.iter().any(|s| s == &Libp2pStrategy::MulticastDns);
        log::trace!("multicast dns enabled {}", relay_mdns);

        // run the libp2p backend in a background task
        log::debug!("spawning libp2p backend to background");

        tokio::spawn(async move {
            let mut backend =
                backend::Backend::new(swarm, cmd_rx, conn_tx, flood_tx, sync_tx, relay_mdns);
            backend.run().await
        });

        // send listen command to the libp2p backend and if it succeeds,
        // create a multiaddress for local peer and return the Libp2pService object
        let (tx, rx) = oneshot::channel();
        cmd_tx
            .send(types::Command::Listen {
                addr: addr.clone(),
                response: tx,
            })
            .await?;
        rx.await?.map_err(|_| P2pError::SocketError(std::io::ErrorKind::AddrInUse))?;

        Ok((
            Self::ConnectivityHandle {
                addr: addr.with(Protocol::P2p(peer_id.into())),
                cmd_tx: cmd_tx.clone(),
                conn_rx,
                _marker: Default::default(),
            },
            Self::PubSubHandle {
                cmd_tx: cmd_tx.clone(),
                flood_rx,
                _marker: Default::default(),
            },
            Self::SyncingHandle {
                cmd_tx,
                sync_rx,
                _marker: Default::default(),
            },
        ))
    }
}

#[async_trait]
impl<T> ConnectivityService<T> for Libp2pConnectivityHandle<T>
where
    T: NetworkService<Address = Multiaddr, PeerId = PeerId> + Send,
    IdentifyInfo: TryInto<net::PeerInfo<T>, Error = P2pError>,
{
    async fn connect(&mut self, addr: T::Address) -> error::Result<net::PeerInfo<T>> {
        log::trace!("try to establish outbound connection, address {:?}", addr);

        let peer_id = match addr.iter().last() {
            Some(Protocol::P2p(hash)) => PeerId::from_multihash(hash).map_err(|_| {
                P2pError::Libp2pError(Libp2pError::DialError(
                    "Expect peer multiaddr to contain peer ID.".into(),
                ))
            })?,
            _ => {
                return Err(P2pError::Libp2pError(Libp2pError::DialError(
                    "Expect peer multiaddr to contain peer ID.".into(),
                )))
            }
        };

        // try to connect to remote peer
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(types::Command::Connect {
                peer_id,
                peer_addr: addr.clone(),
                response: tx,
            })
            .await?;

        let info = rx
            .await
            .map_err(|e| e)? // channel closed
            .map_err(|e| e)?; // command failure

        // TODO: zzz
        let (net, version) = match info.protocol_version.as_str() {
            "/mintlayer/0.1.0-deadbeef" => (
                common::chain::config::ChainType::Mainnet,
                common::primitives::version::SemVer::new(0, 1, 0),
            ),
            _ => return Err(P2pError::ProtocolError(ProtocolError::DifferentNetwork)),
        };

        Ok(net::PeerInfo {
            peer_id,
            net,
            version,
            agent: None,
            protocols: vec![],
        })
    }

    fn local_addr(&self) -> &T::Address {
        &self.addr
    }

    async fn poll_next(&mut self) -> error::Result<ConnectivityEvent<T>> {
        match self.conn_rx.recv().await.ok_or(P2pError::ChannelClosed)? {
            types::ConnectivityEvent::ConnectionAccepted { peer_info } => {
                Ok(ConnectivityEvent::PeerConnected {
                    peer_info: (*peer_info).try_into()?,
                })
            }
            types::ConnectivityEvent::PeerDiscovered { peers } => {
                Ok(ConnectivityEvent::PeerDiscovered {
                    peers: parse_peers(peers),
                })
            }
            types::ConnectivityEvent::PeerExpired { peers } => Ok(ConnectivityEvent::PeerExpired {
                peers: parse_peers(peers),
            }),
        }
    }
}

#[async_trait]
impl<T> PubSubService<T> for Libp2pPubSubHandle<T>
where
    T: NetworkService<PeerId = PeerId, MessageId = MessageId> + Send,
{
    async fn publish<U>(&mut self, topic: PubSubTopic, data: &U) -> error::Result<()>
    where
        U: Sync + Send + Encode,
    {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(types::Command::SendMessage {
                topic,
                message: data.encode(),
                response: tx,
            })
            .await?;

        rx.await
            .map_err(|e| e)? // channel closed
            .map_err(|e| e) // command failure
    }

    async fn report_validation_result(
        &mut self,
        source: T::PeerId,
        message_id: T::MessageId,
        result: net::ValidationResult,
    ) -> error::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(types::Command::ReportValidationResult {
                message_id,
                source,
                result: result.into(),
                response: tx,
            })
            .await?;

        rx.await
            .map_err(|e| e)? // channel closed
            .map_err(|e| e) // command failure
    }

    async fn poll_next(&mut self) -> error::Result<PubSubEvent<T>> {
        match self.flood_rx.recv().await.ok_or(P2pError::ChannelClosed)? {
            types::PubSubEvent::MessageReceived {
                peer_id,
                topic,
                message,
                message_id,
            } => Ok(PubSubEvent::MessageReceived {
                peer_id,
                topic,
                message,
                message_id,
            }),
        }
    }
}

#[async_trait]
impl<T> SyncingService<T> for Libp2pSyncHandle<T>
where
    T: NetworkService<PeerId = PeerId, MessageId = MessageId, RequestId = RequestId> + Send,
{
    async fn send_request(
        &mut self,
        peer_id: T::PeerId,
        message: message::Message,
    ) -> error::Result<T::RequestId> {
        todo!();
    }

    async fn send_response(
        &mut self,
        request_id: T::RequestId,
        message: message::Message,
    ) -> error::Result<()> {
        todo!();
    }

    async fn poll_next(&mut self) -> error::Result<SyncingMessage<T>> {
        todo!();
    }
}

// TODO: move this to its own file
#[derive(Debug, Clone)]
pub struct SyncingProtocol();

#[derive(Clone)]
pub struct SyncingCodec();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockRequest(Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockResponse(Vec<u8>);

impl ProtocolName for SyncingProtocol {
    fn protocol_name(&self) -> &[u8] {
        "/mintlayer/sync/0.1.0".as_bytes()
    }
}

#[async_trait]
impl RequestResponseCodec for SyncingCodec {
    type Protocol = SyncingProtocol;
    type Request = BlockRequest;
    type Response = BlockResponse;

    async fn read_request<T>(
        &mut self,
        _: &SyncingProtocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let vec = read_length_prefixed(io, 1024).await?;

        if vec.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }

        Ok(BlockRequest(vec))
    }

    async fn read_response<T>(
        &mut self,
        _: &SyncingProtocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let vec = read_length_prefixed(io, 1024).await?;

        if vec.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }

        Ok(BlockResponse(vec))
    }

    async fn write_request<T>(
        &mut self,
        _: &SyncingProtocol,
        io: &mut T,
        BlockRequest(data): BlockRequest,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_length_prefixed(io, data).await?;
        io.close().await?;

        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &SyncingProtocol,
        io: &mut T,
        BlockResponse(data): BlockResponse,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_length_prefixed(io, data).await?;
        io.close().await?;

        Ok(())
    }
}

// TODO: move these tests elsewhere
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net;
    use std::time::Duration;
    use tokio::net::TcpListener;

    #[derive(Debug, Encode, Decode, PartialEq, Eq, Copy, Clone)]
    struct Transaction {
        hash: u64,
        value: u128,
    }

    #[tokio::test]
    async fn test_connect_new() {
        let config = Arc::new(common::chain::config::create_mainnet());
        let service = Libp2pService::start(
            "/ip6/::1/tcp/8900".parse().unwrap(),
            &[],
            &[],
            config,
            Duration::from_secs(10),
        )
        .await;
        assert!(service.is_ok());
    }

    // verify that binding to the same interface twice is not possible
    #[ignore]
    #[tokio::test]
    async fn test_connect_new_addrinuse() {
        let config = Arc::new(common::chain::config::create_mainnet());
        let service = Libp2pService::start(
            "/ip6/::1/tcp/8901".parse().unwrap(),
            &[],
            &[],
            Arc::clone(&config),
            Duration::from_secs(10),
        )
        .await;
        assert!(service.is_ok());

        let service = Libp2pService::start(
            "/ip6/::1/tcp/8901".parse().unwrap(),
            &[],
            &[],
            config,
            Duration::from_secs(10),
        )
        .await;

        match service {
            Err(e) => {
                assert_eq!(e, P2pError::SocketError(std::io::ErrorKind::AddrInUse));
            }
            Ok(_) => panic!("address is not in use"),
        }
    }

    // try to connect two nodes together by having `service1` listen for network events
    // and having `service2` trying to connect to `service1`
    #[tokio::test]
    async fn test_connect_accept() {
        let config = Arc::new(common::chain::config::create_mainnet());
        let service1 = Libp2pService::start(
            "/ip6/::1/tcp/8902".parse().unwrap(),
            &[],
            &[],
            Arc::clone(&config),
            Duration::from_secs(10),
        )
        .await;
        let service2 = Libp2pService::start(
            "/ip6/::1/tcp/8903".parse().unwrap(),
            &[],
            &[],
            Arc::clone(&config),
            Duration::from_secs(10),
        )
        .await;
        assert!(service1.is_ok());
        assert!(service2.is_ok());

        let (mut service1, _, _) = service1.unwrap();
        let (mut service2, _, _) = service2.unwrap();
        let conn_addr = service1.local_addr().clone();

        let (res1, res2): (error::Result<ConnectivityEvent<Libp2pService>>, _) =
            tokio::join!(service1.poll_next(), service2.connect(conn_addr));

        assert!(res2.is_ok());
        assert!(res1.is_ok());
    }

    // try to connect to a remote peer with a multiaddress that's missing the peerid
    // and verify that the connection fails
    #[tokio::test]
    async fn test_connect_peer_id_missing() {
        let config = Arc::new(common::chain::config::create_mainnet());
        let addr: Multiaddr = "/ip6/::1/tcp/8904".parse().unwrap();
        let (mut service, _, _) = Libp2pService::start(
            "/ip6/::1/tcp/8905".parse().unwrap(),
            &[],
            &[],
            config,
            Duration::from_secs(10),
        )
        .await
        .unwrap();

        match service.connect(addr).await {
            Ok(_) => panic!("connect succeeded without peer id"),
            Err(e) => {
                assert_eq!(
                    e,
                    P2pError::Libp2pError(Libp2pError::DialError(
                        "Expect peer multiaddr to contain peer ID.".into(),
                    ))
                )
            }
        }
    }

    #[test]
    fn test_parse_discovered_addr() {
        let peer_id: PeerId =
            "12D3KooWE3kBRAnn6jxZMdK1JMWx1iHtR1NKzXSRv5HLTmfD9u9c".parse().unwrap();

        assert_eq!(
            parse_discovered_addr(peer_id, "/ip4/127.0.0.1/udp/9090/quic".parse().unwrap()),
            None
        );
        assert_eq!(
            parse_discovered_addr(peer_id, "/ip6/::1/udp/3217".parse().unwrap()),
            None
        );
        assert_eq!(
            parse_discovered_addr(peer_id, "/ip4/127.0.0.1/tcp/9090/quic".parse().unwrap()),
            None
        );
        assert_eq!(
            parse_discovered_addr(peer_id, "/ip4/127.0.0.1/tcp/80/http".parse().unwrap()),
            None
        );
        assert_eq!(
            parse_discovered_addr(peer_id, "/dns4/foo.com/tcp/80/http".parse().unwrap()),
            None
        );
        assert_eq!(
            parse_discovered_addr(peer_id, "/dns6/foo.com/tcp/443/https".parse().unwrap()),
            None
        );

        let addr: Multiaddr =
            "/ip6/::1/tcp/3217/p2p/12D3KooWRn14SemPVxwzdQNg8e8Trythiww1FWrNfPbukYBmZEbJ"
                .parse()
                .unwrap();
        let id: PeerId = "12D3KooWRn14SemPVxwzdQNg8e8Trythiww1FWrNfPbukYBmZEbJ".parse().unwrap();
        assert_eq!(parse_discovered_addr(id, addr.clone()), Some(addr));

        let id: PeerId = "12D3KooWRn14SemPVxwzdQNg8e8Trythiww1FWrNfPbukYBmZEbJ".parse().unwrap();
        let addr: Multiaddr =
            "/ip4/127.0.0.1/tcp/9090/p2p/12D3KooWRn14SemPVxwzdQNg8e8Trythiww1FWrNfPbukYBmZEbJ"
                .parse()
                .unwrap();
        assert_eq!(parse_discovered_addr(id, addr.clone()), Some(addr));

        let id: PeerId = "12D3KooWRn14SemPVxwzdQNg8e8Trythiww1FWrNfPbukYBmZEbJ".parse().unwrap();
        let addr: Multiaddr = "/ip6/::1/tcp/3217".parse().unwrap();
        assert_eq!(
            parse_discovered_addr(id, addr.clone()),
            Some(addr.with(Protocol::P2p(id.into())))
        );

        let id: PeerId = "12D3KooWRn14SemPVxwzdQNg8e8Trythiww1FWrNfPbukYBmZEbJ".parse().unwrap();
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/9090".parse().unwrap();
        assert_eq!(
            parse_discovered_addr(id, addr.clone()),
            Some(addr.with(Protocol::P2p(id.into())))
        );
    }

    impl PartialEq for Libp2pService {
        fn eq(&self, _: &Self) -> bool {
            true
        }
    }

    impl<T: NetworkService> PartialEq for net::PeerInfo<T> {
        fn eq(&self, other: &Self) -> bool {
            self.peer_id == other.peer_id
                && self.net == other.net
                && self.version == other.version
                && self.agent == other.agent
                && self.protocols == other.protocols
        }
    }

    // verify that vector of address (that all belong to one peer) parse into one `net::Peer` entry
    #[test]
    fn test_parse_peers_valid_1_peer() {
        let config = Arc::new(common::chain::config::create_mainnet());
        let id: PeerId = "12D3KooWRn14SemPVxwzdQNg8e8Trythiww1FWrNfPbukYBmZEbJ".parse().unwrap();
        let ip4: Multiaddr = "/ip4/127.0.0.1/tcp/9090".parse().unwrap();
        let ip6: Multiaddr = "/ip6/::1/tcp/9091".parse().unwrap();
        let addrs = vec![(id, ip4.clone()), (id, ip6.clone())];

        let parsed: Vec<net::AddrInfo<Libp2pService>> = parse_peers(addrs);
        assert_eq!(
            parsed,
            vec![net::AddrInfo {
                id,
                ip4: vec![Arc::new(ip4.with(Protocol::P2p(id.into())))],
                ip6: vec![Arc::new(ip6.with(Protocol::P2p(id.into())))],
            }]
        );
    }

    // discovery 5 different addresses, ipv4 and ipv6 for both peer and an additional
    // dns address for peer
    //
    // verify that `parse_peers` returns two peers and both only have ipv4 and ipv6 addresses
    #[test]
    fn test_parse_peers_valid_2_peers() {
        let id_1: PeerId = "12D3KooWRn14SemPVxwzdQNg8e8Trythiww1FWrNfPbukYBmZEbJ".parse().unwrap();
        let ip4_1: Multiaddr = "/ip4/127.0.0.1/tcp/9090".parse().unwrap();
        let ip6_1: Multiaddr = "/ip6/::1/tcp/9091".parse().unwrap();

        let id_2: PeerId = "12D3KooWE3kBRAnn6jxZMdK1JMWx1iHtR1NKzXSRv5HLTmfD9u9c".parse().unwrap();
        let ip4_2: Multiaddr = "/ip4/127.0.0.1/tcp/8080".parse().unwrap();
        let ip6_2: Multiaddr = "/ip6/::1/tcp/8081".parse().unwrap();
        let dns: Multiaddr = "/dns4/foo.com/tcp/80/http".parse().unwrap();

        let addrs = vec![
            (id_1, ip4_1.clone()),
            (id_2, ip4_2.clone()),
            (id_2, ip6_2.clone()),
            (id_1, ip6_1.clone()),
            (id_2, dns),
        ];

        let mut parsed: Vec<net::AddrInfo<Libp2pService>> = parse_peers(addrs);
        parsed.sort_by(|a, b| a.id.cmp(&b.id));

        assert_eq!(
            parsed,
            vec![
                net::AddrInfo {
                    id: id_2,
                    ip4: vec![Arc::new(ip4_2.with(Protocol::P2p(id_2.into())))],
                    ip6: vec![Arc::new(ip6_2.with(Protocol::P2p(id_2.into())))],
                },
                net::AddrInfo {
                    id: id_1,
                    ip4: vec![Arc::new(ip4_1.with(Protocol::P2p(id_1.into())))],
                    ip6: vec![Arc::new(ip6_1.with(Protocol::P2p(id_1.into())))],
                },
            ]
        );
    }

    // find 3 peers but only one of the peers have an accepted address available so verify
    // that `parse_peers()` returns only that peer
    #[test]
    fn test_parse_peers_valid_3_peers_1_valid() {
        let id_1: PeerId = "12D3KooWRn14SemPVxwzdQNg8e8Trythiww1FWrNfPbukYBmZEbJ".parse().unwrap();
        let ip4: Multiaddr = "/ip4/127.0.0.1/tcp/9090".parse().unwrap();

        let id_2: PeerId = "12D3KooWE3kBRAnn6jxZMdK1JMWx1iHtR1NKzXSRv5HLTmfD9u9c".parse().unwrap();
        let dns: Multiaddr = "/dns4/foo.com/tcp/80/http".parse().unwrap();

        let id_3: PeerId = "12D3KooWGK4RzvNeioS9aXdzmYXU3mgDrRPjQd8SVyXCkHNxLbWN".parse().unwrap();
        let quic: Multiaddr = "/ip4/127.0.0.1/tcp/9090/quic".parse().unwrap();

        let addrs = vec![(id_1, ip4.clone()), (id_2, dns), (id_3, quic)];
        let parsed: Vec<net::AddrInfo<Libp2pService>> = parse_peers(addrs);

        assert_eq!(
            parsed,
            vec![net::AddrInfo {
                id: id_1,
                ip4: vec![Arc::new(ip4.with(Protocol::P2p(id_1.into())))],
                ip6: vec![],
            }]
        );
    }

    // try to connect to a service that is not listening with a small timeout and verify that the connection fails
    // TODO: verify on windows/mac
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_connect_with_timeout() {
        let config = Arc::new(common::chain::config::create_mainnet());
        let (mut service, _, _) = Libp2pService::start(
            test_utils::make_address("/ip6/::1/tcp/"),
            &[],
            &[],
            config,
            Duration::from_secs(2),
        )
        .await
        .unwrap();

        let port = portpicker::pick_unused_port().unwrap();
        let id: PeerId = "12D3KooWE3kBRAnn6jxZMdK1JMWx1iHtR1NKzXSRv5HLTmfD9u9c".parse().unwrap();
        let mut addr: Multiaddr = format!("/ip6/::1/tcp/{}", port).parse().unwrap();
        addr.push(Protocol::P2p(id.into()));

        // first try to connect to address nobody is listening to
        // and verify that the connection is refused immediately
        let start = std::time::SystemTime::now();
        assert_eq!(
            service.connect(addr.clone()).await,
            Err(P2pError::SocketError(std::io::ErrorKind::ConnectionRefused))
        );
        assert_eq!(
            std::time::SystemTime::now().duration_since(start).unwrap().as_secs(),
            0
        );

        // then create a socket that listens to the address and verify that it takes
        // 2 seconds to get the `ConnectionRefused` error, as expected
        let _service = TcpListener::bind(format!("[::1]:{}", port)).await.unwrap();
        let start = std::time::SystemTime::now();
        assert_eq!(
            service.connect(addr).await,
            Err(P2pError::SocketError(std::io::ErrorKind::ConnectionRefused))
        );
        assert!(std::time::SystemTime::now().duration_since(start).unwrap().as_secs() >= 2);
    }
}
