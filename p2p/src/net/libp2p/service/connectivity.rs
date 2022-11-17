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

use std::{collections::BTreeSet, str::FromStr};

use async_trait::async_trait;
use itertools::Itertools;
use libp2p::{core::PeerId, multiaddr, Multiaddr};
use tap::TapFallible;
use tokio::sync::{mpsc, oneshot};

use common::primitives::semver::SemVer;
use logging::log;

use crate::{
    error::{ConversionError, P2pError, ProtocolError},
    net::{
        self,
        libp2p::types,
        types::{ConnectivityEvent, Protocol, ProtocolType},
        ConnectivityService, NetworkingService,
    },
};

/// Connectivity handle for libp2p
#[derive(Debug)]
pub struct Libp2pConnectivityHandle<T: NetworkingService> {
    /// Peer Id of the local node
    peer_id: PeerId,

    /// Channel for sending commands to libp2p backend
    cmd_tx: mpsc::UnboundedSender<types::Command>,

    /// Channel for receiving connectivity events from libp2p backend
    conn_rx: mpsc::UnboundedReceiver<types::ConnectivityEvent>,
    _marker: std::marker::PhantomData<fn() -> T>,
}

impl<T: NetworkingService> Libp2pConnectivityHandle<T> {
    pub fn new(
        peer_id: PeerId,
        cmd_tx: mpsc::UnboundedSender<types::Command>,
        conn_rx: mpsc::UnboundedReceiver<types::ConnectivityEvent>,
    ) -> Self {
        Self {
            peer_id,
            cmd_tx,
            conn_rx,
            _marker: Default::default(),
        }
    }
}

/// Verify that the discovered multiaddress is in a format that Mintlayer supports:
///   /ip4/<IPv4 address>/tcp/<TCP port>/p2p/<PeerId multihash>
///   /ip6/<IPv6 address>/tcp/<TCP port>/p2p/<PeerId multihash>
///
/// Documentation for libp2p-mdns doesn't mention if `peer_addr` includes the PeerId
/// so if it doesn't, add it. Otherwise just return the address
pub fn parse_discovered_addr(peer_id: PeerId, peer_addr: Multiaddr) -> Option<Multiaddr> {
    let mut components = peer_addr.iter();

    if !std::matches!(
        components.next(),
        Some(multiaddr::Protocol::Ip4(_) | multiaddr::Protocol::Ip6(_))
    ) {
        return None;
    }

    if !std::matches!(components.next(), Some(multiaddr::Protocol::Tcp(_))) {
        return None;
    }

    match components.next() {
        Some(multiaddr::Protocol::P2p(_)) => Some(peer_addr.clone()),
        None => Some(peer_addr.with(multiaddr::Protocol::P2p(peer_id.into()))),
        Some(_) => None,
    }
}

/// Get the network layer protocol from `addr`
fn get_addr_from_multiaddr(addr: &Multiaddr) -> Option<multiaddr::Protocol> {
    addr.iter().next()
}

impl<T> FromIterator<(PeerId, Multiaddr)> for net::types::AddrInfo<T>
where
    T: NetworkingService<PeerId = PeerId, Address = Multiaddr>,
{
    fn from_iter<I: IntoIterator<Item = (PeerId, Multiaddr)>>(iter: I) -> Self {
        let mut entry = net::types::AddrInfo {
            peer_id: PeerId::random(),
            ip4: Vec::new(),
            ip6: Vec::new(),
        };

        iter.into_iter().for_each(|(id, addr)| {
            entry.peer_id = id;
            match get_addr_from_multiaddr(&addr) {
                Some(multiaddr::Protocol::Ip4(_)) => entry.ip4.push(addr),
                Some(multiaddr::Protocol::Ip6(_)) => entry.ip6.push(addr),
                _ => panic!("parse_discovered_addr() failed!"),
            }
        });

        log::trace!(
            "id {:?}, ipv4 {:#?}, ipv6 {:#?}",
            entry.peer_id,
            entry.ip4,
            entry.ip6
        );

        entry
    }
}

/// Parse all discovered addresses and group them by PeerId
pub fn parse_peers<T>(mut peers: Vec<(PeerId, Multiaddr)>) -> Vec<net::types::AddrInfo<T>>
where
    T: NetworkingService<PeerId = PeerId, Address = Multiaddr>,
{
    peers.sort_by(|a, b| a.0.cmp(&b.0));
    peers
        .into_iter()
        .map(|(id, addr)| (id, parse_discovered_addr(id, addr)))
        .filter_map(|(id, addr)| addr.map(|addr| (id, addr)))
        .group_by(|info| info.0)
        .into_iter()
        .map(|(_id, addrs)| net::types::AddrInfo::from_iter(addrs))
        .collect()
}

impl<T> TryInto<net::types::PeerInfo<T>> for types::IdentifyInfoWrapper
where
    T: NetworkingService<PeerId = PeerId>,
{
    type Error = P2pError;

    fn try_into(self) -> Result<net::types::PeerInfo<T>, Self::Error> {
        let proto = self.protocol_version.clone();
        let (version, magic_bytes) =
            match sscanf::scanf!(proto, "/{}/{}.{}.{}-{:x}", String, u8, u8, u16, u32) {
                Err(_err) => Err(P2pError::ProtocolError(ProtocolError::InvalidProtocol)),
                Ok((proto, maj, min, pat, magic)) => {
                    if proto != "mintlayer" {
                        return Err(P2pError::ProtocolError(ProtocolError::InvalidProtocol));
                    }

                    Ok((SemVer::new(maj, min, pat), magic.to_le_bytes()))
                }
            }?;

        Ok(net::types::PeerInfo {
            peer_id: PeerId::from_public_key(&self.public_key),
            magic_bytes,
            version,
            agent: Some(self.agent_version.clone()),
            protocols: parse_protocols(&self.protocols),
        })
    }
}

#[async_trait]
impl<T> ConnectivityService<T> for Libp2pConnectivityHandle<T>
where
    T: NetworkingService<Address = Multiaddr, PeerId = PeerId> + Send,
    types::IdentifyInfoWrapper: TryInto<net::types::PeerInfo<T>, Error = P2pError>,
{
    async fn connect(&mut self, addr: T::Address) -> crate::Result<()> {
        log::debug!("try to establish an outbound connection, address {addr}");

        let peer_id = PeerId::try_from_multiaddr(&addr).ok_or_else(|| {
            P2pError::ConversionError(ConversionError::InvalidAddress(addr.to_string()))
        })?;

        // try to connect to remote peer
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(types::Command::Connect {
            peer_id,
            peer_addr: addr.clone(),
            response: tx,
        })?;

        rx.await.map_err(P2pError::from)?.map_err(P2pError::from)
    }

    async fn disconnect(&mut self, peer_id: T::PeerId) -> crate::Result<()> {
        log::debug!("disconnect peer {:?}", peer_id);

        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(types::Command::Disconnect {
            peer_id,
            response: tx,
        })?;
        rx.await.map_err(P2pError::from)?.map_err(P2pError::from)
    }

    async fn local_addr(&self) -> crate::Result<Option<T::Address>> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(types::Command::ListenAddress { response: tx })?;
        rx.await.map_err(P2pError::from)
    }

    fn peer_id(&self) -> &T::PeerId {
        &self.peer_id
    }

    async fn ban_peer(&mut self, peer_id: T::PeerId) -> crate::Result<()> {
        log::debug!("ban peer {}", peer_id);

        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(types::Command::BanPeer {
            peer_id,
            response: tx,
        })?;
        rx.await.map_err(P2pError::from)?.map_err(P2pError::from)
    }

    async fn poll_next(&mut self) -> crate::Result<ConnectivityEvent<T>> {
        match self.conn_rx.recv().await.ok_or(P2pError::ChannelClosed)? {
            types::ConnectivityEvent::OutboundAccepted { address, peer_info } => {
                Ok(ConnectivityEvent::OutboundAccepted {
                    address,
                    peer_info: peer_info.try_into()?,
                })
            }
            types::ConnectivityEvent::ConnectionError { address, error } => {
                Ok(ConnectivityEvent::ConnectionError { address, error })
            }
            types::ConnectivityEvent::InboundAccepted { address, peer_info } => {
                Ok(ConnectivityEvent::InboundAccepted {
                    address,
                    peer_info: peer_info.try_into()?,
                })
            }
            types::ConnectivityEvent::ConnectionClosed { peer_id } => {
                Ok(ConnectivityEvent::ConnectionClosed { peer_id })
            }
            types::ConnectivityEvent::Discovered { peers } => Ok(ConnectivityEvent::Discovered {
                peers: parse_peers(peers),
            }),
            types::ConnectivityEvent::Expired { peers } => Ok(ConnectivityEvent::Expired {
                peers: parse_peers(peers),
            }),
            types::ConnectivityEvent::Misbehaved { peer_id, error } => {
                Ok(ConnectivityEvent::Misbehaved { peer_id, error })
            }
        }
    }
}

impl FromStr for Protocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (protocol, version) = s.rsplit_once('/').ok_or("Invalid protocol format")?;

        let protocol = match protocol {
            "/meshsub" => ProtocolType::PubSub,
            "/ipfs/ping" => ProtocolType::Ping,
            "/mintlayer/sync" => ProtocolType::Sync,
            _ => return Err("Unknown protocol".into()),
        };

        let version = SemVer::try_from(version)?;

        Ok(Protocol::new(protocol, version))
    }
}

/// Parses the given strings into a set of protocols.
///
/// The protocols that aren't related to any `ProtocolType` are ignored.
fn parse_protocols<I, P>(protocols: I) -> BTreeSet<Protocol>
where
    I: IntoIterator<Item = P>,
    P: AsRef<str>,
{
    protocols
        .into_iter()
        .filter_map(|p| {
            p.as_ref()
                .parse()
                .tap_err(|e| log::trace!("Ignoring '{}' protocol: {e:?}", p.as_ref()))
                .ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        let data = [
            ("/meshsub/1.0.0", ProtocolType::PubSub, SemVer::new(1, 0, 0)),
            ("/meshsub/1.1.0", ProtocolType::PubSub, SemVer::new(1, 1, 0)),
            ("/ipfs/ping/2.3.4", ProtocolType::Ping, SemVer::new(2, 3, 4)),
            (
                "/mintlayer/sync/0.1.0",
                ProtocolType::Sync,
                SemVer::new(0, 1, 0),
            ),
        ];

        for (str, protocol, version) in data {
            let actual = str.parse::<Protocol>().unwrap();
            assert_eq!(actual.protocol(), protocol);
            assert_eq!(actual.version(), version);
        }
    }

    #[test]
    fn parse_standard_protocols() {
        let expected: BTreeSet<_> = [
            Protocol::new(ProtocolType::PubSub, SemVer::new(1, 0, 0)),
            Protocol::new(ProtocolType::PubSub, SemVer::new(1, 1, 0)),
            Protocol::new(ProtocolType::Ping, SemVer::new(1, 0, 0)),
            Protocol::new(ProtocolType::Sync, SemVer::new(0, 1, 0)),
        ]
        .into_iter()
        .collect();
        let parsed = parse_protocols([
            "/meshsub/1.0.0",
            "/meshsub/1.1.0",
            "/ipfs/ping/1.0.0",
            "/ipfs/id/1.0.0",
            "/ipfs/id/push/1.0.0",
            "/mintlayer/sync/0.1.0",
        ]);
        assert_eq!(expected, parsed);
    }
}
