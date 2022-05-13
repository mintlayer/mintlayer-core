// Copyright (c) 2021 Protocol Labs
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
    error::{self, Libp2pError, P2pError},
    message,
    net::{self, libp2p::common},
};
use futures::StreamExt;
use libp2p::{
    core::{connection::ConnectedPoint, either::EitherError},
    floodsub::{FloodsubEvent, Topic},
    mdns::MdnsEvent,
    streaming::{OutboundStreamId, StreamHandle, StreamingEvent},
    swarm::{NegotiatedSubstream, ProtocolsHandlerUpgrErr, Swarm, SwarmEvent},
    Multiaddr, PeerId,
};
use logging::log;
use serialization::Decode;
use std::collections::{HashMap, HashSet};
use tokio::sync::{mpsc, oneshot};

pub struct Backend {
    /// Created libp2p swarm object
    swarm: Swarm<common::ComposedBehaviour>,

    /// Receiver for incoming commands
    cmd_rx: mpsc::Receiver<common::Command>,

    /// Sender for outgoing connectivity events
    conn_tx: mpsc::Sender<common::ConnectivityEvent>,

    /// Sender for outgoing floodsub events
    flood_tx: mpsc::Sender<common::FloodsubEvent>,

    /// Hashmap of pending outbound connections
    dials: HashMap<PeerId, oneshot::Sender<error::Result<()>>>,

    /// Hashmap of pending inbound connections
    conns: HashMap<PeerId, Multiaddr>,

    /// Hashmap of pending outbound streams
    streams: HashMap<
        OutboundStreamId,
        oneshot::Sender<error::Result<StreamHandle<NegotiatedSubstream>>>,
    >,

    /// Hashmap of topics and their participants
    active_floodsubs: HashMap<Topic, HashSet<PeerId>>,

    /// Whether mDNS peer events should be relayed to P2P manager
    relay_mdns: bool,
}

impl Backend {
    pub fn new(
        swarm: Swarm<common::ComposedBehaviour>,
        cmd_rx: mpsc::Receiver<common::Command>,
        conn_tx: mpsc::Sender<common::ConnectivityEvent>,
        flood_tx: mpsc::Sender<common::FloodsubEvent>,
        relay_mdns: bool,
    ) -> Self {
        Self {
            swarm,
            cmd_rx,
            conn_tx,
            flood_tx,
            dials: HashMap::new(),
            conns: HashMap::new(),
            streams: HashMap::new(),
            active_floodsubs: HashMap::new(),
            relay_mdns,
        }
    }

    pub async fn run(&mut self) -> error::Result<()> {
        log::debug!("starting event loop");

        loop {
            tokio::select! {
                event = self.swarm.next() => match event {
                    Some(event) => self.on_event(event).await?,
                    None => return Err(P2pError::ChannelClosed)
                },
                command = self.cmd_rx.recv() => match command {
                    Some(cmd) => self.on_command(cmd).await?,
                    None => return Err(P2pError::ChannelClosed),
                },
            }
        }
    }

    /// Collect peers into a vector and send appropriate event to P2P
    async fn send_discovery_event(
        &mut self,
        peers: Vec<(PeerId, Multiaddr)>,
        event_fn: impl FnOnce(Vec<(PeerId, Multiaddr)>) -> common::ConnectivityEvent,
    ) -> error::Result<()> {
        if !self.relay_mdns || peers.is_empty() {
            return Ok(());
        }

        self.conn_tx.send(event_fn(peers)).await.map_err(|_| P2pError::ChannelClosed)
    }

    /// Handle event received from the swarm object
    #[allow(clippy::type_complexity)]
    async fn on_event(
        &mut self,
        event: SwarmEvent<
            common::ComposedEvent,
            EitherError<
                EitherError<ProtocolsHandlerUpgrErr<std::convert::Infallible>, void::Void>,
                ProtocolsHandlerUpgrErr<std::io::Error>,
            >,
        >,
    ) -> error::Result<()> {
        match event {
            SwarmEvent::Behaviour(common::ComposedEvent::StreamingEvent(
                StreamingEvent::StreamOpened {
                    id,
                    peer_id,
                    stream,
                },
            )) => {
                log::trace!(
                    "stream opened with remote, id {:?}, peer id {:?}",
                    id,
                    peer_id
                );

                self.streams
                    .remove(&id)
                    .ok_or_else(|| P2pError::Unknown("Pending stream does not exist".to_string()))?
                    .send(Ok(stream))
                    .map_err(|_| P2pError::ChannelClosed)
            }
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => match endpoint {
                ConnectedPoint::Dialer { .. } => {
                    log::trace!("connection established (dialer), peer id {:?}", peer_id);

                    self.dials
                        .remove(&peer_id)
                        .ok_or_else(|| {
                            P2pError::Unknown("Pending connection does not exist".to_string())
                        })?
                        .send(Ok(()))
                        .map_err(|_| P2pError::ChannelClosed)
                }
                ConnectedPoint::Listener {
                    local_addr: _,
                    send_back_addr,
                } => {
                    log::trace!("connection established (listener), peer id {:?}", peer_id);

                    self.conns.insert(peer_id, send_back_addr);
                    Ok(())
                }
            },
            SwarmEvent::OutgoingConnectionError { peer_id, error } => {
                if let Some(peer_id) = peer_id {
                    self.dials
                        .remove(&peer_id)
                        .ok_or_else(|| {
                            P2pError::Unknown("Pending connection does not exist".to_string())
                        })?
                        .send(Err(P2pError::SocketError(
                            std::io::ErrorKind::ConnectionRefused,
                        )))
                        .map_err(|_| P2pError::ChannelClosed)
                } else {
                    log::error!("unhandled connection error: {:#?}", error);
                    Ok(())
                }
            }
            SwarmEvent::Behaviour(common::ComposedEvent::StreamingEvent(
                StreamingEvent::NewIncoming {
                    peer_id, stream, ..
                },
            )) => {
                log::trace!("incoming stream, peer id {:?}", peer_id);

                let addr = self.conns.remove(&peer_id).ok_or_else(|| {
                    P2pError::Unknown("Pending connection does not exist".to_string())
                })?;
                self.conn_tx
                    .send(common::ConnectivityEvent::ConnectionAccepted {
                        socket: Box::new(net::libp2p::Libp2pSocket {
                            id: peer_id,
                            addr,
                            stream,
                        }),
                    })
                    .await
                    .map_err(|_| P2pError::ChannelClosed)
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                log::trace!("new listen address {:?}", address);
                Ok(())
            }
            SwarmEvent::Behaviour(common::ComposedEvent::MdnsEvent(MdnsEvent::Discovered(
                peers,
            ))) => {
                self.send_discovery_event(peers.collect(), |peers| {
                    common::ConnectivityEvent::PeerDiscovered { peers }
                })
                .await
            }
            SwarmEvent::Behaviour(common::ComposedEvent::MdnsEvent(MdnsEvent::Expired(
                expired,
            ))) => {
                self.send_discovery_event(expired.collect(), |peers| {
                    common::ConnectivityEvent::PeerExpired { peers }
                })
                .await
            }
            SwarmEvent::Behaviour(common::ComposedEvent::Libp2pFloodsubEvent(
                FloodsubEvent::Subscribed { peer_id, topic },
            )) => {
                log::debug!(
                    "add new subscriber ({:?}) to floodsub topic {:?}",
                    peer_id,
                    topic
                );

                self.active_floodsubs.entry(topic).or_insert_with(HashSet::new).insert(peer_id);
                Ok(())
            }
            SwarmEvent::Behaviour(common::ComposedEvent::Libp2pFloodsubEvent(
                FloodsubEvent::Unsubscribed { peer_id, topic },
            )) => match self.active_floodsubs.get_mut(&topic) {
                Some(peers) => {
                    log::debug!(
                        "remove subscriber ({:?}) from floodsub topic {:?}",
                        peer_id,
                        topic
                    );

                    peers.remove(&peer_id);
                    Ok(())
                }
                None => {
                    log::warn!(
                        "topic {:?} does not exist, cannot remove subscriber {:?}",
                        topic,
                        peer_id
                    );
                    Ok(())
                }
            },
            SwarmEvent::Behaviour(common::ComposedEvent::Libp2pFloodsubEvent(
                FloodsubEvent::Message(message),
            )) => {
                // for mintlayer there should only ever be one topic per message
                // because transactions are not published in block topic and vice versa
                //
                // message with multiple topics is considered invalid
                let peer_id = message.source;

                let topic = if message.topics.len() == 1 {
                    match net::FloodsubTopic::try_from(&message.topics[0]) {
                        Ok(topic) => topic,
                        Err(e) => {
                            log::warn!(
                                "failed to convert ({:#?}) to a topic: {:?}",
                                message.topics[0],
                                e
                            );
                            return Ok(());
                        }
                    }
                } else {
                    log::warn!(
                        "message with multiple topics ({:#?}) but only one expected",
                        message.topics
                    );
                    return Ok(());
                };

                let message = match message::Message::decode(&mut &message.data[..]) {
                    Ok(data) => data,
                    Err(e) => {
                        log::warn!("failed to decode floodsub message: {:?}", e);
                        return Ok(());
                    }
                };

                log::trace!(
                    "message ({:#?}) received from floodsub topic {:?}",
                    message,
                    topic
                );

                self.flood_tx
                    .send(common::FloodsubEvent::MessageReceived {
                        peer_id,
                        topic,
                        message,
                    })
                    .await
                    .map_err(|_| P2pError::ChannelClosed)
            }
            _ => {
                log::warn!("unhandled event {:?}", event);
                Ok(())
            }
        }
    }

    /// Handle command received from the libp2p front-end
    async fn on_command(&mut self, cmd: common::Command) -> error::Result<()> {
        log::debug!("handle incoming command {:?}", cmd);

        match cmd {
            common::Command::Listen { addr, response } => {
                let res = self.swarm.listen_on(addr).map(|_| ()).map_err(|e| e.into());
                response.send(res).map_err(|_| P2pError::ChannelClosed)
            }
            common::Command::Dial {
                peer_id,
                peer_addr,
                response,
            } => match self.swarm.dial(peer_addr) {
                Ok(_) => {
                    self.dials.insert(peer_id, response);
                    Ok(())
                }
                Err(e) => Err(e.into()),
            },
            common::Command::OpenStream { peer_id, response } => {
                let stream_id = self.swarm.behaviour_mut().streaming.open_stream(peer_id);
                self.streams.insert(stream_id, response);
                Ok(())
            }
            common::Command::SendMessage {
                topic,
                message,
                response,
            } => {
                let topic: Topic = (&topic).into();
                log::trace!("publish message on floodsub topic {:?}", topic);

                // check if the floodsub topic where the message is supposed to be sent
                // exists (the hashmap entry exists) and that it contains subscribers
                if let Err(e) = match self.active_floodsubs.get(&topic) {
                    None => Err(Libp2pError::PublishError("NoPeers".to_string())),
                    Some(peers) => {
                        if peers.is_empty() {
                            Err(Libp2pError::PublishError("NoPeers".to_string()))
                        } else {
                            Ok(())
                        }
                    }
                } {
                    response
                        .send(Err(P2pError::Libp2pError(e)))
                        .map_err(|_| P2pError::ChannelClosed)?;
                    return Ok(());
                }

                self.swarm.behaviour_mut().floodsub.publish(topic, message);
                response.send(Ok(())).map_err(|_| P2pError::ChannelClosed)
            }
            common::Command::Register { peer, response } => {
                self.swarm.behaviour_mut().floodsub.add_node_to_partial_view(peer);
                response.send(Ok(())).map_err(|_| P2pError::ChannelClosed)
            }
            common::Command::Unregister { peer, response } => {
                self.swarm.behaviour_mut().floodsub.remove_node_from_partial_view(&peer);
                response.send(Ok(())).map_err(|_| P2pError::ChannelClosed)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::{
        core::upgrade,
        floodsub::Floodsub,
        identity,
        mdns::Mdns,
        mplex, noise,
        streaming::{IdentityCodec, Streaming},
        swarm::SwarmBuilder,
        tcp::TcpConfig,
        Transport,
    };
    use tokio::sync::oneshot;

    // create a swarm object which is the top-level object of libp2p
    //
    // it contains the selected transport for the swarm (in this case TCP + Noise)
    // and any custom network behaviour such as streaming or mDNS support
    async fn make_swarm() -> Swarm<common::ComposedBehaviour> {
        let id_keys = identity::Keypair::generate_ed25519();
        let peer_id = id_keys.public().to_peer_id();
        let noise_keys =
            noise::Keypair::<noise::X25519Spec>::new().into_authentic(&id_keys).unwrap();

        let transport = TcpConfig::new()
            .nodelay(true)
            .port_reuse(false)
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
            .multiplex(mplex::MplexConfig::new())
            .boxed();

        let behaviour = common::ComposedBehaviour {
            streaming: Streaming::<IdentityCodec>::default(),
            mdns: Mdns::new(Default::default()).await.unwrap(),
            floodsub: Floodsub::new(peer_id),
        };

        SwarmBuilder::new(transport, behaviour, peer_id).build()
    }

    // verify that binding to a free network interface succeeds
    #[tokio::test]
    async fn test_command_listen_success() {
        let swarm = make_swarm().await;
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (flood_tx, _) = mpsc::channel(64);
        let (conn_tx, _) = mpsc::channel(64);
        let mut backend = Backend::new(swarm, cmd_rx, conn_tx, flood_tx, false);

        tokio::spawn(async move { backend.run().await });

        let (tx, rx) = oneshot::channel();
        let res = cmd_tx
            .send(common::Command::Listen {
                addr: "/ip6/::1/tcp/8890".parse().unwrap(),
                response: tx,
            })
            .await;
        assert!(res.is_ok());

        let res = rx.await;
        assert!(res.is_ok());
        assert!(res.unwrap().is_ok());
    }

    // verify that binding twice to the same network inteface fails
    #[ignore]
    #[tokio::test]
    async fn test_command_listen_addrinuse() {
        let swarm = make_swarm().await;
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (flood_tx, _) = mpsc::channel(64);
        let (conn_tx, _) = mpsc::channel(64);
        let mut backend = Backend::new(swarm, cmd_rx, conn_tx, flood_tx, false);

        tokio::spawn(async move { backend.run().await });

        // start listening to [::1]:8890
        let (tx, rx) = oneshot::channel();
        let res = cmd_tx
            .send(common::Command::Listen {
                addr: "/ip6/::1/tcp/8891".parse().unwrap(),
                response: tx,
            })
            .await;
        assert!(res.is_ok());

        let res = rx.await;
        assert!(res.is_ok());
        assert!(res.unwrap().is_ok());

        // try to bind to the same interface again
        let (tx, rx) = oneshot::channel();
        let res = cmd_tx
            .send(common::Command::Listen {
                addr: "/ip6/::1/tcp/8891".parse().unwrap(),
                response: tx,
            })
            .await;
        assert!(res.is_ok());

        let res = rx.await;
        assert!(res.is_ok());
        assert!(res.unwrap().is_err());
    }

    // verify that libp2p is able to notice if the p2p object closes
    // the command tx which signals that it is no longer responsive
    #[tokio::test]
    async fn test_drop_command_tx() {
        let swarm = make_swarm().await;
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (flood_tx, _) = mpsc::channel(64);
        let (conn_tx, _) = mpsc::channel(64);
        let mut backend = Backend::new(swarm, cmd_rx, conn_tx, flood_tx, false);

        drop(cmd_tx);
        assert_eq!(backend.run().await, Err(P2pError::ChannelClosed));
    }
}
