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
#![allow(unused)]

use crate::{
    error::{self, Libp2pError, P2pError},
    message,
    net::{self, libp2p::types},
};
use futures::StreamExt;
use libp2p::{
    core::{connection::ConnectedPoint, either::EitherError},
    gossipsub::{
        error::GossipsubHandlerError, Gossipsub, GossipsubEvent, GossipsubMessage,
        IdentTopic as Topic, MessageAuthenticity, MessageId, ValidationMode,
    },
    identify::{IdentifyEvent, IdentifyInfo},
    mdns::MdnsEvent,
    ping,
    streaming::{OutboundStreamId, StreamHandle, StreamingEvent},
    swarm::{NegotiatedSubstream, ProtocolsHandlerUpgrErr, Swarm, SwarmEvent},
    Multiaddr, PeerId,
};
use logging::log;
use serialization::Decode;
use std::collections::{HashMap, HashSet};
use tokio::sync::{mpsc, oneshot};

#[derive(Debug)]
enum PendingState {
    /// Outbound connection has been dialed, wait for `ConnectionEstablished` event
    Dialed {
        tx: oneshot::Sender<error::Result<IdentifyInfo>>,
    },

    /// Connection established for outbound connection
    OutboundAccepted {
        tx: oneshot::Sender<error::Result<IdentifyInfo>>,
    },

    /// Connection established for inbound connection
    InboundAccepted { addr: Multiaddr },
}

pub struct Backend {
    /// Created libp2p swarm object
    swarm: Swarm<types::ComposedBehaviour>,

    /// Receiver for incoming commands
    cmd_rx: mpsc::Receiver<types::Command>,

    /// Sender for outgoing connectivity events
    conn_tx: mpsc::Sender<types::ConnectivityEvent>,

    /// Sender for outgoing gossipsub events
    gossip_tx: mpsc::Sender<types::PubSubEvent>,

    /// Hashmap of pending outbound connections
    dials: HashMap<PeerId, oneshot::Sender<error::Result<()>>>,

    // TODO:
    pending: HashMap<PeerId, PendingState>,

    /// Hashmap of pending inbound connections
    conns: HashMap<PeerId, Multiaddr>,

    /// Hashmap of pending outbound streams
    streams: HashMap<
        OutboundStreamId,
        oneshot::Sender<error::Result<StreamHandle<NegotiatedSubstream>>>,
    >,

    // TODO: remove this?
    /// Hashmap of topics and their participants
    active_gossipsubs: HashMap<Topic, HashSet<PeerId>>,

    /// Whether mDNS peer events should be relayed to P2P manager
    relay_mdns: bool,
}

impl Backend {
    pub fn new(
        swarm: Swarm<types::ComposedBehaviour>,
        cmd_rx: mpsc::Receiver<types::Command>,
        conn_tx: mpsc::Sender<types::ConnectivityEvent>,
        gossip_tx: mpsc::Sender<types::PubSubEvent>,
        relay_mdns: bool,
    ) -> Self {
        Self {
            swarm,
            cmd_rx,
            conn_tx,
            gossip_tx,
            dials: HashMap::new(),
            pending: HashMap::new(),
            conns: HashMap::new(),
            streams: HashMap::new(),
            active_gossipsubs: HashMap::new(),
            relay_mdns,
        }
    }

    // TODO: into_fatal()???
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
        event_fn: impl FnOnce(Vec<(PeerId, Multiaddr)>) -> types::ConnectivityEvent,
    ) -> error::Result<()> {
        if !self.relay_mdns || peers.is_empty() {
            return Ok(());
        }

        self.conn_tx.send(event_fn(peers)).await.map_err(|_| P2pError::ChannelClosed)
    }

    // TODO: return errors from here so all state transitions can be tested
    /// Handle event received from the swarm object
    #[allow(clippy::type_complexity)]
    async fn on_event(
        &mut self,
        event: SwarmEvent<
            types::ComposedEvent,
            EitherError<
                EitherError<
                    EitherError<
                        EitherError<ProtocolsHandlerUpgrErr<std::convert::Infallible>, void::Void>,
                        GossipsubHandlerError,
                    >,
                    ping::Failure,
                >,
                std::io::Error,
            >,
        >,
    ) -> error::Result<()> {
        // TODO: separate this code into protocol-specific handlers!
        // TODO: error codes?
        match event {
            // SwarmEvent::Behaviour(types::ComposedEvent::StreamingEvent(
            //     StreamingEvent::StreamOpened {
            //         id,
            //         peer_id,
            //         stream,
            //     },
            // )) => {
            //     log::trace!(
            //         "stream opened with remote, id {:?}, peer id {:?}",
            //         id,
            //         peer_id
            //     );
            //     self.streams
            //         .remove(&id)
            //         .ok_or_else(|| P2pError::Unknown("Pending stream does not exist".to_string()))?
            //         .send(Ok(stream))
            //         .map_err(|_| P2pError::ChannelClosed)
            // }
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => match endpoint {
                ConnectedPoint::Dialer { .. } => {
                    log::trace!("connection established (dialer), peer id {:?}", peer_id);

                    match self.pending.remove(&peer_id) {
                        Some(PendingState::Dialed { tx }) => {
                            self.pending.insert(peer_id, PendingState::OutboundAccepted { tx });
                        }
                        Some(state) => log::error!(
                            "connection state is invalid. Expected `Dialed`, got {:?}",
                            state
                        ),
                        None => log::error!("peer {:?} does not exist", peer_id),
                    }

                    Ok(())
                }
                ConnectedPoint::Listener {
                    local_addr: _,
                    send_back_addr,
                } => {
                    log::trace!("connection established (listener), peer id {:?}", peer_id);

                    match self.pending.remove(&peer_id) {
                        Some(state) => {
                            // TODO: is this an actual error?
                            log::error!("peer {:?} already has active connection!", peer_id);
                        }
                        None => {
                            self.pending.insert(
                                peer_id,
                                PendingState::InboundAccepted {
                                    addr: send_back_addr,
                                },
                            );
                        }
                    }
                    Ok(())
                }
            },
            SwarmEvent::OutgoingConnectionError { peer_id, error } => {
                if let Some(peer_id) = peer_id {
                    match self.pending.remove(&peer_id) {
                        Some(PendingState::Dialed { tx })
                        | Some(PendingState::OutboundAccepted { tx }) => tx
                            .send(Err(P2pError::SocketError(
                                std::io::ErrorKind::ConnectionRefused,
                            )))
                            .map_err(|_| P2pError::ChannelClosed),
                        _ => {
                            log::debug!("connection failed for peer {:?}: {:?}", peer_id, error);
                            Ok(())
                        }
                    }
                } else {
                    log::error!("unhandled connection error: {:#?}", error);
                    Ok(())
                }
            }
            // SwarmEvent::Behaviour(types::ComposedEvent::StreamingEvent(
            //     StreamingEvent::NewIncoming {
            //         peer_id, stream, ..
            //     },
            // )) => {
            //     log::trace!("incoming stream, peer id {:?}", peer_id);
            //     let addr = self.conns.remove(&peer_id).ok_or_else(|| {
            //         P2pError::Unknown("Pending connection does not exist".to_string())
            //     })?;
            //     self.conn_tx
            //         .send(types::ConnectivityEvent::ConnectionAccepted {
            //             socket: Box::new(net::libp2p::Libp2pSocket {
            //                 id: peer_id,
            //                 addr,
            //                 stream,
            //             }),
            //         })
            //         .await
            //         .map_err(|_| P2pError::ChannelClosed)
            // }
            SwarmEvent::NewListenAddr { address, .. } => {
                log::trace!("new listen address {:?}", address);
                Ok(())
            }
            SwarmEvent::Behaviour(types::ComposedEvent::MdnsEvent(MdnsEvent::Discovered(
                peers,
            ))) => {
                self.send_discovery_event(peers.collect(), |peers| {
                    types::ConnectivityEvent::PeerDiscovered { peers }
                })
                .await
            }
            SwarmEvent::Behaviour(types::ComposedEvent::MdnsEvent(MdnsEvent::Expired(expired))) => {
                self.send_discovery_event(expired.collect(), |peers| {
                    types::ConnectivityEvent::PeerExpired { peers }
                })
                .await
            }
            SwarmEvent::Behaviour(types::ComposedEvent::GossipsubEvent(
                GossipsubEvent::Message {
                    propagation_source,
                    message_id,
                    message,
                },
            )) => {
                let topic = match message.topic.clone().try_into() {
                    Ok(topic) => topic,
                    Err(e) => {
                        log::warn!("failed to convert topic ({:?}): {}", message.topic, e);
                        return Ok(());
                    }
                };

                let message = match message::Message::decode(&mut &message.data[..]) {
                    Ok(data) => data,
                    Err(e) => {
                        log::warn!("failed to decode gossipsub message: {:?}", e);
                        return Ok(());
                    }
                };

                log::trace!(
                    "message ({:#?}) received from gossipsub topic {:?}",
                    message,
                    topic
                );

                self.gossip_tx
                    .send(types::PubSubEvent::MessageReceived {
                        peer_id: propagation_source,
                        topic,
                        message,
                        message_id,
                    })
                    .await
                    .map_err(|_| P2pError::ChannelClosed)
            }
            // TODO: implement the ping protocol as specified in the spec
            SwarmEvent::Behaviour(types::ComposedEvent::PingEvent(ping::Event {
                peer,
                result: Result::Ok(ping::Success::Ping { rtt }),
            })) => {
                // println!(
                //     "ping: rtt to {} is {} ms",
                //     peer.to_base58(),
                //     rtt.as_millis()
                // );
                Ok(())
            }
            SwarmEvent::Behaviour(types::ComposedEvent::PingEvent(ping::Event {
                peer,
                result: Result::Ok(ping::Success::Pong),
            })) => {
                // println!("ping: pong from {}", peer.to_base58());
                Ok(())
            }
            SwarmEvent::Behaviour(types::ComposedEvent::PingEvent(ping::Event {
                peer,
                result: Result::Err(ping::Failure::Timeout),
            })) => {
                // println!("ping: timeout to {}", peer.to_base58());
                Ok(())
            }
            SwarmEvent::Behaviour(types::ComposedEvent::PingEvent(ping::Event {
                peer,
                result: Result::Err(ping::Failure::Unsupported),
            })) => {
                // println!("ping: {} does not support ping protocol", peer.to_base58());
                Ok(())
            }
            SwarmEvent::Behaviour(types::ComposedEvent::PingEvent(ping::Event {
                peer,
                result: Result::Err(ping::Failure::Other { error }),
            })) => {
                // println!("ping: ping::Failure with {}: {}", peer.to_base58(), error);
                Ok(())
            }
            SwarmEvent::Behaviour(types::ComposedEvent::IdentifyEvent(
                IdentifyEvent::Received { peer_id, info },
            )) => match self.pending.remove(&peer_id) {
                None => {
                    log::error!("pending connection for peer {:?} does not exist", peer_id);
                    Ok(())
                }
                Some(PendingState::Dialed { tx }) => {
                    log::error!("received peer info before connection was established");
                    Ok(())
                }
                Some(PendingState::OutboundAccepted { tx }) => {
                    tx.send(Ok(info)).map_err(|_| P2pError::ChannelClosed)
                }
                Some(PendingState::InboundAccepted { addr }) => self
                    .conn_tx
                    .send(types::ConnectivityEvent::ConnectionAccepted {
                        peer_info: Box::new(info),
                    })
                    .await
                    .map_err(|_| P2pError::ChannelClosed),
            },
            SwarmEvent::Behaviour(types::ComposedEvent::IdentifyEvent(IdentifyEvent::Error {
                peer_id,
                error,
            })) => {
                todo!();
            }
            _ => {
                log::warn!("unhandled event {:?}", event);
                Ok(())
            }
        }
    }

    /// Handle command received from the libp2p front-end
    async fn on_command(&mut self, cmd: types::Command) -> error::Result<()> {
        log::debug!("handle incoming command {:?}", cmd);

        match cmd {
            types::Command::Listen { addr, response } => {
                let res = self.swarm.listen_on(addr).map(|_| ()).map_err(|e| e.into());
                response.send(res).map_err(|_| P2pError::ChannelClosed)
            }
            types::Command::Connect {
                peer_id,
                peer_addr,
                response,
            } => match self.swarm.dial(peer_addr) {
                Ok(_) => {
                    self.pending.insert(peer_id, PendingState::Dialed { tx: response });
                    // self.dials.insert(peer_id, response);
                    Ok(())
                }
                Err(e) => Err(e.into()),
            },
            types::Command::OpenStream { peer_id, response } => {
                let stream_id = self.swarm.behaviour_mut().streaming.open_stream(peer_id);
                self.streams.insert(stream_id, response);
                Ok(())
            }
            // TODO: rename this
            types::Command::SendMessage {
                topic,
                message,
                response,
            } => {
                log::trace!("publish message on gossipsub topic {:?}", topic);

                let res = self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish((&topic).into(), message)
                    .map(|_| ())
                    .map_err(|e| e.into());
                response.send(res).map_err(|_| P2pError::ChannelClosed)
            }
            // TODO: rename
            types::Command::ReportValidationResult {
                message_id,
                source,
                result,
                response,
            } => {
                log::debug!(
                    "report gossipsub message validation result: {:?} {:?} {:?}",
                    message_id,
                    source,
                    result
                );
                self.swarm.behaviour_mut().gossipsub.report_message_validation_result(
                    &message_id,
                    &source,
                    result,
                );

                // TODO: fix this
                response.send(Ok(())).map_err(|_| P2pError::ChannelClosed)
            }
        }
    }
}

/*
#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::{
        core::upgrade,
        gossipsub::GossipsubConfigBuilder,
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
    async fn make_swarm() -> Swarm<types::ComposedBehaviour> {
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

        let gossipsub_config = GossipsubConfigBuilder::default()
            .validate_messages()
            .build()
            .expect("configuration to be valid");

        let gossipsub: Gossipsub =
            Gossipsub::new(MessageAuthenticity::Signed(id_keys), gossipsub_config)
                .expect("configuration to be valid");
        let behaviour = types::ComposedBehaviour {
            streaming: Streaming::<IdentityCodec>::default(),
            mdns: Mdns::new(Default::default()).await.unwrap(),
            ping: ping::Behaviour::new(ping::Config::new()),
            gossipsub,
        };

        SwarmBuilder::new(transport, behaviour, peer_id).build()
    }

    // verify that binding to a free network interface succeeds
    #[tokio::test]
    async fn test_command_listen_success() {
        let swarm = make_swarm().await;
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (gossip_tx, _) = mpsc::channel(64);
        let (conn_tx, _) = mpsc::channel(64);
        let mut backend = Backend::new(swarm, cmd_rx, conn_tx, gossip_tx, false);

        tokio::spawn(async move { backend.run().await });

        let (tx, rx) = oneshot::channel();
        let res = cmd_tx
            .send(types::Command::Listen {
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
        let (gossip_tx, _) = mpsc::channel(64);
        let (conn_tx, _) = mpsc::channel(64);
        let mut backend = Backend::new(swarm, cmd_rx, conn_tx, gossip_tx, false);

        tokio::spawn(async move { backend.run().await });

        // start listening to [::1]:8890
        let (tx, rx) = oneshot::channel();
        let res = cmd_tx
            .send(types::Command::Listen {
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
            .send(types::Command::Listen {
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
        let (gossip_tx, _) = mpsc::channel(64);
        let (conn_tx, _) = mpsc::channel(64);
        let mut backend = Backend::new(swarm, cmd_rx, conn_tx, gossip_tx, false);

        drop(cmd_tx);
        assert_eq!(backend.run().await, Err(P2pError::ChannelClosed));
    }
}
*/
