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
    error::{self, P2pError},
    message,
    net::{self, libp2p::behaviour, libp2p::common},
};
use futures::StreamExt;
use libp2p::{
    core::{connection::ConnectedPoint, either::EitherError},
    gossipsub::{error::GossipsubHandlerError, GossipsubEvent},
    mdns::MdnsEvent,
    streaming::{OutboundStreamId, StreamHandle, StreamingEvent},
    swarm::{NegotiatedSubstream, ProtocolsHandlerUpgrErr, Swarm, SwarmEvent},
    Multiaddr, PeerId,
};
use logging::log;
use parity_scale_codec::Decode;
use std::collections::HashMap;
use tokio::sync::{
    mpsc::{Receiver, Sender},
    oneshot,
};

pub struct Backend {
    /// Created libp2p swarm object
    swarm: Swarm<behaviour::ComposedBehaviour>,

    /// Receiver for incoming commands
    cmd_rx: Receiver<common::Command>,

    /// Sender for outgoing events (peers, pubsub messages)
    event_tx: Sender<common::Event>,

    /// Hashmap of pending outbound connections
    dials: HashMap<PeerId, oneshot::Sender<error::Result<()>>>,

    /// Hashmap of pending inbound connections
    conns: HashMap<PeerId, Multiaddr>,

    /// Hashmap of pending outbound streams
    streams: HashMap<
        OutboundStreamId,
        oneshot::Sender<error::Result<StreamHandle<NegotiatedSubstream>>>,
    >,

    /// Whether mDNS peer events should be relayed to P2P manager
    relay_mdns: bool,
}

impl Backend {
    pub fn new(
        swarm: Swarm<behaviour::ComposedBehaviour>,
        cmd_rx: Receiver<common::Command>,
        event_tx: Sender<common::Event>,
        relay_mdns: bool,
    ) -> Self {
        Self {
            swarm,
            cmd_rx,
            event_tx,
            dials: HashMap::new(),
            conns: HashMap::new(),
            streams: HashMap::new(),
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
        event_fn: impl FnOnce(Vec<(PeerId, Multiaddr)>) -> common::Event,
    ) -> error::Result<()> {
        if !self.relay_mdns || peers.is_empty() {
            return Ok(());
        }

        self.event_tx.send(event_fn(peers)).await.map_err(|_| P2pError::ChannelClosed)
    }

    /// Handle event received from the swarm object
    async fn on_event(
        &mut self,
        event: SwarmEvent<
            behaviour::ComposedEvent,
            EitherError<
                EitherError<ProtocolsHandlerUpgrErr<std::convert::Infallible>, void::Void>,
                GossipsubHandlerError,
            >,
        >,
    ) -> error::Result<()> {
        match event {
            SwarmEvent::Behaviour(behaviour::ComposedEvent::StreamingEvent(
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
            SwarmEvent::Behaviour(behaviour::ComposedEvent::StreamingEvent(
                StreamingEvent::NewIncoming {
                    peer_id, stream, ..
                },
            )) => {
                log::trace!("incoming stream, peer id {:?}", peer_id);

                let addr = self.conns.remove(&peer_id).ok_or_else(|| {
                    P2pError::Unknown("Pending connection does not exist".to_string())
                })?;
                self.event_tx
                    .send(common::Event::ConnectionAccepted {
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
            SwarmEvent::Behaviour(behaviour::ComposedEvent::MdnsEvent(MdnsEvent::Discovered(
                peers,
            ))) => {
                self.send_discovery_event(peers.collect(), |peers| common::Event::PeerDiscovered {
                    peers,
                })
                .await
            }
            SwarmEvent::Behaviour(behaviour::ComposedEvent::MdnsEvent(MdnsEvent::Expired(
                expired,
            ))) => {
                self.send_discovery_event(expired.collect(), |peers| common::Event::PeerExpired {
                    peers,
                })
                .await
            }
            SwarmEvent::Behaviour(behaviour::ComposedEvent::GossipsubEvent(
                GossipsubEvent::Message {
                    propagation_source: _,
                    message_id: _,
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

                self.event_tx
                    .send(common::Event::MessageReceived { topic, message })
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::{
        core::upgrade,
        gossipsub::{self, MessageAuthenticity, ValidationMode},
        identity,
        mdns::Mdns,
        mplex, noise,
        streaming::{IdentityCodec, Streaming},
        swarm::SwarmBuilder,
        tcp::TcpConfig,
        Transport,
    };
    use std::time::Duration;
    use tokio::sync::oneshot;

    // create a swarm object which is the top-level object of libp2p
    //
    // it contains the selected transport for the swarm (in this case TCP + Noise)
    // and any custom network behaviour such as streaming or mDNS support
    async fn make_swarm() -> Swarm<behaviour::ComposedBehaviour> {
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

        let gossipsub_config = gossipsub::GossipsubConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(10))
            .validation_mode(ValidationMode::Strict)
            .build()
            .unwrap();

        let gossipsub: gossipsub::Gossipsub =
            gossipsub::Gossipsub::new(MessageAuthenticity::Signed(id_keys), gossipsub_config)
                .unwrap();

        SwarmBuilder::new(
            transport,
            behaviour::ComposedBehaviour {
                streaming: Streaming::<IdentityCodec>::default(),
                mdns: Mdns::new(Default::default()).await.unwrap(),
                gossipsub,
            },
            peer_id,
        )
        .build()
    }

    // verify that binding to a free network interface succeeds
    #[tokio::test]
    async fn test_command_listen_success() {
        let swarm = make_swarm().await;
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(16);
        let (event_tx, _) = tokio::sync::mpsc::channel(16);
        let mut backend = Backend::new(swarm, cmd_rx, event_tx, false);

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
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(16);
        let (event_tx, _) = tokio::sync::mpsc::channel(16);
        let mut backend = Backend::new(swarm, cmd_rx, event_tx, false);

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
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(16);
        let (event_tx, _) = tokio::sync::mpsc::channel(16);
        let mut backend = Backend::new(swarm, cmd_rx, event_tx, false);

        drop(cmd_tx);
        assert_eq!(backend.run().await, Err(P2pError::ChannelClosed));
    }
}
