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

// TODO: think about connection management

use crate::{
    error::{P2pError, PeerError},
    net::libp2p::{types, SyncResponse},
};
use futures::StreamExt;
use libp2p::{
    core::either::EitherError,
    gossipsub::error::GossipsubHandlerError,
    identify::IdentifyInfo,
    ping,
    request_response::*,
    swarm::{ConnectionHandlerUpgrErr, Swarm, SwarmEvent},
    Multiaddr, PeerId,
};
use logging::log;
use std::collections::{HashMap, HashSet};
use tokio::sync::{mpsc, oneshot};

#[derive(Debug)]
pub(super) enum PendingState {
    /// Outbound connection has been dialed, wait for `ConnectionEstablished` event
    Dialed {
        tx: oneshot::Sender<crate::Result<IdentifyInfo>>,
    },

    /// Connection established for outbound connection
    OutboundAccepted {
        tx: oneshot::Sender<crate::Result<IdentifyInfo>>,
    },

    /// Connection established for inbound connection
    InboundAccepted { addr: Multiaddr },
}

pub struct Backend {
    /// Created libp2p swarm object
    pub(super) swarm: Swarm<types::ComposedBehaviour>,

    /// Receiver for incoming commands
    cmd_rx: mpsc::Receiver<types::Command>,

    /// Sender for outgoing connectivity events
    pub(super) conn_tx: mpsc::Sender<types::ConnectivityEvent>,

    /// Sender for outgoing gossipsub events
    pub(super) gossip_tx: mpsc::Sender<types::PubSubEvent>,

    /// Sender for outgoing syncing events
    pub(super) sync_tx: mpsc::Sender<types::SyncingEvent>,

    /// Set of pending connections
    pub(super) pending_conns: HashMap<PeerId, PendingState>,

    /// Set of established connections
    pub(super) established_conns: HashSet<PeerId>,

    /// Set of pending requests
    pub(super) pending_reqs: HashMap<RequestId, ResponseChannel<SyncResponse>>,

    /// Whether mDNS peer events should be relayed to P2P manager
    pub(super) relay_mdns: bool,
}

impl Backend {
    pub fn new(
        swarm: Swarm<types::ComposedBehaviour>,
        cmd_rx: mpsc::Receiver<types::Command>,
        conn_tx: mpsc::Sender<types::ConnectivityEvent>,
        gossip_tx: mpsc::Sender<types::PubSubEvent>,
        sync_tx: mpsc::Sender<types::SyncingEvent>,
        relay_mdns: bool,
    ) -> Self {
        Self {
            swarm,
            cmd_rx,
            conn_tx,
            gossip_tx,
            sync_tx,
            pending_conns: HashMap::new(),
            established_conns: HashSet::new(),
            pending_reqs: HashMap::new(),
            relay_mdns,
        }
    }

    // TODO: into_fatal()???
    pub async fn run(&mut self) -> crate::Result<()> {
        log::debug!("starting event loop");

        loop {
            tokio::select! {
                event = self.swarm.next() => match event {
                    Some(event) => match self.on_event(event).await {
                        Ok(_) => {}
                        Err(P2pError::ChannelClosed) => return Err(P2pError::ChannelClosed),
                        Err(e) => {
                            log::error!("error occurred when processing the event: {:?}", e);
                        }
                    }
                    None => return Err(P2pError::ChannelClosed)
                },
                command = self.cmd_rx.recv() => match command {
                    Some(cmd) => self.on_command(cmd).await?,
                    None => return Err(P2pError::ChannelClosed),
                },
            }
        }
    }

    /// Handle event received from the swarm object
    #[allow(clippy::type_complexity)]
    async fn on_event(
        &mut self,
        event: SwarmEvent<
            types::ComposedEvent,
            EitherError<
                EitherError<
                    EitherError<EitherError<void::Void, GossipsubHandlerError>, ping::Failure>,
                    std::io::Error,
                >,
                ConnectionHandlerUpgrErr<std::io::Error>,
            >,
        >,
    ) -> crate::Result<()> {
        match event {
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => self.on_connection_established(peer_id, endpoint).await,
            SwarmEvent::OutgoingConnectionError { peer_id, error } => {
                self.on_outgoing_connection_error(peer_id, error).await
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                self.on_connection_closed(peer_id).await
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                log::trace!("new listen address {:?}", address);
                Ok(())
            }
            SwarmEvent::Behaviour(types::ComposedEvent::MdnsEvent(event)) => {
                self.on_mdns_event(event).await
            }
            SwarmEvent::Behaviour(types::ComposedEvent::GossipsubEvent(event)) => {
                self.on_gossipsub_event(event).await
            }
            SwarmEvent::Behaviour(types::ComposedEvent::PingEvent(event)) => {
                self.on_ping_event(event).await
            }
            SwarmEvent::Behaviour(types::ComposedEvent::IdentifyEvent(event)) => {
                self.on_identify_event(event).await
            }
            SwarmEvent::Behaviour(types::ComposedEvent::SyncingEvent(event)) => {
                self.on_sync_event(event).await
            }
            _ => {
                log::warn!("unhandled event {:?}", event);
                Ok(())
            }
        }
    }

    // TODO: into separate handlers?
    // TODO: there has to be a better way to add new commands?
    /// Handle command received from the libp2p front-end
    async fn on_command(&mut self, cmd: types::Command) -> crate::Result<()> {
        log::debug!("handle incoming command {:?}", cmd);

        match cmd {
            types::Command::Listen { addr, response } => {
                let res = self
                    .swarm
                    .listen_on(addr)
                    .map(|_| ())
                    .map_err(|_| P2pError::Other("Failed to bind to address"));
                response.send(res).map_err(|_| P2pError::ChannelClosed)
            }
            types::Command::Connect {
                peer_id,
                peer_addr,
                response,
            } => match self.swarm.dial(peer_addr) {
                Ok(_) => {
                    self.pending_conns.insert(peer_id, PendingState::Dialed { tx: response });
                    Ok(())
                }
                Err(e) => Err(e.into()),
            },
            types::Command::Disconnect { peer_id, response } => {
                log::debug!("disconnect peer {:?}", peer_id);

                if !self.swarm.is_connected(&peer_id) {
                    log::debug!("peer {:?} is not connected", peer_id);
                    return response
                        .send(Err(P2pError::PeerError(PeerError::PeerDoesntExist)))
                        .map_err(|_| P2pError::ChannelClosed);
                }

                match self.swarm.disconnect_peer_id(peer_id) {
                    Ok(_) => {
                        log::trace!("peer {:?} disconnected", peer_id);
                        self.established_conns.remove(&peer_id);
                        response.send(Ok(())).map_err(|_| P2pError::ChannelClosed)
                    }
                    Err(_) => response
                        .send(Err(P2pError::Other("`Swarm::disconnect_peer_id()` failed")))
                        .map_err(|_| P2pError::ChannelClosed),
                }
            }
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
                match self.swarm.behaviour_mut().gossipsub.report_message_validation_result(
                    &message_id,
                    &source,
                    result,
                ) {
                    Ok(_) => response.send(Ok(())).map_err(|_| P2pError::ChannelClosed),
                    Err(e) => response.send(Err(e.into())).map_err(|_| P2pError::ChannelClosed),
                }
            }
            types::Command::SendRequest {
                peer_id,
                request,
                response,
            } => response
                .send(Ok(self
                    .swarm
                    .behaviour_mut()
                    .sync
                    .send_request(&peer_id, *request)))
                .map_err(|_| P2pError::ChannelClosed),
            types::Command::SendResponse {
                request_id,
                response,
                channel,
            } => match self.pending_reqs.remove(&request_id) {
                None => {
                    log::error!("pending request ({:?}) doesn't exist", request_id);
                    channel.send(Err(P2pError::ChannelClosed)).map_err(|_| P2pError::ChannelClosed)
                }
                Some(response_channel) => {
                    let res = self
                        .swarm
                        .behaviour_mut()
                        .sync
                        .send_response(response_channel, *response)
                        .map(|_| ())
                        .map_err(|_| P2pError::Other("Channel closed or request timed out"));
                    channel.send(res).map_err(|_| P2pError::ChannelClosed)
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::libp2p::{SyncingCodec, SyncingProtocol};
    use libp2p::{
        core::upgrade,
        gossipsub::{Gossipsub, GossipsubConfigBuilder, MessageAuthenticity},
        identify::{Identify, IdentifyConfig},
        identity,
        mdns::Mdns,
        mplex, noise,
        swarm::SwarmBuilder,
        tcp::TcpConfig,
        Transport,
    };
    use std::iter;
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

        let gossipsub: Gossipsub = Gossipsub::new(
            MessageAuthenticity::Signed(id_keys.clone()),
            gossipsub_config,
        )
        .expect("configuration to be valid");

        let identify = Identify::new(IdentifyConfig::new(
            "/mintlayer/0.1.0-13371338".into(),
            id_keys.public(),
        ));

        // TODO: configure sync protocol
        let protocols = iter::once((SyncingProtocol(), ProtocolSupport::Full));
        let cfg = RequestResponseConfig::default();
        let sync = RequestResponse::new(SyncingCodec(), protocols, cfg);

        let behaviour = types::ComposedBehaviour {
            mdns: Mdns::new(Default::default()).await.unwrap(),
            ping: ping::Behaviour::new(ping::Config::new()),
            gossipsub,
            identify,
            sync,
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
        let (sync_tx, _) = mpsc::channel(64);
        let mut backend = Backend::new(swarm, cmd_rx, conn_tx, gossip_tx, sync_tx, false);

        tokio::spawn(async move { backend.run().await });

        let (tx, rx) = oneshot::channel();
        let res = cmd_tx
            .send(types::Command::Listen {
                addr: test_utils::make_address("/ip6/::1/tcp/"),
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
        let (sync_tx, _) = mpsc::channel(64);
        let mut backend = Backend::new(swarm, cmd_rx, conn_tx, gossip_tx, sync_tx, false);

        tokio::spawn(async move { backend.run().await });

        let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
        let (tx, rx) = oneshot::channel();
        let res = cmd_tx
            .send(types::Command::Listen {
                addr: addr.clone(),
                response: tx,
            })
            .await;
        assert!(res.is_ok());

        let res = rx.await;
        assert!(res.is_ok());
        assert!(res.unwrap().is_ok());

        // try to bind to the same interface again
        let (tx, rx) = oneshot::channel();
        let res = cmd_tx.send(types::Command::Listen { addr, response: tx }).await;
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
        let (sync_tx, _) = mpsc::channel(64);
        let mut backend = Backend::new(swarm, cmd_rx, conn_tx, gossip_tx, sync_tx, false);

        drop(cmd_tx);
        assert_eq!(backend.run().await, Err(P2pError::ChannelClosed));
    }
}
