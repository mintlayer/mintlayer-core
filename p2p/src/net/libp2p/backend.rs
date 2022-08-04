// Copyright (c) 2021 Protocol Labs
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
//
// Author(s): A. Altonen

//! Libp2p backend service

use crate::{
    error::{P2pError, PeerError},
    net::libp2p::{
        behaviour,
        types::{self, ControlEvent, Libp2pBehaviourEvent},
    },
};
use futures::StreamExt;
use libp2p::{
    swarm::{Swarm, SwarmEvent},
    Multiaddr,
};
use logging::log;
use tokio::sync::mpsc;

pub struct Backend {
    /// Created libp2p swarm object
    pub(super) swarm: Swarm<behaviour::Libp2pBehaviour>,

    /// Receiver for incoming commands
    cmd_rx: mpsc::Receiver<types::Command>,

    /// Sender for outgoing connectivity events
    pub(super) conn_tx: mpsc::Sender<types::ConnectivityEvent>,

    /// Sender for outgoing gossipsub events
    pub(super) gossip_tx: mpsc::Sender<types::PubSubEvent>,

    /// Sender for outgoing syncing events
    pub(super) sync_tx: mpsc::Sender<types::SyncingEvent>,

    /// Active listen address of the backend
    listen_addr: Option<Multiaddr>,
}

impl Backend {
    pub fn new(
        swarm: Swarm<behaviour::Libp2pBehaviour>,
        cmd_rx: mpsc::Receiver<types::Command>,
        conn_tx: mpsc::Sender<types::ConnectivityEvent>,
        gossip_tx: mpsc::Sender<types::PubSubEvent>,
        sync_tx: mpsc::Sender<types::SyncingEvent>,
    ) -> Self {
        Self {
            swarm,
            cmd_rx,
            conn_tx,
            gossip_tx,
            sync_tx,
            listen_addr: None,
        }
    }

    pub async fn run(&mut self) -> crate::Result<void::Void> {
        log::debug!("starting event loop");

        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        let peer_id = *self.swarm.local_peer_id();
                        self.listen_addr = Some(address.with(libp2p::multiaddr::Protocol::P2p(peer_id.into())));
                    }
                    SwarmEvent::BannedPeer { peer_id, endpoint: _ } => {
                        self.swarm.behaviour_mut().connmgr.handle_banned_peer(peer_id);
                    }
                    SwarmEvent::Behaviour(Libp2pBehaviourEvent::Connectivity(event)) => {
                        self.conn_tx.send(event).await.map_err(P2pError::from)?;
                    }
                    SwarmEvent::Behaviour(Libp2pBehaviourEvent::Syncing(event)) => {
                        self.sync_tx.send(event).await.map_err(P2pError::from)?;
                    }
                    SwarmEvent::Behaviour(Libp2pBehaviourEvent::PubSub(event)) => {
                        self.gossip_tx.send(event).await.map_err(P2pError::from)?;
                    }
                    SwarmEvent::Behaviour(Libp2pBehaviourEvent::Control(
                        ControlEvent::CloseConnection { peer_id })
                    ) => {
                        match self.swarm.disconnect_peer_id(peer_id) {
                            Ok(_) => {}
                            Err(err) => {
                                log::error!("Failed to disconnect peer {}: {:?}", peer_id, err);
                            }
                        }
                    }
                    _ => {
                        log::debug!("unhandled event {:?}", event);
                    }
                },
                command = self.cmd_rx.recv() => match command {
                    Some(cmd) => self.on_command(cmd).await?,
                    None => return Err(P2pError::ChannelClosed),
                },
            }
        }
    }

    // TODO: design p2p global command system
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
            } => match self.swarm.dial(peer_addr.clone()) {
                Ok(_) => {
                    self.swarm.behaviour_mut().connmgr.dialing(peer_id, peer_addr);
                    response.send(Ok(())).map_err(|_| P2pError::ChannelClosed)
                }
                Err(err) => response.send(Err(err.into())).map_err(|_| P2pError::ChannelClosed),
            },
            types::Command::Disconnect { peer_id, response } => {
                log::debug!("disconnect peer {:?}", peer_id);

                if !self.swarm.is_connected(&peer_id) {
                    return response
                        .send(Err(P2pError::PeerError(PeerError::PeerDoesntExist)))
                        .map_err(|_| P2pError::ChannelClosed);
                }

                match self.swarm.disconnect_peer_id(peer_id) {
                    Ok(_) => response.send(Ok(())).map_err(|_| P2pError::ChannelClosed),
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
                // TODO: better API for requests/responses + extensibility
            } => match self.swarm.behaviour_mut().pending_reqs.remove(&request_id) {
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
            types::Command::Subscribe { topics, response } => {
                for topic in topics {
                    if let Err(err) = self.swarm.behaviour_mut().gossipsub.subscribe(&topic) {
                        return response.send(Err(err.into())).map_err(|_| P2pError::ChannelClosed);
                    }
                }

                response.send(Ok(())).map_err(|_| P2pError::ChannelClosed)
            }
            types::Command::ListenAddress { response } => {
                response.send(self.listen_addr.clone()).map_err(|_| P2pError::ChannelClosed)
            }
            types::Command::BanPeer { peer_id, response } => {
                self.swarm.ban_peer_id(peer_id);
                response.send(Ok(())).map_err(|_| P2pError::ChannelClosed)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::libp2p::{
        behaviour, connectivity, discovery,
        sync::{SyncingCodec, SyncingProtocol},
    };
    use libp2p::{
        core::upgrade,
        gossipsub::{Gossipsub, GossipsubConfigBuilder, MessageAuthenticity},
        identify::{Identify, IdentifyConfig},
        identity, mplex, noise, ping,
        request_response::{ProtocolSupport, RequestResponse, RequestResponseConfig},
        swarm::SwarmBuilder,
        tcp::TcpConfig,
        Transport,
    };
    use std::{
        collections::{HashMap, VecDeque},
        iter,
    };
    use tokio::sync::oneshot;

    // create a swarm object which is the top-level object of libp2p
    //
    // it contains the selected transport for the swarm (in this case TCP + Noise)
    // and any custom network behaviour such as streaming or mDNS support
    async fn make_swarm() -> Swarm<behaviour::Libp2pBehaviour> {
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

        let protocols = iter::once((SyncingProtocol(), ProtocolSupport::Full));
        let cfg = RequestResponseConfig::default();
        let sync = RequestResponse::new(SyncingCodec(), protocols, cfg);

        let behaviour = behaviour::Libp2pBehaviour {
            ping: ping::Behaviour::new(ping::Config::new()),
            gossipsub,
            identify,
            sync,
            connmgr: connectivity::ConnectionManager::new(),
            discovery: discovery::DiscoveryManager::new(Default::default()).await,
            events: VecDeque::new(),
            pending_reqs: HashMap::new(),
            waker: None,
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
        let mut backend = Backend::new(swarm, cmd_rx, conn_tx, gossip_tx, sync_tx);

        tokio::spawn(async move { backend.run().await });

        let (tx, rx) = oneshot::channel();
        let res = cmd_tx
            .send(types::Command::Listen {
                addr: p2p_test_utils::make_libp2p_addr(),
                response: tx,
            })
            .await;
        assert!(res.is_ok());

        let res = rx.await;
        assert!(res.is_ok());
        assert!(res.unwrap().is_ok());
    }

    // verify that binding twice to the same network interface fails
    #[ignore]
    #[tokio::test]
    async fn test_command_listen_addrinuse() {
        let swarm = make_swarm().await;
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (gossip_tx, _) = mpsc::channel(64);
        let (conn_tx, _) = mpsc::channel(64);
        let (sync_tx, _) = mpsc::channel(64);
        let mut backend = Backend::new(swarm, cmd_rx, conn_tx, gossip_tx, sync_tx);

        tokio::spawn(async move { backend.run().await });

        let (tx, rx) = oneshot::channel();
        let res = cmd_tx
            .send(types::Command::Listen {
                addr: p2p_test_utils::make_libp2p_addr(),
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
                addr: p2p_test_utils::make_libp2p_addr(),
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
        let (sync_tx, _) = mpsc::channel(64);
        let mut backend = Backend::new(swarm, cmd_rx, conn_tx, gossip_tx, sync_tx);

        drop(cmd_tx);
        assert_eq!(backend.run().await, Err(P2pError::ChannelClosed));
    }
}
