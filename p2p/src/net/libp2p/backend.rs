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
    net::libp2p::common,
};
use futures::StreamExt;
use libp2p::{
    streaming::{OutboundStreamId, StreamHandle, StreamingEvent},
    swarm::{NegotiatedSubstream, ProtocolsHandlerUpgrErr, Swarm, SwarmEvent},
    PeerId,
};
use std::collections::HashMap;
use tokio::sync::{
    mpsc::{Receiver, Sender},
    oneshot,
};

pub struct Backend {
    /// Created libp2p swarm object
    swarm: Swarm<common::ComposedBehaviour>,

    /// Receiver for incoming commands
    cmd_rx: Receiver<common::Command>,

    /// Sender for outgoing events (peers, pubsub messages)
    _event_tx: Sender<common::Event>,

    /// Hashmap of pending outbound connections
    dials: HashMap<PeerId, oneshot::Sender<error::Result<()>>>,

    /// Hashmap of pending outbound streams
    streams: HashMap<
        OutboundStreamId,
        oneshot::Sender<error::Result<StreamHandle<NegotiatedSubstream>>>,
    >,
}

impl Backend {
    pub fn new(
        swarm: Swarm<common::ComposedBehaviour>,
        cmd_rx: Receiver<common::Command>,
        event_tx: Sender<common::Event>,
    ) -> Self {
        Self {
            swarm,
            cmd_rx,
            _event_tx: event_tx,
            dials: HashMap::new(),
            streams: HashMap::new(),
        }
    }

    pub async fn run(&mut self) -> error::Result<()> {
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

    /// Handle event received from the swarm object
    async fn on_event(
        &mut self,
        event: SwarmEvent<common::ComposedEvent, ProtocolsHandlerUpgrErr<std::convert::Infallible>>,
    ) -> error::Result<()> {
        match event {
            SwarmEvent::Behaviour(common::ComposedEvent::StreamingEvent(
                StreamingEvent::StreamOpened {
                    id,
                    peer_id: _,
                    stream,
                },
            )) => self
                .streams
                .remove(&id)
                .ok_or_else(|| P2pError::Unknown("Pending stream does not exist".to_string()))?
                .send(Ok(stream))
                .map_err(|_| P2pError::ChannelClosed),
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                if endpoint.is_dialer() {
                    return self
                        .dials
                        .remove(&peer_id)
                        .ok_or_else(|| {
                            P2pError::Unknown("Pending connection does not exist".to_string())
                        })?
                        .send(Ok(()))
                        .map_err(|_| P2pError::ChannelClosed);
                }

                Ok(())
            }
            _ => {
                println!("libp2p: unhandled event: {:?}", event);
                Ok(())
            }
        }
    }

    /// Handle command received from the libp2p front-end
    async fn on_command(&mut self, cmd: common::Command) -> error::Result<()> {
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::{
        core::upgrade,
        identity, mplex, noise,
        streaming::{IdentityCodec, Streaming},
        swarm::SwarmBuilder,
        tcp::TcpConfig,
        Transport,
    };
    use tokio::sync::oneshot;

    fn make_swarm() -> Swarm<common::ComposedBehaviour> {
        let id_keys = identity::Keypair::generate_ed25519();
        let peer_id = id_keys.public().to_peer_id();
        let noise_keys =
            noise::Keypair::<noise::X25519Spec>::new().into_authentic(&id_keys).unwrap();

        let transport = TcpConfig::new()
            .nodelay(true)
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
            .multiplex(mplex::MplexConfig::new())
            .boxed();

        SwarmBuilder::new(
            transport,
            common::ComposedBehaviour {
                streaming: Streaming::<IdentityCodec>::default(),
            },
            peer_id,
        )
        .build()
    }

    #[tokio::test]
    async fn test_command_listen_success() {
        let swarm = make_swarm();
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(16);
        let (event_tx, _) = tokio::sync::mpsc::channel(16);
        let mut backend = Backend::new(swarm, cmd_rx, event_tx);

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

    #[tokio::test]
    async fn test_command_listen_addrinuse() {
        let swarm = make_swarm();
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(16);
        let (event_tx, _) = tokio::sync::mpsc::channel(16);
        let mut backend = Backend::new(swarm, cmd_rx, event_tx);

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

    #[tokio::test]
    async fn test_drop_command_tx() {
        let swarm = make_swarm();
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(16);
        let (event_tx, _) = tokio::sync::mpsc::channel(16);
        let mut backend = Backend::new(swarm, cmd_rx, event_tx);

        drop(cmd_tx);
        assert_eq!(backend.run().await, Err(P2pError::ChannelClosed));
    }
}
