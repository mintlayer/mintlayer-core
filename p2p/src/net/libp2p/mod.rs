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
use crate::{
    error,
    net::{Event, GossipSubTopic, NetworkService, SocketService},
};
use async_trait::async_trait;
use libp2p::{
    core::{upgrade, PeerId},
    identity, mplex, noise,
    streaming::{IdentityCodec, StreamHandle, Streaming},
    swarm::{NegotiatedSubstream, SwarmBuilder},
    tcp::TcpConfig,
    Multiaddr, Transport,
};
use parity_scale_codec::{Decode, Encode};
use tokio::sync::mpsc::{Receiver, Sender};

pub mod backend;
pub mod common;

#[derive(Debug)]
pub enum LibP2pStrategy {}

#[derive(Debug)]
pub struct Libp2pService {
    _peer_id: PeerId,
    _cmd_tx: Sender<common::Command>,
    _event_rx: Receiver<common::Event>,
}

#[derive(Debug)]
pub struct Libp2pSocket {
    pub peer: Multiaddr,
    pub socket: StreamHandle<NegotiatedSubstream>,
}

#[async_trait]
impl NetworkService for Libp2pService {
    type Address = Multiaddr;
    type Socket = Libp2pSocket;
    type Strategy = LibP2pStrategy;

    async fn new(
        _addr: Self::Address,
        _strategies: &[Self::Strategy],
        _topics: &[GossipSubTopic],
    ) -> error::Result<Self> {
        let id_keys = identity::Keypair::generate_ed25519();
        let peer_id = id_keys.public().to_peer_id();
        let noise_keys = noise::Keypair::<noise::X25519Spec>::new().into_authentic(&id_keys)?;

        let transport = TcpConfig::new()
            .nodelay(true)
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
            .multiplex(mplex::MplexConfig::new())
            .boxed();

        let swarm = SwarmBuilder::new(
            transport,
            common::ComposedBehaviour {
                streaming: Streaming::<IdentityCodec>::default(),
            },
            peer_id,
        )
        .build();

        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(16);
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);

        // run the libp2p backend in a background task
        tokio::spawn(async move {
            let mut backend = backend::Backend::new(swarm, cmd_rx, event_tx);
            backend.run().await;
        });

        // TODO: start listening to `_addr` when command support is added

        Ok(Self {
            _peer_id: peer_id,
            _cmd_tx: cmd_tx,
            _event_rx: event_rx,
        })
    }

    async fn connect(&mut self, _addr: Self::Address) -> error::Result<Self::Socket> {
        todo!();
    }

    async fn poll_next<T>(&mut self) -> error::Result<Event<T>>
    where
        T: NetworkService,
    {
        todo!();
    }

    async fn publish<T>(&mut self, _topic: GossipSubTopic, _data: &T)
    where
        T: Sync + Send + Encode,
    {
        todo!();
    }
}

#[async_trait]
impl SocketService for Libp2pSocket {
    async fn send<T>(&mut self, _data: &T) -> error::Result<()>
    where
        T: Sync + Send + Encode,
    {
        todo!();
    }

    async fn recv<T>(&mut self) -> error::Result<T>
    where
        T: Decode,
    {
        todo!();
    }
}
