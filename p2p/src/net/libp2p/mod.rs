// Copyright (c) 2018 Parity Technologies (UK) Ltd.
// Copyright (c) 2021 Protocol Labs
// Copyright (c) 2021-2022 RBB S.r.l
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

use crate::{
    config,
    error::{DialError, P2pError},
    net::{libp2p::backend::Libp2pBackend, NetworkingService},
};
use async_trait::async_trait;
use libp2p::{
    core::{upgrade, PeerId},
    gossipsub::MessageId,
    identity, mplex,
    noise::{self, AuthenticKeypair},
    request_response::*,
    swarm::SwarmBuilder,
    tcp::TcpConfig,
    Multiaddr, Transport,
};
use logging::log;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

mod backend;
pub mod behaviour;
mod constants;
pub mod service;
mod tests;
mod types;

#[derive(Debug)]
pub struct Libp2pService;

// TODO: Check the data directory first, and use keys from there if available
fn make_libp2p_keys() -> (
    PeerId,
    identity::Keypair,
    AuthenticKeypair<noise::X25519Spec>,
) {
    let id_keys = identity::Keypair::generate_ed25519();
    let peer_id = id_keys.public().to_peer_id();
    let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(&id_keys)
        .expect("Noise key creation to succeed");

    (peer_id, id_keys, noise_keys)
}

#[async_trait]
impl NetworkingService for Libp2pService {
    type Address = Multiaddr;
    type PeerId = PeerId;
    type ProtocolId = String;
    type SyncingPeerRequestId = RequestId;
    type PubSubMessageId = MessageId;
    type ConnectivityHandle = service::connectivity::Libp2pConnectivityHandle<Self>;
    type PubSubHandle = service::pubsub::Libp2pPubSubHandle<Self>;
    type SyncingMessagingHandle = service::syncing::Libp2pSyncHandle<Self>;

    async fn start(
        bind_addr: Self::Address,
        chain_config: Arc<common::chain::ChainConfig>,
        p2p_config: Arc<config::P2pConfig>,
    ) -> crate::Result<(
        Self::ConnectivityHandle,
        Self::PubSubHandle,
        Self::SyncingMessagingHandle,
    )> {
        let (peer_id, id_keys, noise_keys) = make_libp2p_keys();
        let transport = TcpConfig::new()
            .nodelay(true)
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
            .multiplex(mplex::MplexConfig::new())
            .outbound_timeout(std::time::Duration::from_secs(
                p2p_config.outbound_connection_timeout,
            ))
            .boxed();

        let swarm = SwarmBuilder::new(
            transport,
            behaviour::Libp2pBehaviour::new(
                Arc::clone(&chain_config),
                Arc::clone(&p2p_config),
                id_keys,
            )
            .await,
            peer_id,
        )
        .build();

        // TODO: unbounded
        let (cmd_tx, cmd_rx) = mpsc::channel(constants::CHANNEL_SIZE);
        let (gossip_tx, gossip_rx) = mpsc::channel(constants::CHANNEL_SIZE);
        let (conn_tx, conn_rx) = mpsc::channel(constants::CHANNEL_SIZE);
        let (sync_tx, sync_rx) = mpsc::channel(constants::CHANNEL_SIZE);

        // run the libp2p backend in a background task
        tokio::spawn(async move {
            log::debug!("spawning libp2p backend to background");

            Libp2pBackend::new(swarm, cmd_rx, conn_tx, gossip_tx, sync_tx).run().await
        });

        // send listen command to the libp2p backend and if it succeeds,
        // create a multiaddress for local peer and return the Libp2pService object
        let (tx, rx) = oneshot::channel();
        cmd_tx
            .send(types::Command::Listen {
                addr: bind_addr.clone(),
                response: tx,
            })
            .await?;
        rx.await?
            .map_err(|_| P2pError::DialError(DialError::IoError(std::io::ErrorKind::AddrInUse)))?;

        Ok((
            Self::ConnectivityHandle::new(peer_id, cmd_tx.clone(), conn_rx),
            Self::PubSubHandle::new(cmd_tx.clone(), gossip_rx),
            Self::SyncingMessagingHandle::new(cmd_tx, sync_rx),
        ))
    }
}
