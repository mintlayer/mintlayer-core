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
    error::{self, Libp2pError, P2pError},
    net::{Event, GossipSubTopic, NetworkService, SocketService},
};
use async_trait::async_trait;
use futures::prelude::*;
use libp2p::{
    core::{upgrade, PeerId},
    identity, mplex,
    multiaddr::Protocol,
    noise,
    streaming::{IdentityCodec, StreamHandle, Streaming},
    swarm::{NegotiatedSubstream, SwarmBuilder},
    tcp::TcpConfig,
    Multiaddr, Transport,
};
use parity_scale_codec::{Decode, Encode};
use tokio::sync::{
    mpsc::{Receiver, Sender},
    oneshot,
};

mod backend;
mod common;

#[derive(Debug)]
pub enum LibP2pStrategy {}

#[derive(Debug)]
pub struct Libp2pService {
    /// Multiaddress of the local peer
    pub addr: Multiaddr,

    /// TX channel for sending commands to libp2p backend
    cmd_tx: Sender<common::Command>,

    /// RX channel for receiving events from libp2p backend
    event_rx: Receiver<common::Event>,
}

#[derive(Debug)]
#[allow(unused)]
pub struct Libp2pSocket {
    /// Multiaddress of the remote peer
    addr: Multiaddr,

    /// Stream handle for the remote peer
    stream: StreamHandle<NegotiatedSubstream>,
}

#[async_trait]
impl NetworkService for Libp2pService {
    type Address = Multiaddr;
    type Socket = Libp2pSocket;
    type Strategy = LibP2pStrategy;

    async fn new(
        addr: Self::Address,
        _strategies: &[Self::Strategy],
        _topics: &[GossipSubTopic],
    ) -> error::Result<Self> {
        let id_keys = identity::Keypair::generate_ed25519();
        let peer_id = id_keys.public().to_peer_id();
        let noise_keys = noise::Keypair::<noise::X25519Spec>::new().into_authentic(&id_keys)?;

        let transport = TcpConfig::new()
            .nodelay(true)
            .port_reuse(true)
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
            backend.run().await
        });

        // send listen command to the libp2p backend and if it succeeds,
        // create a multiaddress for local peer and return the Libp2pService object
        let (tx, rx) = oneshot::channel();
        cmd_tx
            .send(common::Command::Listen {
                addr: addr.clone(),
                response: tx,
            })
            .await?;
        rx.await?.map_err(|_| P2pError::SocketError(std::io::ErrorKind::AddrInUse))?;

        Ok(Self {
            addr: addr.with(Protocol::P2p(peer_id.into())),
            cmd_tx,
            event_rx,
        })
    }

    async fn connect(&mut self, addr: Self::Address) -> error::Result<Self::Socket> {
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

        // dial the remote peer
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(common::Command::Dial {
                peer_id,
                peer_addr: addr.clone(),
                response: tx,
            })
            .await?;

        // wait for command response
        rx.await
            .map_err(|e| e)? // channel closed
            .map_err(|e| e)?; // command failure

        // if dial succeeded, open a generic stream
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(common::Command::OpenStream {
                peer_id,
                response: tx,
            })
            .await?;

        let stream = rx
            .await
            .map_err(|e| e)? // channel closed
            .map_err(|e| e)?; // command failure

        Ok(Libp2pSocket { addr, stream })
    }

    async fn poll_next<T>(&mut self) -> error::Result<Event<T>>
    where
        T: NetworkService<Socket = Libp2pSocket>,
    {
        match self.event_rx.recv().await.ok_or(P2pError::ChannelClosed)? {
            common::Event::ConnectionAccepted { socket } => Ok(Event::IncomingConnection(socket)),
        }
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
    async fn send<T>(&mut self, data: &T) -> error::Result<()>
    where
        T: Sync + Send + Encode,
    {
        let encoded = data.encode();
        let size = (encoded.len() as u32).encode();

        self.stream
            .write_all(&size)
            .await
            .map_err(|e| P2pError::SocketError(e.kind()))?;

        self.stream
            .write_all(&encoded)
            .await
            .map_err(|e| P2pError::SocketError(e.kind()))?;

        self.stream.flush().await.map_err(|e| P2pError::SocketError(e.kind()))
    }

    async fn recv<T>(&mut self) -> error::Result<T>
    where
        T: Decode,
    {
        todo!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net;

    #[derive(Debug, Encode, Decode, PartialEq, Eq)]
    struct Transaction {
        hash: u64,
        value: u128,
    }

    #[tokio::test]
    async fn test_connect_new() {
        let service = Libp2pService::new("/ip6/::1/tcp/8900".parse().unwrap(), &[], &[]).await;
        assert!(service.is_ok());
    }

    // verify that binding to the same interface twice is not possible
    #[ignore]
    #[tokio::test]
    async fn test_connect_new_addrinuse() {
        let service = Libp2pService::new("/ip6/::1/tcp/8901".parse().unwrap(), &[], &[]).await;
        assert!(service.is_ok());

        let service = Libp2pService::new("/ip6/::1/tcp/8901".parse().unwrap(), &[], &[]).await;

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
        let service1 = Libp2pService::new("/ip6/::1/tcp/8902".parse().unwrap(), &[], &[]).await;
        let service2 = Libp2pService::new("/ip6/::1/tcp/8903".parse().unwrap(), &[], &[]).await;
        assert!(service1.is_ok());
        assert!(service2.is_ok());

        let mut service1 = service1.unwrap();
        let mut service2 = service2.unwrap();
        let conn_addr = service1.addr.clone();

        let (res1, res2): (error::Result<Event<Libp2pService>>, _) =
            tokio::join!(service1.poll_next(), service2.connect(conn_addr));

        assert!(res2.is_ok());
        assert!(res1.is_ok());
    }

    // try to connect to a remote peer with a multiaddress that's missing the peerid
    // and verify that the connection fails
    #[tokio::test]
    async fn test_connect_peer_id_missing() {
        let addr1: Multiaddr = "/ip6/::1/tcp/8904".parse().unwrap();
        let mut service2 = Libp2pService::new("/ip6/::1/tcp/8905".parse().unwrap(), &[], &[])
            .await
            .unwrap();
        match service2.connect(addr1).await {
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

    // connect two libp2p services together and send a transaction from one service
    // to another and verify that the transaction was received successfully and that
    // it decodes to the same transaction that was sent.
    #[tokio::test]
    async fn test_peer_send() {
        let service1 = Libp2pService::new("/ip6/::1/tcp/8905".parse().unwrap(), &[], &[]).await;
        let service2 = Libp2pService::new("/ip6/::1/tcp/8906".parse().unwrap(), &[], &[]).await;

        let mut service1 = service1.unwrap();
        let mut service2 = service2.unwrap();
        let conn_addr = service1.addr.clone();

        let (res1, res2): (error::Result<Event<Libp2pService>>, _) =
            tokio::join!(service1.poll_next(), service2.connect(conn_addr));

        let net::Event::IncomingConnection(mut socket1) = res1.unwrap();
        let mut socket2 = res2.unwrap();

        // try to send data that implements `Encode + Decode`
        // and verify that it was received correctly
        let tx = Transaction {
            hash: u64::MAX,
            value: u128::MAX,
        };
        let encoded_size: u32 = tx.encode().len() as u32;

        let mut buf = vec![0u8; 64];
        let (server_res, peer_res) = tokio::join!(socket2.stream.read(&mut buf), socket1.send(&tx));

        assert!(peer_res.is_ok());
        assert!(server_res.is_ok());

        let received_size: u32 = Decode::decode(&mut &buf[..]).unwrap();
        assert_eq!(received_size, encoded_size);

        buf.resize(received_size as usize, 0);
        socket2.stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(Decode::decode(&mut &buf[..]), Ok(tx));
    }
}
