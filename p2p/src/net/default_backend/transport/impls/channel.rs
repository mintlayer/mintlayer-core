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

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicU32 as StdAtomicU32, Ordering},
        Mutex,
    },
};

use async_trait::async_trait;
use futures::future::BoxFuture;
use once_cell::sync::Lazy;
use p2p_types::socket_address::SocketAddress;
use tokio::{
    io::DuplexStream,
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        oneshot::{self, Sender},
    },
};
use utils::sync::atomic::AtomicU16;

use crate::{
    error::DialError,
    net::default_backend::transport::{PeerStream, TransportListener, TransportSocket},
    P2pError, Result,
};

// How much bytes is allowed for write (without reading on the other side).
const MAX_BUF_SIZE: usize = 10 * 1024 * 1024;

type IncomingConnection = (SocketAddr, Sender<DuplexStream>);

static CONNECTIONS: Lazy<Mutex<BTreeMap<SocketAddr, UnboundedSender<IncomingConnection>>>> =
    Lazy::new(Default::default);

// Note: we can't use utils::sync::atomic::AtomicU32 here, because loom types don't have a const
// constructor function.
static NEXT_IP_ADDRESS: StdAtomicU32 = StdAtomicU32::new(1);

/// Creating a new transport is like adding a new "host" to the network with a new unique IPv4 address.
///
/// Connections work the same way as with TCP:
/// - Trying to bind to port 0 results in a new unused port being selected.
/// - New outbound connection gets a new unused port, which is used as the local socket address.
///
/// This transport should only be used in tests.
#[derive(Debug)]
pub struct MpscChannelTransport {
    local_address: IpAddr,
    last_port: AtomicU16,
}

impl MpscChannelTransport {
    pub fn new() -> Self {
        let local_address: Ipv4Addr = NEXT_IP_ADDRESS.fetch_add(1, Ordering::Relaxed).into();
        MpscChannelTransport {
            local_address: local_address.into(),
            last_port: 1024.into(),
        }
    }

    fn new_port(&self) -> u16 {
        let port = self.last_port.fetch_add(1, Ordering::Relaxed);
        assert_ne!(port, 0);
        port
    }
}

#[async_trait]
impl TransportSocket for MpscChannelTransport {
    type Listener = ChannelListener;
    type Stream = ChannelStream;

    async fn bind(&self, addresses: Vec<SocketAddress>) -> Result<Self::Listener> {
        let mut addresses: Vec<SocketAddr> =
            addresses.iter().map(SocketAddress::socket_addr).collect();

        let mut connections = CONNECTIONS.lock().expect("Connections mutex is poisoned");

        for address in addresses.iter_mut() {
            if address.ip().is_unspecified() {
                address.set_ip(self.local_address);
            }

            if address.port() == 0 {
                address.set_port(self.new_port());
            }

            // It's not possible to bind to a random address
            if address.ip() != self.local_address {
                return Err(P2pError::DialError(DialError::IoError(
                    std::io::ErrorKind::AddrNotAvailable,
                )));
            };

            // It's not possible to bind to the used address
            if connections.contains_key(address) {
                return Err(P2pError::DialError(DialError::IoError(
                    std::io::ErrorKind::AddrInUse,
                )));
            }
        }

        let (sender, receiver) = unbounded_channel();

        for address in addresses.iter() {
            let old_entry = connections.insert(*address, sender.clone());
            assert!(old_entry.is_none());
        }

        Ok(Self::Listener {
            addresses,
            receiver,
        })
    }

    fn connect(&self, address: SocketAddress) -> BoxFuture<'static, Result<Self::Stream>> {
        let mut address = address.socket_addr();
        if address.ip().is_unspecified() {
            address.set_ip(self.local_address);
        }

        let port = self.new_port();
        let local_address = SocketAddr::new(self.local_address, port);

        Box::pin(async move {
            let server_sender = CONNECTIONS
                .lock()
                .expect("Connections mutex is poisoned")
                .get(&address)
                .ok_or(P2pError::DialError(DialError::NoAddresses))?
                .clone();

            let (connect_sender, connect_receiver) = oneshot::channel();
            server_sender
                .send((local_address, connect_sender))
                .map_err(|_| P2pError::DialError(DialError::NoAddresses))?;

            let channel = connect_receiver.await.map_err(|_| P2pError::ChannelClosed)?;

            Ok(channel)
        })
    }
}

pub struct ChannelListener {
    addresses: Vec<SocketAddr>,
    receiver: UnboundedReceiver<IncomingConnection>,
}

#[async_trait]
impl TransportListener for ChannelListener {
    type Stream = ChannelStream;

    async fn accept(&mut self) -> Result<(ChannelStream, SocketAddress)> {
        let (remote_address, response_sender) =
            self.receiver.recv().await.ok_or(P2pError::ChannelClosed)?;

        let (server, client) = tokio::io::duplex(MAX_BUF_SIZE);

        response_sender.send(client).map_err(|_| P2pError::ChannelClosed)?;

        Ok((server, SocketAddress::new(remote_address)))
    }

    fn local_addresses(&self) -> Result<Vec<SocketAddress>> {
        Ok(self.addresses.iter().cloned().map(SocketAddress::new).collect())
    }
}

impl Drop for ChannelListener {
    fn drop(&mut self) {
        for address in self.addresses.iter() {
            let old_entry =
                CONNECTIONS.lock().expect("Connections mutex is poisoned").remove(address);
            assert!(old_entry.is_some());
        }
    }
}

pub type ChannelStream = DuplexStream;

impl PeerStream for ChannelStream {}

#[cfg(test)]
mod tests {
    use std::net::SocketAddrV4;

    use crypto::random::Rng;
    use test_utils::random::Seed;

    use super::*;
    use crate::{
        message::BlockListRequest,
        net::default_backend::{transport::BufferedTranscoder, types::Message},
    };

    #[tracing::instrument(skip(seed))]
    #[rstest::rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test]
    async fn send_recv(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let transport = MpscChannelTransport::new();
        let address = SocketAddress::new(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into());
        let mut server = transport.bind(vec![address]).await.unwrap();
        let peer_fut = transport.connect(server.local_addresses().unwrap()[0]);

        let (server_res, peer_res) = tokio::join!(server.accept(), peer_fut);
        let server_stream = server_res.unwrap().0;
        let peer_stream = peer_res.unwrap();

        let message = Message::BlockListRequest(BlockListRequest::new(vec![]));
        let mut peer_stream = BufferedTranscoder::new(peer_stream, rng.gen_range(128..1024));
        peer_stream.send(message.clone()).await.unwrap();

        let mut server_stream = BufferedTranscoder::new(server_stream, rng.gen_range(128..1024));
        assert_eq!(server_stream.recv().await.unwrap(), message);
    }
}
