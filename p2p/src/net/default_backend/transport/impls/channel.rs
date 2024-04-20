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
    io::{AsyncRead, AsyncWrite, DuplexStream},
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        oneshot::{self, Sender},
    },
};
use utils::sync::atomic::AtomicU16;

use crate::{
    error::DialError,
    net::default_backend::transport::{
        ConnectedSocketInfo, PeerStream, TransportListener, TransportSocket,
    },
    P2pError, Result,
};

// How much bytes is allowed for write (without reading on the other side).
const MAX_BUF_SIZE: usize = 10 * 1024 * 1024;

struct IncomingConnection {
    from: SocketAddr,
    to: SocketAddr,
    stream_sender: Sender<DuplexStream>,
}

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
        Self::new_with_addr_in_group(0, 0)
    }

    /// Create a new transport with a local address in the specified "group", which is represented
    /// by a certain number of most significant bits in the ip address.
    ///
    /// The resulting local address will be:
    /// (addr_group_idx << (32 - addr_group_bits)) + NEXT_IP_ADDRESS
    pub fn new_with_addr_in_group(addr_group_idx: u32, addr_group_bits: u32) -> Self {
        let addr_group_bit_offset = 32 - addr_group_bits;
        let next_addr = NEXT_IP_ADDRESS.fetch_add(1, Ordering::Relaxed);
        assert!((next_addr as u64) < (1_u64 << addr_group_bit_offset));
        let addr_group = (addr_group_idx as u64) << addr_group_bit_offset;
        assert!(addr_group <= u32::MAX as u64);

        let local_address: Ipv4Addr = (next_addr + addr_group as u32).into();
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
                .send(IncomingConnection {
                    from: local_address,
                    to: address,
                    stream_sender: connect_sender,
                })
                .map_err(|_| P2pError::DialError(DialError::NoAddresses))?;

            let stream = connect_receiver.await.map_err(|_| P2pError::ChannelClosed)?;

            Ok(ChannelStream {
                stream,
                local_address: SocketAddress::new(local_address),
                remote_address: SocketAddress::new(address),
            })
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
        let IncomingConnection {
            from: remote_address,
            to: local_address,
            stream_sender: client_stream_sender,
        } = self.receiver.recv().await.ok_or(P2pError::ChannelClosed)?;

        assert!(self.addresses.contains(&local_address));

        let (server_stream, client_stream) = tokio::io::duplex(MAX_BUF_SIZE);

        client_stream_sender.send(client_stream).map_err(|_| P2pError::ChannelClosed)?;

        let remote_address = SocketAddress::new(remote_address);
        let local_address = SocketAddress::new(local_address);

        Ok((
            ChannelStream {
                stream: server_stream,
                local_address,
                remote_address,
            },
            remote_address,
        ))
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

pub struct ChannelStream {
    stream: DuplexStream,
    local_address: SocketAddress,
    remote_address: SocketAddress,
}

impl AsyncRead for ChannelStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::pin!(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for ChannelStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::pin!(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::pin!(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::pin!(&mut self.stream).poll_shutdown(cx)
    }
}

impl PeerStream for ChannelStream {}

impl ConnectedSocketInfo for ChannelStream {
    fn local_address(&self) -> crate::Result<SocketAddress> {
        Ok(self.local_address)
    }

    fn remote_address(&self) -> crate::Result<SocketAddress> {
        Ok(self.remote_address)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddrV4;

    use randomness::Rng;
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
