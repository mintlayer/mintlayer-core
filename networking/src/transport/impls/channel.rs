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
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream},
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        oneshot::{self, Sender},
    },
};

use utils::sync::atomic::AtomicU16;

use crate::{
    error::NetworkingError,
    transport::{ConnectedSocketInfo, PeerStream, TransportListener, TransportSocket},
    Result,
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
        let addr: Ipv4Addr = Self::next_local_address_as_u32().into();
        Self::new_with_local_address(addr.into())
    }

    pub fn new_with_local_address(local_address: IpAddr) -> Self {
        Self {
            local_address,
            last_port: 1024.into(),
        }
    }

    /// Return the next u32 value that can be used to construct a unique local address for this kind of transport.
    pub fn next_local_address_as_u32() -> u32 {
        NEXT_IP_ADDRESS.fetch_add(1, Ordering::Relaxed)
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

    async fn bind(&self, mut addresses: Vec<SocketAddr>) -> Result<Self::Listener> {
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
                return Err(NetworkingError::IoError(
                    std::io::ErrorKind::AddrNotAvailable,
                ));
            };

            // It's not possible to bind to the used address
            if connections.contains_key(address) {
                return Err(NetworkingError::IoError(std::io::ErrorKind::AddrInUse));
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

    fn connect(&self, mut address: SocketAddr) -> BoxFuture<'static, Result<Self::Stream>> {
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
                .ok_or(MpscChannelTransportError::NoListener(address))?
                .clone();

            let (connect_sender, connect_receiver) = oneshot::channel();
            server_sender
                .send(IncomingConnection {
                    from: local_address,
                    to: address,
                    stream_sender: connect_sender,
                })
                .map_err(|_| MpscChannelTransportError::ListenerDroppedUnexpectedly(address))?;

            let stream = connect_receiver
                .await
                .map_err(|_| MpscChannelTransportError::ListenerDroppedUnexpectedly(address))?;

            Ok(ChannelStream {
                stream,
                local_address,
                remote_address: address,
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

    async fn accept(&mut self) -> Result<(ChannelStream, SocketAddr)> {
        let IncomingConnection {
            from: remote_address,
            to: local_address,
            stream_sender: client_stream_sender,
        } = self.receiver.recv().await.ok_or_else(|| {
            MpscChannelTransportError::UnknownConnectorDroppedUnexpectedly {
                listening_addresses: self.addresses.clone(),
            }
        })?;

        assert!(self.addresses.contains(&local_address));

        let (server_stream, client_stream) = tokio::io::duplex(MAX_BUF_SIZE);

        client_stream_sender.send(client_stream).map_err(|_| {
            MpscChannelTransportError::ConnectorDroppedUnexpectedly {
                local_address,
                remote_address,
            }
        })?;

        Ok((
            ChannelStream {
                stream: server_stream,
                local_address,
                remote_address,
            },
            remote_address,
        ))
    }

    fn local_addresses(&self) -> Result<Vec<SocketAddr>> {
        Ok(self.addresses.clone())
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
    local_address: SocketAddr,
    remote_address: SocketAddr,
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
    fn local_address(&self) -> crate::Result<SocketAddr> {
        Ok(self.local_address)
    }

    fn remote_address(&self) -> crate::Result<SocketAddr> {
        Ok(self.remote_address)
    }
}

/// Some errors specific to the channel transport.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum MpscChannelTransportError {
    #[error("The address {0} is not being listened on")]
    NoListener(SocketAddr),
    #[error("Listener for address {0} dropped unexpectedly")]
    ListenerDroppedUnexpectedly(SocketAddr),
    #[error("Unknown connection initiator dropped unexpectedly when listening to addresses {listening_addresses:?}")]
    UnknownConnectorDroppedUnexpectedly {
        listening_addresses: Vec<SocketAddr>,
    },
    #[error("Connection initiator dropped unexpectedly, local_address = {local_address}, remote_address = {remote_address}")]
    ConnectorDroppedUnexpectedly {
        local_address: SocketAddr,
        remote_address: SocketAddr,
    },
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddrV4;

    use randomness::Rng;
    use test_utils::random::{gen_random_bytes, Seed};

    use crate::transport::BufferedTranscoder;

    use super::*;

    #[tracing::instrument(skip(seed))]
    #[rstest::rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test]
    async fn send_recv(#[case] seed: Seed) {
        use serialization::Encode;

        let mut rng = test_utils::random::make_seedable_rng(seed);

        let transport = MpscChannelTransport::new();
        let address = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into();
        let mut server = transport.bind(vec![address]).await.unwrap();
        let peer_fut = transport.connect(server.local_addresses().unwrap()[0]);

        let (server_res, peer_res) = tokio::join!(server.accept(), peer_fut);
        let server_stream = server_res.unwrap().0;
        let peer_stream = peer_res.unwrap();

        let message_size = rng.gen_range(128..1024);

        let message = gen_random_bytes(&mut rng, 1, message_size);
        let mut peer_stream = BufferedTranscoder::new(peer_stream, Some(message.encoded_size()));
        peer_stream.send(message.clone()).await.unwrap();

        let mut server_stream =
            BufferedTranscoder::<_, Vec<u8>>::new(server_stream, Some(message.encoded_size()));
        assert_eq!(server_stream.recv().await.unwrap(), message);
    }
}
