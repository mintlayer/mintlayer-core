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

pub mod identity;
pub mod noise;
pub mod traits;

use std::{pin::Pin, task::Poll};

use async_trait::async_trait;
use futures::{future::BoxFuture, Future};

use crate::{net::mock::peer::Role, Result};

use self::traits::StreamAdapter;

use super::{TransportListener, TransportSocket};

/// Transport layer that wraps a lower-level transport layer (can be seen like an onion with multiple layer)
/// Simplest version of this can be seen as a tcp transport layer, with an Identity stream_adapter. That would
/// be equivalent to the tcp transport layer with nothing done to it.
/// More layers can be added on top of this, with this struct, where we add encryption on top.
#[derive(Debug)]
pub struct WrappedTransportSocket<S, T> {
    stream_adapter: S,
    base_transport: T,
}

#[async_trait]
impl<S: StreamAdapter<T::Stream>, T: TransportSocket> TransportSocket
    for WrappedTransportSocket<S, T>
{
    type Address = T::Address;
    type BannableAddress = T::BannableAddress;
    type Listener = AdaptedListener<S, T>;
    type Stream = S::Stream;

    fn new() -> Self {
        let base_transport = T::new();
        let stream_adapter = S::new();
        Self {
            stream_adapter,
            base_transport,
        }
    }

    async fn bind(&self, address: Self::Address) -> Result<Self::Listener> {
        let stream_adapter = S::new();
        let listener = self.base_transport.bind(address).await?;
        Ok(AdaptedListener {
            listener,
            stream_adapter,
            handshakes: Vec::new(),
        })
    }

    async fn connect(&self, address: Self::Address) -> Result<Self::Stream> {
        let base = self.base_transport.connect(address).await?;
        let stream = self.stream_adapter.handshake(base, Role::Outbound).await?;
        Ok(stream)
    }
}

/// A listener object that handles new incoming connections, and does any required hand-shakes (see members' comments)
pub struct AdaptedListener<S: StreamAdapter<T::Stream>, T: TransportSocket> {
    stream_adapter: S,
    listener: T::Listener,
    handshakes: Vec<(BoxFuture<'static, Result<S::Stream>>, T::Address)>,
}

// Helper future used to drive handshakes concurrently
struct HandshakeFut<'a, S: StreamAdapter<T::Stream>, T: TransportSocket>(
    &'a mut Vec<(BoxFuture<'static, Result<S::Stream>>, T::Address)>,
);

impl<'a, S: StreamAdapter<T::Stream>, T: TransportSocket> Future for HandshakeFut<'a, S, T> {
    type Output = (S::Stream, T::Address);

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        'outer: loop {
            for i in 0..self.0.len() {
                match Future::poll(self.0[i].0.as_mut(), cx) {
                    Poll::Ready(res) => {
                        let (_, addr) = self.0.remove(i);
                        match res {
                            Ok(stream) => {
                                return Poll::Ready((stream, addr));
                            }
                            Err(err) => {
                                logging::log::warn!("handshake failed: {}", err);
                                continue 'outer;
                            }
                        }
                    }
                    Poll::Pending => continue,
                }
            }

            return Poll::Pending;
        }
    }
}

#[async_trait]
impl<S: StreamAdapter<T::Stream>, T: TransportSocket> TransportListener<S::Stream, T::Address>
    for AdaptedListener<S, T>
{
    async fn accept(&mut self) -> Result<(S::Stream, T::Address)> {
        loop {
            tokio::select! {
                handshake = HandshakeFut::<S, T>(&mut self.handshakes) => {
                    return Ok(handshake);
                }
                accept_res = self.listener.accept() => {
                    match accept_res {
                        Ok((base, addr)) => {
                            // Store active handshakes because accept must be cancel safe
                            let handshake = self.stream_adapter.handshake(base, Role::Inbound);
                            self.handshakes.push((handshake, addr));
                        },
                        Err(err) => {
                            logging::log::error!("accept failed unexpectedly: {}", err);
                            return Err(err);
                        },
                    }
                }
            }
        }
    }

    fn local_address(&self) -> Result<T::Address> {
        self.listener.local_address()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{
        identity::IdentityStreamAdapter, noise::NoiseEncryptionAdapter, WrappedTransportSocket,
    };
    use crate::net::mock::transport::{
        MockChannelListener, MockChannelTransport, PeerStream, TcpTransportSocket,
        TransportListener, TransportSocket,
    };

    async fn send_recv<T: PeerStream>(sender: &mut T, receiver: &mut T, len: usize) {
        let send_data = (0..len).map(|v| v as u8).collect::<Vec<_>>();
        sender.write_all(&send_data).await.unwrap();
        sender.flush().await.unwrap();

        let mut recv_data = (0..len).map(|_| 0).collect::<Vec<_>>();
        receiver.read_exact(&mut recv_data).await.unwrap();
        assert_eq!(send_data, recv_data);
    }

    async fn test<T: TransportSocket>(bind_addr: &str) {
        let transport = T::new();
        let address = bind_addr.parse().map_err(|_| std::fmt::Error).unwrap();
        let mut server = transport.bind(address).await.unwrap();
        let peer_fut = transport.connect(server.local_address().unwrap());

        let (server_res, peer_res) = tokio::join!(server.accept(), peer_fut);
        let mut server_stream = server_res.unwrap().0;
        let mut peer_stream = peer_res.unwrap();

        send_recv(&mut peer_stream, &mut server_stream, 1).await;
        send_recv(&mut server_stream, &mut peer_stream, 1).await;
        send_recv(&mut peer_stream, &mut server_stream, 65500).await;
        send_recv(&mut peer_stream, &mut server_stream, 65536).await;
        send_recv(&mut server_stream, &mut peer_stream, 70000).await;
    }

    #[tokio::test]
    async fn test_send_recv() {
        test::<TcpTransportSocket>("[::1]:0").await;
        test::<MockChannelTransport>("0").await;

        test::<WrappedTransportSocket<NoiseEncryptionAdapter, TcpTransportSocket>>("[::1]:0").await;
        test::<WrappedTransportSocket<NoiseEncryptionAdapter, MockChannelTransport>>("0").await;
        test::<WrappedTransportSocket<IdentityStreamAdapter, TcpTransportSocket>>("[::1]:0").await;
        test::<WrappedTransportSocket<IdentityStreamAdapter, MockChannelTransport>>("0").await;

        test::<
            WrappedTransportSocket<
                NoiseEncryptionAdapter,
                WrappedTransportSocket<NoiseEncryptionAdapter, TcpTransportSocket>,
            >,
        >("[::1]:0")
        .await;
    }

    pub struct TestMockTransport {
        transport: MockChannelTransport,
        port_open: Arc<Mutex<bool>>,
    }

    pub struct TestMockListener {
        listener: MockChannelListener,
        port_open: Arc<Mutex<bool>>,
    }

    #[async_trait]
    impl TransportSocket for TestMockTransport {
        type Address = <MockChannelTransport as TransportSocket>::Address;
        type BannableAddress = <MockChannelTransport as TransportSocket>::BannableAddress;
        type Listener = TestMockListener;
        type Stream = <MockChannelTransport as TransportSocket>::Stream;

        fn new() -> Self {
            Self {
                transport: MockChannelTransport::new(),
                port_open: Default::default(),
            }
        }

        async fn bind(&self, address: Self::Address) -> crate::Result<Self::Listener> {
            let listener = self.transport.bind(address).await.unwrap();
            *self.port_open.lock().unwrap() = true;
            Ok(TestMockListener {
                listener,
                port_open: Arc::clone(&self.port_open),
            })
        }

        async fn connect(&self, address: Self::Address) -> crate::Result<Self::Stream> {
            self.transport.connect(address).await
        }
    }

    #[async_trait]
    impl
        TransportListener<
            <MockChannelTransport as TransportSocket>::Stream,
            <MockChannelTransport as TransportSocket>::Address,
        > for TestMockListener
    {
        async fn accept(
            &mut self,
        ) -> crate::Result<(
            <MockChannelTransport as TransportSocket>::Stream,
            <MockChannelTransport as TransportSocket>::Address,
        )> {
            self.listener.accept().await
        }

        fn local_address(
            &self,
        ) -> crate::Result<<MockChannelTransport as TransportSocket>::Address> {
            self.listener.local_address()
        }
    }

    impl Drop for TestMockListener {
        fn drop(&mut self) {
            *self.port_open.lock().unwrap() = false;
        }
    }

    #[tokio::test]
    // Test that the base listener is dropped after AdaptedMockTransport::Listener is dropped.
    async fn test_bind_port_closed() {
        let transport = WrappedTransportSocket::<NoiseEncryptionAdapter, TestMockTransport>::new();
        assert!(!*transport.base_transport.port_open.lock().unwrap());

        let listener = transport.bind(0).await.unwrap();
        assert!(*transport.base_transport.port_open.lock().unwrap());

        drop(listener);
        assert!(!*transport.base_transport.port_open.lock().unwrap());
    }
}
