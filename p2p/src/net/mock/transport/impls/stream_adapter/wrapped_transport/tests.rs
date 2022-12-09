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
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::testing_utils::{TestTransportChannel, TestTransportMaker, TestTransportTcp};
use async_trait::async_trait;
use futures::StreamExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

use crate::{
    message::{BlockListRequest, Request},
    net::mock::{
        transport::{
            impls::stream_adapter::wrapped_transport::wrapped_listener::MAX_CONCURRENT_HANDSHAKES,
            BufferedTranscoder, IdentityStreamAdapter, MockChannelListener, MockChannelTransport,
            NoiseEncryptionAdapter, PeerStream, TcpTransportSocket, TransportListener,
            TransportSocket,
        },
        types::{Message, MockRequestId},
    },
};

use super::wrapped_socket::WrappedTransportSocket;

async fn send_recv<T: PeerStream>(sender: &mut T, receiver: &mut T, len: usize) {
    let send_data = (0..len).map(|v| v as u8).collect::<Vec<_>>();
    sender.write_all(&send_data).await.unwrap();
    sender.flush().await.unwrap();

    let mut recv_data = (0..len).map(|_| 0).collect::<Vec<_>>();
    receiver.read_exact(&mut recv_data).await.unwrap();
    assert_eq!(send_data, recv_data);
}

async fn test<A: TestTransportMaker<Address = T::Address>, T: TransportSocket>(transport: T) {
    let mut server = transport.bind(A::make_address()).await.unwrap();
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
    test::<TestTransportTcp, TcpTransportSocket>(TcpTransportSocket::new()).await;

    test::<TestTransportChannel, MockChannelTransport>(MockChannelTransport::new()).await;

    test::<TestTransportTcp, WrappedTransportSocket<NoiseEncryptionAdapter, TcpTransportSocket>>(
        WrappedTransportSocket::new(NoiseEncryptionAdapter::gen_new(), TcpTransportSocket::new()),
    )
    .await;

    test::<
        TestTransportChannel,
        WrappedTransportSocket<NoiseEncryptionAdapter, MockChannelTransport>,
    >(WrappedTransportSocket::new(
        NoiseEncryptionAdapter::gen_new(),
        MockChannelTransport::new(),
    ))
    .await;

    test::<TestTransportTcp, WrappedTransportSocket<IdentityStreamAdapter, TcpTransportSocket>>(
        WrappedTransportSocket::new(IdentityStreamAdapter::new(), TcpTransportSocket::new()),
    )
    .await;

    test::<
        TestTransportChannel,
        WrappedTransportSocket<IdentityStreamAdapter, MockChannelTransport>,
    >(WrappedTransportSocket::new(IdentityStreamAdapter::new(), MockChannelTransport::new()))
    .await;

    test::<
        TestTransportTcp,
        WrappedTransportSocket<
            NoiseEncryptionAdapter,
            WrappedTransportSocket<NoiseEncryptionAdapter, TcpTransportSocket>,
        >,
    >(WrappedTransportSocket::new(
        NoiseEncryptionAdapter::gen_new(),
        WrappedTransportSocket::new(NoiseEncryptionAdapter::gen_new(), TcpTransportSocket::new()),
    ))
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

impl TestMockTransport {
    fn new() -> Self {
        Self {
            transport: MockChannelTransport::new(),
            port_open: Default::default(),
        }
    }
}

#[async_trait]
impl TransportSocket for TestMockTransport {
    type Address = <MockChannelTransport as TransportSocket>::Address;
    type BannableAddress = <MockChannelTransport as TransportSocket>::BannableAddress;
    type Listener = TestMockListener;
    type Stream = <MockChannelTransport as TransportSocket>::Stream;

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

    fn local_address(&self) -> crate::Result<<MockChannelTransport as TransportSocket>::Address> {
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
    let transport = WrappedTransportSocket::<NoiseEncryptionAdapter, TestMockTransport>::new(
        NoiseEncryptionAdapter::gen_new(),
        TestMockTransport::new(),
    );
    assert!(!*transport.base_transport.port_open.lock().unwrap());

    let listener = transport.bind(0).await.unwrap();
    assert!(*transport.base_transport.port_open.lock().unwrap());

    drop(listener);
    assert!(!*transport.base_transport.port_open.lock().unwrap());
}

#[tokio::test]
async fn send_2_reqs() {
    let transport = WrappedTransportSocket::<NoiseEncryptionAdapter, TcpTransportSocket>::new(
        NoiseEncryptionAdapter::gen_new(),
        TcpTransportSocket::new(),
    );
    let mut server = transport.bind(TestTransportTcp::make_address()).await.unwrap();
    let peer_fut = transport.connect(server.local_address().unwrap());

    let (server_res, peer_res) = tokio::join!(server.accept(), peer_fut);
    let server_stream = server_res.unwrap().0;
    let peer_stream = peer_res.unwrap();

    let id_1 = MockRequestId::new(1337u64);
    let request = Request::BlockListRequest(BlockListRequest::new(vec![]));
    let mut peer_stream = BufferedTranscoder::new(peer_stream);
    peer_stream
        .send(Message::Request {
            request_id: id_1,
            request: request.clone(),
        })
        .await
        .unwrap();

    let id_2 = MockRequestId::new(1338u64);
    peer_stream
        .send(Message::Request {
            request_id: id_2,
            request: request.clone(),
        })
        .await
        .unwrap();

    let mut server_stream = BufferedTranscoder::new(server_stream);
    assert_eq!(
        server_stream.recv().await.unwrap().unwrap(),
        Message::Request {
            request_id: id_1,
            request: request.clone(),
        }
    );
    assert_eq!(
        server_stream.recv().await.unwrap().unwrap(),
        Message::Request {
            request_id: id_2,
            request,
        }
    );
}

#[tokio::test]
async fn pending_handshakes() {
    let transport = WrappedTransportSocket::<NoiseEncryptionAdapter, TcpTransportSocket>::new(
        NoiseEncryptionAdapter::gen_new(),
        TcpTransportSocket::new(),
    );
    let mut server = transport.bind(TestTransportTcp::make_address()).await.unwrap();
    let local_addr = server.local_address().unwrap();

    let join_handle = tokio::spawn(async move {
        loop {
            _ = server.accept().await;
        }
    });

    // Connect MAX_CONCURRENT_HANDSHAKES amount of idle clients
    let mut sockets = futures::stream::iter(0..MAX_CONCURRENT_HANDSHAKES)
        .then(|_| async { tokio::net::TcpStream::connect(local_addr).await.unwrap() })
        .collect::<Vec<_>>()
        .await;

    // Noise connection will fail because of too many connected idle TCP clients
    let pending_fut = timeout(Duration::from_millis(100), transport.connect(local_addr)).await;
    assert!(matches!(pending_fut, Err(_)));

    // Disconnect one idle client
    sockets.pop();

    // Noise connection should succeed now
    let pending_fut = timeout(Duration::from_millis(100), transport.connect(local_addr)).await;
    assert!(matches!(pending_fut, Ok(Ok(_))));

    join_handle.abort();
}

#[tokio::test]
async fn handshake_timeout() {
    let transport = WrappedTransportSocket::<NoiseEncryptionAdapter, TcpTransportSocket>::new(
        NoiseEncryptionAdapter::gen_new(),
        TcpTransportSocket::new(),
    );
    let mut server = transport.bind(TestTransportTcp::make_address()).await.unwrap();
    let local_addr = server.local_address().unwrap();

    let join_handle = tokio::spawn(async move {
        loop {
            _ = server.accept().await;
        }
    });

    let mut bad_client = tokio::net::TcpStream::connect(local_addr).await.unwrap();
    // Server should disconnect the bad client because of handshake timeout
    let read_res = bad_client.read_u8().await;
    assert!(read_res.is_err());

    join_handle.abort();
}
