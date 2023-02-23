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

use async_trait::async_trait;
use futures::{future::BoxFuture, StreamExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

use crate::testing_utils::{
    P2pTokioTestTimeGetter, TestTransportChannel, TestTransportMaker, TestTransportTcp,
};
use common::{
    chain::Block,
    primitives::{Id, H256},
};

use crate::{
    message::BlockListRequest,
    net::default_backend::{
        transport::{
            impls::stream_adapter::wrapped_transport::wrapped_listener::MAX_CONCURRENT_HANDSHAKES,
            BufferedTranscoder, ChannelListener, IdentityStreamAdapter, MpscChannelTransport,
            NoiseEncryptionAdapter, PeerStream, TcpTransportSocket, TransportListener,
            TransportSocket,
        },
        types::Message,
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
    let mut server = transport.bind(vec![A::make_address()]).await.unwrap();
    let peer_fut = transport.connect(server.local_addresses().unwrap()[0].clone());

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

    test::<TestTransportChannel, MpscChannelTransport>(MpscChannelTransport::new()).await;

    test::<TestTransportTcp, WrappedTransportSocket<NoiseEncryptionAdapter, TcpTransportSocket>>(
        WrappedTransportSocket::new(NoiseEncryptionAdapter::gen_new(), TcpTransportSocket::new()),
    )
    .await;

    test::<
        TestTransportChannel,
        WrappedTransportSocket<NoiseEncryptionAdapter, MpscChannelTransport>,
    >(WrappedTransportSocket::new(
        NoiseEncryptionAdapter::gen_new(),
        MpscChannelTransport::new(),
    ))
    .await;

    test::<TestTransportTcp, WrappedTransportSocket<IdentityStreamAdapter, TcpTransportSocket>>(
        WrappedTransportSocket::new(IdentityStreamAdapter::new(), TcpTransportSocket::new()),
    )
    .await;

    test::<
        TestTransportChannel,
        WrappedTransportSocket<IdentityStreamAdapter, MpscChannelTransport>,
    >(WrappedTransportSocket::new(IdentityStreamAdapter::new(), MpscChannelTransport::new()))
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

pub struct TestTransport {
    transport: MpscChannelTransport,
    port_open: Arc<Mutex<bool>>,
}

pub struct TestListener {
    listener: ChannelListener,
    port_open: Arc<Mutex<bool>>,
}

impl TestTransport {
    fn new() -> Self {
        Self {
            transport: MpscChannelTransport::new(),
            port_open: Default::default(),
        }
    }
}

#[async_trait]
impl TransportSocket for TestTransport {
    type Address = <MpscChannelTransport as TransportSocket>::Address;
    type BannableAddress = <MpscChannelTransport as TransportSocket>::BannableAddress;
    type Listener = TestListener;
    type Stream = <MpscChannelTransport as TransportSocket>::Stream;

    async fn bind(&self, addresses: Vec<Self::Address>) -> crate::Result<Self::Listener> {
        let listener = self.transport.bind(addresses).await.unwrap();
        *self.port_open.lock().unwrap() = true;
        Ok(TestListener {
            listener,
            port_open: Arc::clone(&self.port_open),
        })
    }

    fn connect(&self, address: Self::Address) -> BoxFuture<'static, crate::Result<Self::Stream>> {
        Box::pin(self.transport.connect(address))
    }
}

#[async_trait]
impl
    TransportListener<
        <MpscChannelTransport as TransportSocket>::Stream,
        <MpscChannelTransport as TransportSocket>::Address,
    > for TestListener
{
    async fn accept(
        &mut self,
    ) -> crate::Result<(
        <MpscChannelTransport as TransportSocket>::Stream,
        <MpscChannelTransport as TransportSocket>::Address,
    )> {
        self.listener.accept().await
    }

    fn local_addresses(
        &self,
    ) -> crate::Result<Vec<<MpscChannelTransport as TransportSocket>::Address>> {
        self.listener.local_addresses()
    }
}

impl Drop for TestListener {
    fn drop(&mut self) {
        *self.port_open.lock().unwrap() = false;
    }
}

#[tokio::test]
// Test that the base listener is dropped after AdaptedTransport::Listener is dropped.
async fn test_bind_port_closed() {
    let transport = WrappedTransportSocket::<NoiseEncryptionAdapter, TestTransport>::new(
        NoiseEncryptionAdapter::gen_new(),
        TestTransport::new(),
    );
    assert!(!*transport.base_transport.port_open.lock().unwrap());

    let listener = transport.bind(vec![0]).await.unwrap();
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
    let mut server = transport.bind(vec![TestTransportTcp::make_address()]).await.unwrap();
    let peer_fut = transport.connect(server.local_addresses().unwrap()[0]);

    let (server_res, peer_res) = tokio::join!(server.accept(), peer_fut);
    let server_stream = server_res.unwrap().0;
    let peer_stream = peer_res.unwrap();

    let message_1 = Message::BlockListRequest(BlockListRequest::new(vec![]));
    let mut rng = test_utils::random::make_seedable_rng(test_utils::random::Seed::from_entropy());
    let id: Id<Block> = H256::random_using(&mut rng).into();
    let message_2 = Message::BlockListRequest(BlockListRequest::new(vec![id]));
    let mut peer_stream = BufferedTranscoder::new(peer_stream);
    peer_stream.send(message_1.clone()).await.unwrap();

    peer_stream.send(message_2.clone()).await.unwrap();

    let mut server_stream = BufferedTranscoder::new(server_stream);
    assert_eq!(server_stream.recv().await.unwrap(), message_1);
    assert_eq!(server_stream.recv().await.unwrap(), message_2);
}

#[tokio::test]
async fn pending_handshakes() {
    let transport = WrappedTransportSocket::<NoiseEncryptionAdapter, TcpTransportSocket>::new(
        NoiseEncryptionAdapter::gen_new(),
        TcpTransportSocket::new(),
    );
    let mut server = transport.bind(vec![TestTransportTcp::make_address()]).await.unwrap();
    let local_addr = server.local_addresses().unwrap();

    let join_handle = tokio::spawn(async move {
        loop {
            _ = server.accept().await;
        }
    });

    // Connect MAX_CONCURRENT_HANDSHAKES amount of idle clients
    let mut sockets = futures::stream::iter(0..MAX_CONCURRENT_HANDSHAKES)
        .then(|_| async { tokio::net::TcpStream::connect(local_addr[0]).await.unwrap() })
        .collect::<Vec<_>>()
        .await;

    // Noise connection will fail because of too many connected idle TCP clients
    let pending_fut = timeout(Duration::from_millis(100), transport.connect(local_addr[0])).await;
    assert!(matches!(pending_fut, Err(_)));

    // Disconnect one idle client
    sockets.pop();

    // Noise connection should succeed now
    let pending_fut = timeout(Duration::from_millis(100), transport.connect(local_addr[0])).await;
    assert!(matches!(pending_fut, Ok(Ok(_))));

    join_handle.abort();
}

#[tokio::test]
async fn handshake_timeout() {
    let time_getter = P2pTokioTestTimeGetter::new();
    let transport = WrappedTransportSocket::<NoiseEncryptionAdapter, TcpTransportSocket>::new(
        NoiseEncryptionAdapter::gen_new(),
        TcpTransportSocket::new(),
    );
    let mut server = transport.bind(vec![TestTransportTcp::make_address()]).await.unwrap();
    let local_addr = server.local_addresses().unwrap();

    let join_handle = tokio::spawn(async move {
        loop {
            _ = server.accept().await;
        }
    });

    let mut bad_client = tokio::net::TcpStream::connect(local_addr[0]).await.unwrap();
    for _ in 0..30 {
        time_getter.advance_time(Duration::from_secs(1)).await;
    }
    // Server should disconnect the bad client because of handshake timeout
    let read_res = bad_client.read_u8().await;
    assert!(read_res.is_err());

    join_handle.abort();
}
