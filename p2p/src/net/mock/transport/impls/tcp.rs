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

use std::net::{IpAddr, SocketAddr};

use async_trait::async_trait;
use tokio::net::{TcpListener, TcpStream};

use crate::{
    net::{
        mock::transport::{PeerStream, TransportListener, TransportSocket},
        AsBannableAddress, IsBannableAddress,
    },
    Result,
};

#[derive(Debug)]
pub struct TcpTransportSocket;

impl TcpTransportSocket {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TransportSocket for TcpTransportSocket {
    type Address = SocketAddr;
    type BannableAddress = IpAddr;
    type Listener = TcpTransportListener;
    type Stream = TcpTransportStream;

    async fn bind(&self, address: Self::Address) -> Result<Self::Listener> {
        TcpTransportListener::new(address).await
    }

    async fn connect(&self, address: Self::Address) -> Result<Self::Stream> {
        let stream = TcpStream::connect(address).await?;
        Ok(stream)
    }
}

pub struct TcpTransportListener {
    listener: TcpListener,
}

impl TcpTransportListener {
    async fn new(address: SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind(address).await?;

        Ok(Self { listener })
    }
}

#[async_trait]
impl TransportListener<TcpTransportStream, SocketAddr> for TcpTransportListener {
    async fn accept(&mut self) -> Result<(TcpTransportStream, SocketAddr)> {
        let (stream, address) = self.listener.accept().await?;
        Ok((stream, address))
    }

    fn local_address(&self) -> Result<SocketAddr> {
        let local_addr = self.listener.local_addr()?;
        Ok(local_addr)
    }
}

impl AsBannableAddress for SocketAddr {
    type BannableAddress = IpAddr;

    fn as_bannable(&self) -> Self::BannableAddress {
        self.ip()
    }
}

impl IsBannableAddress for SocketAddr {
    fn is_bannable(&self) -> bool {
        true
    }
}

pub type TcpTransportStream = TcpStream;

#[async_trait]
impl PeerStream for TcpTransportStream {}

#[cfg(test)]
mod tests {
    use crate::testing_utils::{TestTransportMaker, TestTransportTcp};

    use super::*;
    use crate::net::{
        message::{BlockListRequest, Request},
        mock::{
            transport::BufferedTranscoder,
            types::{Message, MockRequestId},
        },
    };

    #[tokio::test]
    async fn send_recv() {
        let transport = TcpTransportSocket::new();
        let mut server = transport.bind(TestTransportTcp::make_address()).await.unwrap();
        let peer_fut = transport.connect(server.local_address().unwrap());

        let (server_res, peer_res) = tokio::join!(server.accept(), peer_fut);
        let server_stream = server_res.unwrap().0;
        let peer_stream = peer_res.unwrap();

        let request_id = MockRequestId::new(1337u64);
        let request = Request::BlockListRequest(BlockListRequest::new(vec![]));
        let mut peer_stream = BufferedTranscoder::new(peer_stream);
        peer_stream
            .send(Message::Request {
                request_id,
                request: request.clone(),
            })
            .await
            .unwrap();

        let mut server_stream = BufferedTranscoder::new(server_stream);
        assert_eq!(
            server_stream.recv().await.unwrap().unwrap(),
            Message::Request {
                request_id,
                request,
            }
        );
    }

    #[tokio::test]
    async fn send_2_reqs() {
        let transport = TcpTransportSocket::new();
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
}
