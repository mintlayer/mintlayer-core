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
    fmt::{self, Display, Formatter},
    net::SocketAddr,
};

use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use tokio::net::TcpListener;
use tokio_util::codec::{Decoder, Encoder};

use serialization::{Decode, Encode};

use crate::{
    constants::MAX_MESSAGE_SIZE,
    net::mock::{
        transport::{AddressMock, ConnectionMock, NetworkMock},
        types::Message,
    },
};

pub struct TcpNetworkMock {}

impl TcpNetworkMock {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl NetworkMock for TcpNetworkMock {
    type Address = TcpAddressMock;

    fn new(peers: usize) -> (Self, Vec<Self::Address>) {
        todo!()
    }

    // fn add_peer(&mut self) -> Self::Address {
    //     TcpAddressMock::new("[::1]:0".parse().unwrap())
    // }

    async fn run(self) {
        // We don't need to do anything special here.
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TcpAddressMock {
    address: SocketAddr,
}

impl TcpAddressMock {
    pub fn new(address: SocketAddr) -> Self {
        Self { address }
    }
}

// TODO: FIXME:
impl Display for TcpAddressMock {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

#[async_trait]
impl AddressMock for TcpAddressMock {
    type Connection = TcpConnectionMock;

    async fn create(self) -> Result<Self::Connection, ()> {
        // TODO: FIXME: Handle error.
        Ok(TcpConnectionMock::new(
            TcpListener::bind(self.address).await.unwrap(),
        ))
    }

    async fn connect(self) -> Result<Self::Connection, ()> {
        todo!()
    }
}

pub struct TcpConnectionMock {
    socket: TcpListener,
    buffer: BytesMut,
}

impl TcpConnectionMock {
    fn new(socket: TcpListener) -> Self {
        Self {
            socket,
            buffer: BytesMut::new(),
        }
    }
}

#[async_trait]
impl ConnectionMock for TcpConnectionMock {
    async fn send(&mut self, message: Message) -> Result<(), ()> {
        let mut buf = bytes::BytesMut::new();
        // TODO: FIXME: Fix error.
        EncoderDecoder {}.encode(message, &mut buf).unwrap();
        //self.socket.write(&buf).await.map(|_| ())
        todo!()
    }

    async fn recv(&mut self) -> Result<Option<Message>, ()> {
        // TODO: FIXME
        todo!()
        // if self.socket.read_buf(&mut self.buffer).await? == 0 {
        //     // TODO: FIXME:
        //     //return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        //     return Err(());
        // }
        //
        // // TODO: FIXME: Error.
        // Ok(EncoderDecoder {}.decode(&mut self.buffer).unwrap())
    }
}

struct EncoderDecoder {}

impl Encoder<Message> for EncoderDecoder {
    type Error = std::io::Error;

    fn encode(&mut self, msg: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let encoded = msg.encode();

        if encoded.len() <= MAX_MESSAGE_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Frame of length {} is too large.", encoded.len()),
            ));
        }

        let len_slice = u32::to_le_bytes(encoded.len() as u32);

        dst.reserve(4 + encoded.len());
        dst.extend_from_slice(&len_slice);
        dst.extend_from_slice(&encoded);

        Ok(())
    }
}

impl Decoder for EncoderDecoder {
    type Item = Message;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 4 {
            return Ok(None);
        }

        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&src[..4]);
        let length = u32::from_le_bytes(length_bytes) as usize;

        if length <= MAX_MESSAGE_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Frame of length {} is too large.", length),
            ));
        }

        if src.len() < 4 + length {
            src.reserve(4 + length - src.len());
            return Ok(None);
        }

        let data = src[4..4 + length].to_vec();
        src.advance(4 + length);

        match Message::decode(&mut &data[..]) {
            Ok(msg) => Ok(Some(msg)),
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e.to_string(),
            )),
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::{message::*, net::mock::types};
//     use tokio::net::TcpListener;
//
//     #[tokio::test]
//     async fn test_mock_socket_send_recv() {
//         let addr: std::net::SocketAddr = "[::1]:0".parse().unwrap();
//         let server = TcpListener::bind(addr).await.unwrap();
//         let peer_fut = TcpStream::connect(server.local_addr().unwrap());
//
//         let (res1, res2) = tokio::join!(server.accept(), peer_fut);
//         let mut server_socket = MockSocket::new(res1.unwrap().0);
//         let mut peer_socket = MockSocket::new(res2.unwrap());
//
//         let msg = Message::Request {
//             request_id: types::MockRequestId::new(1337u64),
//             request: Request::BlockListRequest(BlockListRequest::new(vec![])),
//         };
//         peer_socket.send(msg.clone()).await.unwrap();
//
//         assert_eq!(server_socket.recv().await.unwrap().unwrap(), msg);
//     }
// }
