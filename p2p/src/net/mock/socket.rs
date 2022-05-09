// Copyright (c) 2022 RBB S.r.l
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
use crate::net::mock::types;
use bytes::{Buf, BytesMut};
use parity_scale_codec::{Decode, Encode};
use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{Decoder, Encoder};

const MAX: usize = 10 * 1024 * 1024;

struct MessageDecoder {}

impl Decoder for MessageDecoder {
    type Item = types::Message;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 4 {
            return Ok(None);
        }

        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&src[..4]);
        let length = u32::from_le_bytes(length_bytes) as usize;

        if length > MAX {
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

        match types::Message::decode(&mut &data[..]) {
            Ok(msg) => Ok(Some(msg)),
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e.to_string(),
            )),
        }
    }
}

struct MessageEncoder {}

impl Encoder<types::Message> for MessageEncoder {
    type Error = std::io::Error;

    fn encode(&mut self, msg: types::Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let encoded = msg.encode();

        if encoded.len() > MAX {
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

pub struct MockSocket {
    encoder: MessageEncoder,
    decoder: MessageDecoder,
    buffer: BytesMut,
    socket: TcpStream,
}

impl MockSocket {
    pub fn new(socket: TcpStream) -> Self {
        Self {
            socket,
            buffer: bytes::BytesMut::new(),
            encoder: MessageEncoder {},
            decoder: MessageDecoder {},
        }
    }

    pub async fn send(&mut self, msg: types::Message) -> Result<(), std::io::Error> {
        let mut buf = bytes::BytesMut::new();
        self.encoder.encode(msg, &mut buf)?;
        self.socket.write(&buf).await.map(|_| ())
    }

    pub async fn recv(&mut self) -> Result<Option<types::Message>, std::io::Error> {
        if self.socket.read_buf(&mut self.buffer).await? == 0 {
            return self.decoder.decode_eof(&mut self.buffer);
        }

        self.decoder.decode(&mut self.buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: fix this test
    // #[tokio::test]
    // async fn test_mock_socket_send_recv() {
    //     let addr: std::net::SocketAddr = test_utils::make_address("[::1]:");
    //     let mut server = TcpListener::bind(addr).await.unwrap();
    //     let mut peer_fut = TcpStream::connect(addr);

    //     let (res1, res2) = tokio::join!(server.accept(), peer_fut,);
    //     let mut server_socket = MockSocket::new(res1.unwrap().0);
    //     let mut peer_socket = MockSocket::new(res2.unwrap());

    //     let msg = types::Message {
    //         magic: [1, 2, 3, 4],
    //         msg: types::MessageType::Syncing(types::SyncingMessage::Request(
    //             types::SyncingRequest::GetBlocks { headers: vec![] },
    //         )),
    //     };
    //     peer_socket.send(msg.clone()).await.unwrap();

    //     assert_eq!(server_socket.recv().await.unwrap().unwrap(), msg);
    // }
}
