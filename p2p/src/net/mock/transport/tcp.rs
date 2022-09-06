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

use std::{io, net::SocketAddr};

use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_util::codec::{Decoder, Encoder};

use serialization::{Decode, Encode};

use crate::{
    constants::MAX_MESSAGE_SIZE,
    net::mock::{
        transport::{MockListener, MockStream, MockTransport},
        types::Message,
    },
    P2pError, Result,
};

#[derive(Debug)]
pub struct TcpMockTransport {}

#[async_trait]
impl MockTransport for TcpMockTransport {
    type Address = SocketAddr;
    type Listener = TcpListener;
    type Stream = TcpMockStream;

    async fn bind(address: Self::Address) -> Result<Self::Listener> {
        TcpListener::bind(address).await.map_err(Into::into)
    }

    async fn connect(address: Self::Address) -> Result<Self::Stream> {
        let stream = TcpStream::connect(address).await?;
        Ok(TcpMockStream::new(stream))
    }
}

#[async_trait]
impl MockListener<TcpMockStream, SocketAddr> for TcpListener {
    async fn accept(&mut self) -> Result<(TcpMockStream, SocketAddr)> {
        let (stream, address) = TcpListener::accept(self).await?;
        Ok((TcpMockStream::new(stream), address))
    }

    fn local_address(&self) -> Result<SocketAddr> {
        self.local_addr().map_err(Into::into)
    }
}

pub struct TcpMockStream {
    stream: TcpStream,
    buffer: BytesMut,
}

impl TcpMockStream {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            buffer: BytesMut::new(),
        }
    }
}

#[async_trait]
impl MockStream for TcpMockStream {
    async fn send(&mut self, msg: Message) -> Result<()> {
        let mut buf = bytes::BytesMut::new();
        EncoderDecoder {}.encode(msg, &mut buf)?;
        self.stream.write(&buf).await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<Message>> {
        if self.stream.read_buf(&mut self.buffer).await? == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }

        EncoderDecoder {}.decode(&mut self.buffer).map_err(Into::into)
    }
}

struct EncoderDecoder {}

impl Decoder for EncoderDecoder {
    type Item = Message;
    type Error = P2pError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        if src.len() < 4 {
            return Ok(None);
        }

        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&src[..4]);
        let length = u32::from_le_bytes(length_bytes) as usize;

        if length > MAX_MESSAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Frame of length {length} is too large"),
            )
            .into());
        }

        if src.len() < 4 + length {
            src.reserve(4 + length - src.len());
            return Ok(None);
        }

        let data = src[4..4 + length].to_vec();
        src.advance(4 + length);

        match Message::decode(&mut &data[..]) {
            Ok(msg) => Ok(Some(msg)),
            Err(e) => {
                Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()).into())
            }
        }
    }
}

struct MessageEncoder {}

impl Encoder<Message> for EncoderDecoder {
    type Error = P2pError;

    fn encode(&mut self, msg: Message, dst: &mut BytesMut) -> Result<()> {
        let encoded = msg.encode();

        if encoded.len() > MAX_MESSAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Frame of length {} is too large", encoded.len()),
            )
            .into());
        }

        let len_slice = u32::to_le_bytes(encoded.len() as u32);

        dst.reserve(4 + encoded.len());
        dst.extend_from_slice(&len_slice);
        dst.extend_from_slice(&encoded);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{
        message::{BlockListRequest, Request},
        mock::types::MockRequestId,
    };

    #[tokio::test]
    async fn send_recv() {
        let address = "[::1]:0".parse().unwrap();
        let mut server = TcpMockTransport::bind(address).await.unwrap();
        let peer_fut = TcpMockTransport::connect(server.local_address().unwrap());

        let (server_res, peer_res) = tokio::join!(MockListener::accept(&mut server), peer_fut);
        let mut server_stream = server_res.unwrap().0;
        let mut peer_stream = peer_res.unwrap();

        let msg = Message::Request {
            request_id: MockRequestId::new(1337u64),
            request: Request::BlockListRequest(BlockListRequest::new(vec![])),
        };
        peer_stream.send(msg.clone()).await.unwrap();

        assert_eq!(server_stream.recv().await.unwrap().unwrap(), msg);
    }
}
