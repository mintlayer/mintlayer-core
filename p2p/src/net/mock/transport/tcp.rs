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
    io,
    net::{IpAddr, SocketAddr},
};

use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_util::codec::{Decoder, Encoder};

use serialization::{Decode, Encode};

use crate::{
    constants::MAX_MESSAGE_SIZE,
    net::{
        mock::{
            transport::{MockListener, MockStream, MockTransport},
            types::Message,
        },
        AsBannableAddress, IsBannableAddress,
    },
    P2pError, Result,
};

#[derive(Debug)]
pub struct TcpMockTransport {}

#[async_trait]
impl MockTransport for TcpMockTransport {
    type Address = SocketAddr;
    type BannableAddress = IpAddr;
    type Listener = TcpMockListener;
    type Stream = TcpMockStream;

    async fn bind(address: Self::Address) -> Result<Self::Listener> {
        TcpMockListener::new(address).await
    }

    async fn connect(address: Self::Address) -> Result<Self::Stream> {
        let stream = TcpStream::connect(address).await?;
        Ok(stream)
    }
}

pub struct TcpMockListener {
    listener: TcpListener,
}

impl TcpMockListener {
    async fn new(address: SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind(address).await?;

        Ok(Self { listener })
    }
}

#[async_trait]
impl MockListener<TcpMockStream, SocketAddr> for TcpMockListener {
    async fn accept(&mut self) -> Result<(TcpMockStream, SocketAddr)> {
        let (stream, address) = self.listener.accept().await?;
        Ok((stream, address))
    }

    fn local_address(&self) -> Result<SocketAddr> {
        let local_addr = self.listener.local_addr()?;
        Ok(local_addr)
    }
}

pub type TcpMockStream = TcpStream;

#[async_trait]
impl MockStream for TcpMockStream {}

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

pub struct EncoderDecoderWithBuf<S> {
    stream: S,
    buffer: BytesMut,
}

impl<S: AsyncWrite + AsyncRead + Unpin> EncoderDecoderWithBuf<S> {
    pub fn new(stream: S) -> EncoderDecoderWithBuf<S> {
        EncoderDecoderWithBuf {
            stream,
            buffer: BytesMut::new(),
        }
    }

    pub async fn send(&mut self, msg: Message) -> Result<()> {
        let mut buf = bytes::BytesMut::new();
        EncoderDecoder {}.encode(msg, &mut buf)?;
        self.stream.write_all(&buf).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Read a framed message from socket
    ///
    /// First try to decode whatever may be in the stream's buffer and if it's empty
    /// or the frame hasn't been completely received, wait on the socket until the buffer
    /// has all data. If the buffer has a full frame that can be decoded, return that without
    /// calling the socket first.
    pub async fn recv(&mut self) -> Result<Option<Message>> {
        loop {
            match (EncoderDecoder {}.decode(&mut self.buffer)) {
                Ok(None) => {
                    if self.stream.read_buf(&mut self.buffer).await? == 0 {
                        return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
                    }
                    continue;
                }
                frame => return frame,
            }
        }
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

        let (server_res, peer_res) = tokio::join!(server.accept(), peer_fut);
        let server_stream = server_res.unwrap().0;
        let peer_stream = peer_res.unwrap();

        let request_id = MockRequestId::new(1337u64);
        let request = Request::BlockListRequest(BlockListRequest::new(vec![]));
        let mut peer_stream = EncoderDecoderWithBuf::new(peer_stream);
        peer_stream
            .send(Message::Request {
                request_id,
                request: request.clone(),
            })
            .await
            .unwrap();

        let mut server_stream = EncoderDecoderWithBuf::new(server_stream);
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
        let address = "[::1]:0".parse().unwrap();
        let mut server = TcpMockTransport::bind(address).await.unwrap();
        let peer_fut = TcpMockTransport::connect(server.local_address().unwrap());

        let (server_res, peer_res) = tokio::join!(server.accept(), peer_fut);
        let server_stream = server_res.unwrap().0;
        let peer_stream = peer_res.unwrap();

        let id_1 = MockRequestId::new(1337u64);
        let request = Request::BlockListRequest(BlockListRequest::new(vec![]));
        let mut peer_stream = EncoderDecoderWithBuf::new(peer_stream);
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

        let mut server_stream = EncoderDecoderWithBuf::new(server_stream);
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
