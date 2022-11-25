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
    marker::PhantomData,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

pub mod adapter;

use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc::UnboundedReceiver,
    time::timeout,
};
use tokio_util::codec::{Decoder, Encoder};

use serialization::{Decode, Encode};

use crate::{
    constants::MAX_MESSAGE_SIZE,
    net::{
        mock::{
            peer::Role,
            transport::{MockListener, MockStream, MockTransport},
            types::Message,
        },
        AsBannableAddress, IsBannableAddress,
    },
    P2pError, Result,
};

use self::adapter::StreamAdapter;

// How much time is allowed to spend setting up (optionally) encrypted stream.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub struct TcpMockTransport<E: StreamAdapter>(PhantomData<E>);

#[async_trait]
impl<E: StreamAdapter + 'static> MockTransport for TcpMockTransport<E> {
    type Address = SocketAddr;
    type BannableAddress = IpAddr;
    type Listener = TcpMockListener<E>;
    type Stream = TcpMockStream<E>;

    async fn bind(
        stream_key: &<<Self as MockTransport>::Stream as MockStream>::StreamKey,
        address: Self::Address,
    ) -> Result<Self::Listener> {
        TcpMockListener::start(stream_key, address).await
    }

    async fn connect(
        stream_key: &<<Self as MockTransport>::Stream as MockStream>::StreamKey,
        address: Self::Address,
    ) -> Result<Self::Stream> {
        let base = TcpStream::connect(address).await?;
        let stream = TcpMockStream::new(stream_key, base, Role::Outbound).await?;
        Ok(stream)
    }
}

pub struct TcpMockListener<E: StreamAdapter> {
    receiver: UnboundedReceiver<(TcpMockStream<E>, SocketAddr)>,
    local_address: SocketAddr,
    join_handle: tokio::task::JoinHandle<()>,
    _phantom: PhantomData<E>,
}

impl<E: StreamAdapter + 'static> TcpMockListener<E> {
    async fn start(stream_key: &E::StreamKey, address: SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind(address).await?;
        let local_address = listener.local_addr()?;
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();

        // Process new connections in background because MockListener::accept must be cancel safe.
        let stream_key = Arc::new(stream_key.clone());
        let join_handle = tokio::spawn(async move {
            loop {
                let (socket, socket_addr) = match listener.accept().await {
                    Ok(socket) => socket,
                    Err(err) => {
                        logging::log::error!("TCP accept failed unexpectedly: {}", err);
                        return;
                    }
                };
                let sender_copy = sender.clone();
                let stream_key = Arc::clone(&stream_key);
                tokio::spawn(async move {
                    let res = timeout(
                        HANDSHAKE_TIMEOUT,
                        TcpMockStream::<E>::new(&stream_key, socket, Role::Inbound),
                    )
                    .await;
                    let socket = match res {
                        Ok(Ok(socket)) => socket,
                        Ok(Err(err)) => {
                            logging::log::warn!("encryption handshake failed: {}", err);
                            return;
                        }
                        Err(err) => {
                            logging::log::warn!("encryption handshake timed out: {}", err);
                            return;
                        }
                    };
                    // It's not an error if the channel is already closed
                    _ = sender_copy.send((socket, socket_addr));
                });
            }
        });

        Ok(Self {
            receiver,
            local_address,
            join_handle,
            _phantom: PhantomData,
        })
    }
}

impl<E: StreamAdapter> Drop for TcpMockListener<E> {
    fn drop(&mut self) {
        self.join_handle.abort();
    }
}

#[async_trait]
impl<E: StreamAdapter> MockListener<TcpMockStream<E>, SocketAddr> for TcpMockListener<E> {
    async fn accept(&mut self) -> Result<(TcpMockStream<E>, SocketAddr)> {
        self.receiver.recv().await.ok_or(P2pError::ChannelClosed)
    }

    fn local_address(&self) -> Result<SocketAddr> {
        Ok(self.local_address)
    }
}

pub struct TcpMockStream<E: StreamAdapter> {
    stream: E::Stream,
    buffer: BytesMut,
}

impl<E: StreamAdapter> TcpMockStream<E> {
    async fn new(stream_key: &E::StreamKey, base: TcpStream, role: Role) -> Result<Self> {
        let stream = E::handshake(stream_key, base, role).await?;
        Ok(Self {
            stream,
            buffer: BytesMut::new(),
        })
    }
}

#[async_trait]
impl<E: StreamAdapter> MockStream for TcpMockStream<E> {
    type StreamKey = E::StreamKey;

    async fn send(&mut self, msg: Message) -> Result<()> {
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
    async fn recv(&mut self) -> Result<Option<Message>> {
        match (EncoderDecoder {}.decode(&mut self.buffer)) {
            Ok(None) => {
                if self.stream.read_buf(&mut self.buffer).await? == 0 {
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
                }
                self.recv().await
            }
            frame => frame,
        }
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
    use super::{
        adapter::identity::IdentityStreamAdapter, adapter::noise::NoiseEncryptionAdapter, *,
    };
    use crate::net::{
        message::{BlockListRequest, Request},
        mock::{transport::StreamKey, types::MockRequestId},
    };

    async fn test_send_recv<E: StreamAdapter + 'static>() {
        let address = "[::1]:0".parse().unwrap();
        let mut server =
            TcpMockTransport::<E>::bind(&E::StreamKey::gen_new(), address).await.unwrap();
        let client_stream_key = E::StreamKey::gen_new();
        let peer_fut =
            TcpMockTransport::<E>::connect(&client_stream_key, server.local_address().unwrap());

        let (server_res, peer_res) = tokio::join!(server.accept(), peer_fut);
        let mut server_stream = server_res.unwrap().0;
        let mut peer_stream = peer_res.unwrap();

        let request_id = MockRequestId::new(1337u64);
        let request = Request::BlockListRequest(BlockListRequest::new(vec![]));
        peer_stream
            .send(Message::Request {
                request_id,
                request: request.clone(),
            })
            .await
            .unwrap();

        assert_eq!(
            server_stream.recv().await.unwrap().unwrap(),
            Message::Request {
                request_id,
                request,
            }
        );
    }

    #[tokio::test]
    async fn send_recv_cleartext() {
        test_send_recv::<IdentityStreamAdapter>().await;
    }

    #[tokio::test]
    async fn send_recv_noise() {
        test_send_recv::<NoiseEncryptionAdapter>().await;
    }

    async fn test_send_2_reqs<E: StreamAdapter + 'static>() {
        let address = "[::1]:0".parse().unwrap();
        let mut server =
            TcpMockTransport::<E>::bind(&E::StreamKey::gen_new(), address).await.unwrap();
        let client_stream_key = E::StreamKey::gen_new();
        let peer_fut =
            TcpMockTransport::<E>::connect(&client_stream_key, server.local_address().unwrap());

        let (server_res, peer_res) = tokio::join!(server.accept(), peer_fut);
        let mut server_stream = server_res.unwrap().0;
        let mut peer_stream = peer_res.unwrap();

        let id_1 = MockRequestId::new(1337u64);
        let request = Request::BlockListRequest(BlockListRequest::new(vec![]));
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
    async fn send_2_reqs_cleartext() {
        test_send_2_reqs::<IdentityStreamAdapter>().await;
    }

    #[tokio::test]
    async fn send_2_reqs_noise() {
        test_send_2_reqs::<NoiseEncryptionAdapter>().await;
    }
}
