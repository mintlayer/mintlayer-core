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

use std::io;

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::codec::{Decoder, Encoder};

use crate::{
    net::default_backend::{transport::message_codec::MessageCodec, types::Message},
    Result,
};

pub struct BufferedTranscoder<S> {
    stream: S,
    buffer: BytesMut,
    message_codec: MessageCodec<Message>,
}

impl<S> BufferedTranscoder<S> {
    pub fn new(stream: S, max_message_size: usize) -> BufferedTranscoder<S> {
        let message_codec = MessageCodec::new(max_message_size);
        BufferedTranscoder {
            stream,
            buffer: BytesMut::new(),
            message_codec,
        }
    }

    /// The inner stream. This is only accessible as an immutable reference, so it'll allow
    /// to read some additional info that the concrete stream might provide, but won't allow
    /// reading or writing the actual stream data.
    pub fn inner_stream(&self) -> &S {
        &self.stream
    }
}

impl<S: AsyncWrite + AsyncRead + Unpin> BufferedTranscoder<S> {
    pub async fn send(&mut self, msg: Message) -> Result<()> {
        let mut buf = BytesMut::new();
        self.message_codec.encode(msg, &mut buf)?;
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
    pub async fn recv(&mut self) -> Result<Message> {
        loop {
            match self.message_codec.decode(&mut self.buffer) {
                Ok(None) => {
                    if self.stream.read_buf(&mut self.buffer).await? == 0 {
                        return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
                    }
                    continue;
                }
                Ok(Some(msg)) => return Ok(msg),
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use chainstate::Locator;
    use chainstate_test_framework::TestFramework;
    use common::{
        chain::config::MagicBytes,
        primitives::{semver::SemVer, Id},
    };
    use crypto::random::Rng;
    use p2p_types::services::Service;
    use test_utils::random::Seed;

    use crate::{
        message::{
            AddrListRequest, AddrListResponse, AnnounceAddrRequest, BlockListRequest,
            BlockResponse, HeaderList, HeaderListRequest, PingRequest, PingResponse,
            TransactionResponse,
        },
        net::default_backend::{
            transport::MpscChannelTransport,
            types::{HandshakeMessage, P2pTimestamp},
        },
        protocol::ProtocolVersion,
        testing_utils::{get_two_connected_sockets, test_p2p_config, TestTransportChannel},
    };

    use super::*;

    // Send and receive each variant of Message once and assert that its value hasn't changed.
    #[tracing::instrument(skip(seed))]
    #[rstest::rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test]
    async fn message_roundtrip(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let p2p_config = test_p2p_config();
        let mut tf = TestFramework::builder(&mut rng).build();
        let block = tf.make_block_builder().add_test_transaction_from_best_block(&mut rng).build();

        let messages = [
            Message::Handshake(HandshakeMessage::Hello {
                protocol_version: ProtocolVersion::new(rng.gen()),
                network: MagicBytes::new([rng.gen(), rng.gen(), rng.gen(), rng.gen()]),
                services: [Service::Blocks].as_slice().into(),
                user_agent: p2p_config.user_agent.clone(),
                software_version: SemVer {
                    major: rng.gen(),
                    minor: rng.gen(),
                    patch: rng.gen(),
                },
                receiver_address: Some(
                    SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(rng.gen(), rng.gen(), rng.gen(), rng.gen())),
                        rng.gen(),
                    )
                    .into(),
                ),
                current_time: P2pTimestamp::from_int_seconds(rng.gen()),
                handshake_nonce: rng.gen(),
            }),
            Message::Handshake(HandshakeMessage::HelloAck {
                protocol_version: ProtocolVersion::new(rng.gen()),
                network: MagicBytes::new([rng.gen(), rng.gen(), rng.gen(), rng.gen()]),
                services: [Service::Blocks].as_slice().into(),
                user_agent: p2p_config.user_agent.clone(),
                software_version: SemVer {
                    major: rng.gen(),
                    minor: rng.gen(),
                    patch: rng.gen(),
                },
                receiver_address: Some(
                    SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(rng.gen(), rng.gen(), rng.gen(), rng.gen())),
                        rng.gen(),
                    )
                    .into(),
                ),
                current_time: P2pTimestamp::from_int_seconds(rng.gen()),
            }),
            Message::PingRequest(PingRequest { nonce: rng.gen() }),
            Message::PingResponse(PingResponse { nonce: rng.gen() }),
            Message::NewTransaction(Id::new(rng.gen())),
            Message::HeaderListRequest(HeaderListRequest::new(Locator::new(vec![
                Id::new(rng.gen()),
                Id::new(rng.gen()),
            ]))),
            Message::HeaderList(HeaderList::new(vec![block.header().clone()])),
            Message::BlockListRequest(BlockListRequest::new(vec![
                Id::new(rng.gen()),
                Id::new(rng.gen()),
            ])),
            Message::BlockResponse(BlockResponse::new(block.clone())),
            Message::TransactionRequest(Id::new(rng.gen())),
            Message::TransactionResponse(TransactionResponse::NotFound(Id::new(rng.gen()))),
            Message::TransactionResponse(TransactionResponse::Found(
                block.transactions()[0].clone(),
            )),
            Message::AnnounceAddrRequest(AnnounceAddrRequest {
                address: SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(rng.gen(), rng.gen(), rng.gen(), rng.gen())),
                    rng.gen(),
                )
                .into(),
            }),
            Message::AddrListRequest(AddrListRequest {}),
            Message::AddrListResponse(AddrListResponse {
                addresses: vec![SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(rng.gen(), rng.gen(), rng.gen(), rng.gen())),
                    rng.gen(),
                )
                .into()],
            }),
        ];

        let (socket1, socket2) =
            get_two_connected_sockets::<TestTransportChannel, MpscChannelTransport>().await;
        let mut sender =
            BufferedTranscoder::new(socket1, *p2p_config.protocol_config.max_message_size);
        let mut receiver =
            BufferedTranscoder::new(socket2, *p2p_config.protocol_config.max_message_size);

        for message in messages {
            sender.send(message.clone()).await.unwrap();
            let received_message = receiver.recv().await.unwrap();
            assert_eq!(received_message, message);
        }

        assert_eq!(sender.buffer.len(), 0);
        assert_eq!(receiver.buffer.len(), 0);
    }
}
