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

use serialization::{Decode, Encode};

use super::message_codec::MessageCodec;

pub struct BufferedTranscoder<S, Msg> {
    stream: S,
    buffer: BytesMut,
    message_codec: MessageCodec<Msg>,
}

impl<S, Msg> BufferedTranscoder<S, Msg> {
    pub fn new(stream: S, max_message_size: Option<usize>) -> BufferedTranscoder<S, Msg> {
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

impl<S, Msg> BufferedTranscoder<S, Msg>
where
    Msg: Encode + Decode,
    S: AsyncWrite + AsyncRead + Unpin,
{
    pub async fn send(&mut self, msg: Msg) -> crate::Result<()> {
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
    pub async fn recv(&mut self) -> crate::Result<Msg> {
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

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use randomness::Rng;
    use test_utils::random::{gen_random_bytes, make_seedable_rng, Seed};

    use super::*;

    // Send and receive messages of various lengths and assert that their values haven't changed.
    #[tracing::instrument(skip(seed))]
    #[rstest::rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test]
    async fn message_roundtrip(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let message_count = rng.gen_range(1..=20);

        let max_msg_size = 1000;
        let messages = (0..message_count)
            .map(|_| gen_random_bytes(&mut rng, 1, max_msg_size))
            .collect::<Vec<_>>();

        let buf_size = rng.gen_range(10..max_msg_size + 10);
        let (stream1, stream2) = tokio::io::duplex(buf_size);

        let mut sender = BufferedTranscoder::new(stream1, None);
        let mut receiver = BufferedTranscoder::<_, Vec<u8>>::new(stream2, None);

        let (sender_sender, sender_receiver) = tokio::sync::oneshot::channel();

        tokio::spawn({
            let messages = messages.clone();
            async move {
                for message in messages {
                    sender.send(message).await.unwrap();
                }

                sender_sender.send(sender).ok().unwrap();
            }
        });

        for message in messages {
            let received_message = receiver.recv().await.unwrap();
            assert_eq!(received_message, message);
        }

        let sender = sender_receiver.await.unwrap();

        assert_eq!(sender.buffer.len(), 0);
        assert_eq!(receiver.buffer.len(), 0);
    }
}
