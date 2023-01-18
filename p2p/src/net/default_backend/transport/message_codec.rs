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

use bytes::{Buf, BytesMut};
use serialization::{DecodeAll, Encode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::codec::{Decoder, Encoder};

use crate::{constants::MAX_MESSAGE_SIZE, net::default_backend::types::Message, P2pError, Result};

struct EncoderDecoder {}

impl Decoder for EncoderDecoder {
    type Item = Message;
    type Error = P2pError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        if src.len() < 4 {
            return Ok(None);
        }

        let (header, remaining_bytes) = src.split_at_mut(4);

        // Unwrap is safe here because the header size is 4 bytes
        let length = u32::from_le_bytes(header.try_into().expect("valid size")) as usize;

        if length > MAX_MESSAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Frame of length {length} is too large"),
            )
            .into());
        }

        if remaining_bytes.len() < length {
            src.reserve(4 + length - src.len());
            return Ok(None);
        }

        let (body, _extra_bytes) = remaining_bytes.split_at_mut(length);

        let decode_res = Message::decode_all(&mut &body[..]);

        src.advance(4 + length);

        match decode_res {
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

pub struct BufferedTranscoder<S> {
    stream: S,
    buffer: BytesMut,
}

impl<S: AsyncWrite + AsyncRead + Unpin> BufferedTranscoder<S> {
    pub fn new(stream: S) -> BufferedTranscoder<S> {
        BufferedTranscoder {
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
    pub async fn recv(&mut self) -> Result<Message> {
        loop {
            match (EncoderDecoder {}.decode(&mut self.buffer)) {
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
