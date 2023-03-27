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
    net::default_backend::{transport::message_codec::EncoderDecoder, types::Message},
    Result,
};

pub struct BufferedTranscoder<S> {
    stream: S,
    buffer: BytesMut,
    encoder_decoder: EncoderDecoder,
}

impl<S: AsyncWrite + AsyncRead + Unpin> BufferedTranscoder<S> {
    pub fn new(stream: S, max_message_size: usize) -> BufferedTranscoder<S> {
        let encoder_decoder = EncoderDecoder::new(max_message_size);
        BufferedTranscoder {
            stream,
            buffer: BytesMut::new(),
            encoder_decoder,
        }
    }

    pub async fn send(&mut self, msg: Message) -> Result<()> {
        let mut buf = BytesMut::new();
        self.encoder_decoder.encode(msg, &mut buf)?;
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
            match self.encoder_decoder.decode(&mut self.buffer) {
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
