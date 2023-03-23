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
use tokio_util::codec::{Decoder, Encoder};

use crate::{net::default_backend::types::Message, P2pError, Result};

pub struct EncoderDecoder {
    max_message_size: usize,
}

impl EncoderDecoder {
    pub fn new(max_message_size: usize) -> Self {
        Self { max_message_size }
    }
}

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

        if length > self.max_message_size {
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
            Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()).into()),
        }
    }
}

impl Encoder<Message> for EncoderDecoder {
    type Error = P2pError;

    fn encode(&mut self, msg: Message, dst: &mut BytesMut) -> Result<()> {
        let encoded = msg.encode();

        if encoded.len() > self.max_message_size {
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
