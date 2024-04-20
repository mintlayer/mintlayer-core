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

use std::{marker::PhantomData, mem::size_of};

use bytes::{Buf, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::{error::MessageCodecError, P2pError, Result};
use serialization::{DecodeAll, Encode};

/// The header that precedes each message and specifies the size of the message, not including
/// the header itself.
type MsgLenHeader = u32;

pub struct MessageCodec<Msg> {
    max_message_size: usize,
    _phantom_msg: PhantomData<Msg>,
}

impl<Msg> MessageCodec<Msg> {
    pub fn new(max_message_size: usize) -> Self {
        Self {
            max_message_size,
            _phantom_msg: PhantomData::<Msg>,
        }
    }
}

impl<Msg: DecodeAll> Decoder for MessageCodec<Msg> {
    type Item = Msg;
    type Error = P2pError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        if src.len() < size_of::<MsgLenHeader>() {
            return Ok(None);
        }

        let (header, remaining_bytes) = src.split_at_mut(size_of::<MsgLenHeader>());

        // Unwrap is safe here because the header size is exactly size_of::<Header>().
        let length = MsgLenHeader::from_le_bytes(header.try_into().expect("valid size")) as usize;

        if length > self.max_message_size {
            return Err(MessageCodecError::MessageTooLarge {
                actual_size: length,
                max_size: self.max_message_size,
            }
            .into());
        }

        if remaining_bytes.len() < length {
            src.reserve(size_of::<MsgLenHeader>() + length - src.len());
            return Ok(None);
        }

        let (body, _extra_bytes) = remaining_bytes.split_at_mut(length);

        let decode_res = Msg::decode_all(&mut &body[..]);

        src.advance(size_of::<MsgLenHeader>() + length);

        match decode_res {
            Ok(msg) => Ok(Some(msg)),
            Err(e) => Err(MessageCodecError::InvalidEncodedData(e).into()),
        }
    }
}

impl<Msg: Encode> Encoder<Msg> for MessageCodec<Msg> {
    type Error = P2pError;

    fn encode(&mut self, msg: Msg, dst: &mut BytesMut) -> Result<()> {
        let encoded = msg.encode();

        if encoded.len() > self.max_message_size {
            return Err(MessageCodecError::MessageTooLarge {
                actual_size: encoded.len(),
                max_size: self.max_message_size,
            }
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
    use randomness::Rng;
    use serialization::Decode;
    use test_utils::random::Seed;

    use super::*;

    #[derive(Encode, Decode, Clone, PartialEq, Eq, Debug)]
    struct TestMessage {
        data: u64,
    }

    #[tracing::instrument(skip(seed))]
    #[rstest::rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn size_limit_encode(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let message = TestMessage { data: rng.gen() };

        let mut buf = BytesMut::new();
        // Encode to determine the serialized message length.
        MessageCodec::new(rng.gen_range(64..128))
            .encode(message.clone(), &mut buf)
            .unwrap();
        assert!(buf.len() > size_of::<MsgLenHeader>());

        let message_length = buf.len() - size_of::<MsgLenHeader>();
        let max_length = rng.gen_range(0..message_length);
        let mut encoder = MessageCodec::new(max_length);
        let result = encoder.encode(message, &mut buf);
        assert_eq!(
            result,
            Err(P2pError::MessageCodecError(
                MessageCodecError::MessageTooLarge {
                    actual_size: message_length,
                    max_size: max_length,
                }
            ))
        );
    }

    #[tracing::instrument(skip(seed))]
    #[rstest::rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn size_limit_decode(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let message = TestMessage { data: rng.gen() };
        let mut encoded = BytesMut::new();
        MessageCodec::new(rng.gen_range(126..512))
            .encode(message, &mut encoded)
            .unwrap();

        let message_length = encoded.len() - size_of::<MsgLenHeader>();
        let max_length = rng.gen_range(0..message_length);
        let mut decoder = MessageCodec::<TestMessage>::new(max_length);
        let result = decoder.decode(&mut encoded);
        assert_eq!(
            result,
            Err(P2pError::MessageCodecError(
                MessageCodecError::MessageTooLarge {
                    actual_size: message_length,
                    max_size: max_length,
                }
            ))
        );
    }

    #[tracing::instrument(skip(seed))]
    #[rstest::rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn roundtrip(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let message = TestMessage { data: rng.gen() };

        let mut encoder = MessageCodec::new(rng.gen_range(128..2048));

        let mut buf = BytesMut::new();
        encoder.encode(message.clone(), &mut buf).unwrap();
        let decoded = encoder.decode(&mut buf).unwrap().unwrap();
        assert_eq!(message, decoded);
    }
}
