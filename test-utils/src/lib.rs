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

pub mod mock_time_getter;
pub mod nft_utils;
pub mod random;
pub mod test_dir;

use crypto::random::distributions::uniform::SampleRange;
use crypto::random::Rng;
use hex::ToHex;

/// Assert that the encoded object matches the expected hex string.
pub fn assert_encoded_eq<E: serialization::Encode>(to_encode: &E, expected_hex: &str) {
    assert_eq!(to_encode.encode().encode_hex::<String>(), expected_hex);
}

/// Encodes an object to a hex string
pub fn encode_to_hex<E: serialization::Encode>(to_encode: &E) -> String {
    to_encode.encode().encode_hex::<String>()
}

/// Decodes a hex string to an object. Will panic on errors
pub fn decode_from_hex<D: serialization::DecodeAll>(to_decode: &str) -> D {
    D::decode_all(&mut hex::decode(to_decode).expect("The provided string is a hex").as_slice())
        .expect("The decoding succeeded")
}

pub fn random_string<R: SampleRange<usize>>(rng: &mut impl Rng, range_len: R) -> String {
    use crypto::random::distributions::{Alphanumeric, DistString};
    if range_len.is_empty() {
        return String::new();
    }
    let len = rng.gen_range(range_len);
    Alphanumeric.sample_string(rng, len)
}

pub fn gen_text_with_non_ascii(c: u8, rng: &mut impl Rng, max_len: usize) -> Vec<u8> {
    assert!(!c.is_ascii_alphanumeric());
    let text_len = 1 + rng.gen::<usize>() % max_len;
    let random_index_to_replace = rng.gen::<usize>() % text_len;
    let token_ticker: Vec<u8> = (0..text_len)
        .into_iter()
        .map(|idx| {
            if idx != random_index_to_replace {
                rng.sample(crypto::random::distributions::Alphanumeric)
            } else {
                c
            }
        })
        .take(text_len)
        .collect();
    token_ticker
}
