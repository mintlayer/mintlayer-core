// Copyright (c) 2023 RBB S.r.l
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

use serialization::{Decode, Encode};
use std::fmt::Display;

/// Just an empty struct used as key for the DB table
/// It only represents a single value as there can be only one root key
#[derive(PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct SeedPhraseConstant;

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum SeedPhraseLanguage {
    #[codec(index = 0)]
    English,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum SerializedSeedPhrase {
    #[codec(index = 0)]
    V0(SeedPhraseLanguage, SeedPhrase),
}

impl SerializedSeedPhrase {
    pub fn new(mnemonic: zeroize::Zeroizing<bip39::Mnemonic>) -> Self {
        Self::V0(SeedPhraseLanguage::English, SeedPhrase::new(mnemonic))
    }
}

impl Display for SerializedSeedPhrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V0(_, words) => f.write_str(words.mnemonic.join(" ").as_str()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedPhrase {
    mnemonic: zeroize::Zeroizing<Vec<String>>,
}

impl SeedPhrase {
    pub fn new(mnemonic: zeroize::Zeroizing<bip39::Mnemonic>) -> Self {
        Self {
            mnemonic: zeroize::Zeroizing::new(mnemonic.word_iter().map(|w| w.into()).collect()),
        }
    }
}

impl Encode for SeedPhrase {
    fn encode_to<T: serialization::Output + ?Sized>(&self, dest: &mut T) {
        self.mnemonic.encode_to(dest)
    }
}

impl Decode for SeedPhrase {
    fn decode<I: serialization::Input>(input: &mut I) -> Result<Self, serialization::Error> {
        Ok(Self {
            mnemonic: zeroize::Zeroizing::new(Vec::<String>::decode(input)?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;
    use serialization::DecodeAll;

    #[test]
    fn seed_phrase_encode_decode() {
        let seed_phrase = SeedPhrase::new(zeroize::Zeroizing::new(
            bip39::Mnemonic::generate(24).unwrap(),
        ));

        let encoded = seed_phrase.encode();
        let decoded_seed_phrase = SeedPhrase::decode_all(&mut encoded.as_slice()).unwrap();

        assert_eq!(seed_phrase, decoded_seed_phrase);

        let encode_again = decoded_seed_phrase.encode();

        assert_eq!(encoded, encode_again);
    }

    #[test]
    fn decode_fixed_seed_phrase() {
        let encoded: Vec<u8> =
            FromHex::from_hex("301c6162616e646f6e1c6162616e646f6e1c6162616e646f6e1c6162616e646f6e1c6162616e646f6e1c6162616e646f6e1c6162616e646f6e1c6162616e646f6e1c6162616e646f6e1c6162616e646f6e1c6162616e646f6e1461626f7574")
                .unwrap();
        let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let expected_seed_phrase = SeedPhrase::new(zeroize::Zeroizing::new(
            bip39::Mnemonic::parse_normalized(mnemonic_str).unwrap(),
        ));

        let decoded_seed_phrase = SeedPhrase::decode_all(&mut encoded.as_slice()).unwrap();

        assert_eq!(decoded_seed_phrase, expected_seed_phrase);
        assert_eq!(decoded_seed_phrase.mnemonic.join(" "), mnemonic_str);
    }
}
