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

pub const MNEMONIC_24_WORDS_ENTROPY_SIZE: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreSeedPhrase {
    Store,
    DoNotStore,
}

impl StoreSeedPhrase {
    pub fn should_save(self) -> bool {
        match self {
            Self::Store => true,
            Self::DoNotStore => false,
        }
    }
}

/// Just an empty struct used as key for the DB table
/// It only represents a single value as there can be only one root key
#[derive(PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct SeedPhraseConstant;

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum SeedPhraseLanguage {
    #[codec(index = 0)]
    English,
}

impl SeedPhraseLanguage {
    fn new(language: bip39::Language) -> Self {
        match language {
            bip39::Language::English => Self::English,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum SerializableSeedPhrase {
    #[codec(index = 0)]
    V0(SeedPhraseLanguage, SeedPhrase),
    #[codec(index = 1)]
    V1(SeedPhraseLanguage, SeedPhrase, PassPhrase),
}

impl SerializableSeedPhrase {
    pub fn zero_seed_phrase() -> Self {
        SerializableSeedPhrase::V0(
            SeedPhraseLanguage::English,
            SeedPhrase {
                mnemonic: zeroize::Zeroizing::new(vec![String::new(); 24]),
            },
        )
    }

    pub fn new(
        mnemonic: zeroize::Zeroizing<bip39::Mnemonic>,
        passphrase: zeroize::Zeroizing<Option<String>>,
    ) -> Self {
        Self::V1(
            SeedPhraseLanguage::new(mnemonic.language()),
            SeedPhrase::new(mnemonic),
            PassPhrase::new(passphrase),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassPhrase {
    passphrase: zeroize::Zeroizing<Option<String>>,
}

impl PassPhrase {
    pub fn new(passphrase: zeroize::Zeroizing<Option<String>>) -> Self {
        Self { passphrase }
    }

    pub fn take(mut self) -> Option<String> {
        self.passphrase.take()
    }
}

impl Encode for PassPhrase {
    fn encode_to<T: serialization::Output + ?Sized>(&self, dest: &mut T) {
        self.passphrase.encode_to(dest)
    }
}

impl Decode for PassPhrase {
    fn decode<I: serialization::Input>(input: &mut I) -> Result<Self, serialization::Error> {
        Ok(Self {
            passphrase: zeroize::Zeroizing::new(Option::<String>::decode(input)?),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedPhrase {
    mnemonic: zeroize::Zeroizing<Vec<String>>,
}

impl SeedPhrase {
    pub fn new(mnemonic: zeroize::Zeroizing<bip39::Mnemonic>) -> Self {
        Self {
            mnemonic: zeroize::Zeroizing::new(
                bip39::Mnemonic::words(&mnemonic).map(|w| w.into()).collect(),
            ),
        }
    }

    pub fn mnemonic(&self) -> &[String] {
        &self.mnemonic
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
    use randomness::Rng;
    use rstest::rstest;
    use serialization::DecodeAll;

    #[rstest]
    #[trace]
    #[case(test_utils::random::Seed::from_entropy())]
    fn seed_phrase_encode_decode(#[case] seed: test_utils::random::Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let entropy = rng.gen::<[u8; MNEMONIC_24_WORDS_ENTROPY_SIZE]>();

        let seed_phrase = SeedPhrase::new(zeroize::Zeroizing::new(
            bip39::Mnemonic::from_entropy(&entropy).unwrap(),
        ));

        assert_eq!(seed_phrase.mnemonic().len(), 24);

        let encoded = seed_phrase.encode();
        let decoded_seed_phrase = SeedPhrase::decode_all(&mut encoded.as_slice()).unwrap();

        assert_eq!(seed_phrase, decoded_seed_phrase);

        let encode_again = decoded_seed_phrase.encode();

        assert_eq!(encoded, encode_again);
    }

    #[test]
    fn decode_fixed_seed_phrase() {
        let encoded: Vec<u8> =
            FromHex::from_hex("60146177616b65186e756d626572146772616365186361727065741c636c757374657218636c7574636818666f72676574106d617468107768617418696d6d756e6510746861741462726f776e1c6465706f73697410676f61741873756666657214757375616c1861707065617218746f6e6775651872656c6965661464697a7a791c63757368696f6e146578616374147368696e6518636f70706572")
                .unwrap();
        let mnemonic_vec = [
            "awake", "number", "grace", "carpet", "cluster", "clutch", "forget", "math", "what",
            "immune", "that", "brown", "deposit", "goat", "suffer", "usual", "appear", "tongue",
            "relief", "dizzy", "cushion", "exact", "shine", "copper",
        ]
        .to_vec();

        let expected_seed_phrase = SeedPhrase::new(zeroize::Zeroizing::new(
            bip39::Mnemonic::parse_normalized(&mnemonic_vec.join(" ")).unwrap(),
        ));

        let decoded_seed_phrase = SeedPhrase::decode_all(&mut encoded.as_slice()).unwrap();

        assert_eq!(decoded_seed_phrase, expected_seed_phrase);
        assert_eq!(decoded_seed_phrase.mnemonic, decoded_seed_phrase.mnemonic);
    }
}
