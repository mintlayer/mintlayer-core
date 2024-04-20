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

pub use bip39::{Error, Language, Mnemonic};

use randomness::Rng;
use wallet_types::seed_phrase::MNEMONIC_24_WORDS_ENTROPY_SIZE;
use zeroize::Zeroize;

/// Generate a new 24-word mnemonic string using [crypto::random::make_true_rng]
pub fn generate_new_mnemonic(language: Language) -> Mnemonic {
    let mut rng = randomness::make_true_rng();
    let mut data = [0u8; MNEMONIC_24_WORDS_ENTROPY_SIZE];
    rng.fill(&mut data);
    let res = bip39::Mnemonic::from_entropy_in(language, &data).expect("should not fail");
    data.zeroize();
    res
}

/// Try to parse a mnemonic string (12, 15, 18, 21, or 24 words)
pub fn parse_mnemonic(language: Language, mnemonic: &str) -> Result<Mnemonic, Error> {
    bip39::Mnemonic::parse_in(language, mnemonic)
}
