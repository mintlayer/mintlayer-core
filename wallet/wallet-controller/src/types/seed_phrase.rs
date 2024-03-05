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

use wallet_types::seed_phrase::SerializableSeedPhrase;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, rpc_description::HasValueHint)]
pub struct SeedWithPassPhrase {
    pub seed_phrase: Vec<String>,
    pub passphrase: Option<String>,
}

impl SeedWithPassPhrase {
    pub fn from_serializable_seed_phrase(serializable_seed_phrase: SerializableSeedPhrase) -> Self {
        match serializable_seed_phrase {
            wallet_types::seed_phrase::SerializableSeedPhrase::V0(_, words) => Self {
                seed_phrase: words.mnemonic().to_vec(),
                passphrase: None,
            },
            wallet_types::seed_phrase::SerializableSeedPhrase::V1(_, words, passphrase) => Self {
                seed_phrase: words.mnemonic().to_vec(),
                passphrase: passphrase.take(),
            },
        }
    }
}
