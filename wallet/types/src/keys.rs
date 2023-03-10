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

use crypto::key::extended::{ExtendedPrivateKey, ExtendedPublicKey};
use serialization::{Decode, Encode};
use storage::HasPrefix;

/// The key class is referring to the type of the key, for example a deterministic root
/// This can be used as a prefix for searching specific kinds of keys
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub enum KeyType {
    #[codec(index = 0)]
    DeterministicRoot,
}

/// The key id is described by it's public key
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub enum KeyId {
    #[codec(index = 0)]
    DeterministicRoot(ExtendedPublicKey),
}

impl HasPrefix<KeyType> for KeyId {}

/// The useful content of this key e.g. a private key or an address depending on the usage
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub enum KeyContent {
    #[codec(index = 0)]
    DeterministicRoot(ExtendedPrivateKey),
}
