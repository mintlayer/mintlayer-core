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

/// The key id is described by it's public key
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct RootKeyId(ExtendedPublicKey);

impl From<ExtendedPublicKey> for RootKeyId {
    fn from(key: ExtendedPublicKey) -> Self {
        Self(key)
    }
}

/// The useful content of this key e.g. a private key or an address depending on the usage
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct RootKeyContent(ExtendedPrivateKey);

impl RootKeyContent {
    pub fn into_key(self) -> ExtendedPrivateKey {
        self.0
    }
}

impl From<ExtendedPrivateKey> for RootKeyContent {
    fn from(key: ExtendedPrivateKey) -> Self {
        Self(key)
    }
}
