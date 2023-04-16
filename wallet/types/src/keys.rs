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

use crate::keys::KeyPurpose::{Change, ReceiveFunds};
use crypto::key::extended::{ExtendedPrivateKey, ExtendedPublicKey};
use crypto::key::hdkd::child_number::ChildNumber;
use crypto::key::hdkd::u31::U31;
use serialization::{Decode, Encode};

/// The usage purpose of a key i.e. if it is for receiving funds or for change
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
#[allow(clippy::unnecessary_cast)]
pub enum KeyPurpose {
    /// This is for addresses created for receiving funds that are given to the user
    ReceiveFunds = 0,
    /// This is for the internal usage of the wallet when creating change output for a transaction
    Change = 1,
}

impl KeyPurpose {
    /// All purposes
    pub const ALL: [KeyPurpose; 2] = [ReceiveFunds, Change];
    /// The index for receiving funds
    const RECEIVE_FUNDS_INDEX: ChildNumber = ChildNumber::from_normal(U31::from_u32_with_msb(0).0);
    /// The index for change addresses/keys
    const CHANGE_INDEX: ChildNumber = ChildNumber::from_normal(U31::from_u32_with_msb(1).0);

    pub fn get_deterministic_index(&self) -> ChildNumber {
        match self {
            ReceiveFunds => Self::RECEIVE_FUNDS_INDEX,
            Change => Self::CHANGE_INDEX,
        }
    }
}

impl TryFrom<ChildNumber> for KeyPurpose {
    type Error = ChildNumber;

    fn try_from(num: ChildNumber) -> Result<Self, Self::Error> {
        match num.get_index() {
            0 => Ok(ReceiveFunds),
            1 => Ok(Change),
            _ => Err(num),
        }
    }
}

// TODO store separately
// receiving_state: KeychainUsageState,
// change_state: KeychainUsageState,

/// Struct that holds information for account addresses
#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct KeychainUsageState {
    /// Last used address index. An address might not be used so the corresponding entry would be
    /// None, otherwise it would be that last used ChildNumber
    last_used: Option<ChildNumber>,
    /// Last issued address to the user. Those addresses can be issued until the
    /// last used index + lookahead size.
    last_issued: Option<ChildNumber>,
}

impl KeychainUsageState {
    pub fn new(last_used: Option<ChildNumber>, last_issued: Option<ChildNumber>) -> Self {
        Self {
            last_used,
            last_issued,
        }
    }

    /// Get the last index used in the blockchain
    pub fn get_last_used(&self) -> Option<ChildNumber> {
        self.last_used
    }

    /// Set the last index used in the blockchain
    pub fn set_last_used(&mut self, new_last_used: Option<ChildNumber>) {
        self.last_used = new_last_used;
    }

    /// Get the last index issued to the user
    pub fn get_last_issued(&self) -> Option<ChildNumber> {
        self.last_issued
    }

    /// Set the last index issued to the user
    pub fn set_last_issued(&mut self, new_last_issued: Option<ChildNumber>) {
        self.last_issued = new_last_issued;
    }
}

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
