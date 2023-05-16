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

/// The index of the receiving key hierarchy
const BIP32_RECEIVING_INDEX: ChildNumber = ChildNumber::ZERO;
/// The index of the change key hierarchy
const BIP32_CHANGE_INDEX: ChildNumber = ChildNumber::ONE;

/// KeyPurpose errors
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum KeyPurposeError {
    #[error("Could not convert key index to key purpose: {0}")]
    KeyPurposeConversion(ChildNumber),
}

/// The usage purpose of a key i.e. if it is for receiving funds or for change
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
#[repr(u32)]
#[allow(clippy::unnecessary_cast)]
pub enum KeyPurpose {
    /// This is for addresses created for receiving funds that are given to the user
    ReceiveFunds = BIP32_RECEIVING_INDEX.get_index(),
    /// This is for the internal usage of the wallet when creating change output for a transaction
    Change = BIP32_CHANGE_INDEX.get_index(),
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
    type Error = KeyPurposeError;

    fn try_from(num: ChildNumber) -> Result<Self, Self::Error> {
        match num {
            BIP32_RECEIVING_INDEX => Ok(ReceiveFunds),
            BIP32_CHANGE_INDEX => Ok(Change),
            _ => Err(KeyPurposeError::KeyPurposeConversion(num)),
        }
    }
}

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

    /// Increments the last index used in the blockchain until up_to_last_used. This has no effect
    /// if the up_to_last_used is smaller than the self value
    pub fn increment_up_to_last_used(&mut self, up_to_last_used: ChildNumber) {
        if self.last_used.is_none() || self.last_used.expect("must be present") < up_to_last_used {
            self.last_used = Some(up_to_last_used);
        }
    }

    /// Get the last index issued to the user
    pub fn get_last_issued(&self) -> Option<ChildNumber> {
        self.last_issued
    }

    /// Increments the last index issued in the blockchain until up_to_last_issued.
    /// This has no effect if the up_to_last_issued is smaller than the self value
    pub fn increment_up_to_last_issued(&mut self, up_to_last_issued: ChildNumber) {
        if self.last_issued.is_none()
            || self.last_issued.expect("must be present") < up_to_last_issued
        {
            self.last_issued = Some(up_to_last_issued);
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keychain_usage_state() {
        let mut state = KeychainUsageState::default();
        assert_eq!(state.get_last_issued(), None);
        assert_eq!(state.get_last_used(), None);

        let index_0 = ChildNumber::ZERO;
        state.increment_up_to_last_used(index_0);
        state.increment_up_to_last_issued(index_0);
        assert_eq!(state.get_last_issued(), Some(index_0));
        assert_eq!(state.get_last_used(), Some(index_0));

        let index_1 = ChildNumber::ONE;
        state.increment_up_to_last_used(index_1);
        state.increment_up_to_last_issued(index_1);
        assert_eq!(state.get_last_issued(), Some(index_1));
        assert_eq!(state.get_last_used(), Some(index_1));

        state.increment_up_to_last_used(index_0);
        state.increment_up_to_last_issued(index_0);
        assert_eq!(state.get_last_issued(), Some(index_1));
        assert_eq!(state.get_last_used(), Some(index_1));
    }
}
