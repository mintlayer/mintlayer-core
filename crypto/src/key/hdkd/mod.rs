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

pub(crate) mod derivation_path;

use crate::key::hdkd::derivation_path::{ChildNumber, DerivationPath};

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum DerivationError {
    #[error("Invalid child number {0}")]
    InvalidChildNumber(u32),
    #[error("Malformed child number format")]
    InvalidChildNumberFormat,
    #[error("Malformed derivation path format")]
    InvalidDerivationPathFormat,
    #[error("Unsupported derivation type")]
    UnsupportedDerivationType,
}

pub trait Derivable: Sized {
    /// Derive a child private key given a derivation path
    fn derive_path(self, path: &DerivationPath) -> Result<Self, DerivationError> {
        path.into_iter().try_fold(self, |key, num| key.derive_child(*num))
    }

    fn derive_child(self, num: ChildNumber) -> Result<Self, DerivationError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct DummyDerivable(Vec<ChildNumber>);

    impl Derivable for DummyDerivable {
        fn derive_child(self, num: ChildNumber) -> Result<Self, DerivationError> {
            let mut dummy_child = self;
            dummy_child.0.push(num);
            Ok(dummy_child)
        }
    }

    #[test]
    fn test_derivation_trait() {
        let dummy = DummyDerivable::default();
        let path = DerivationPath::from_str("m/1'/2'/3'").unwrap();
        let derived = dummy.derive_path(&path).unwrap();
        let mut expected = DummyDerivable(vec![
            ChildNumber::hardened(1).unwrap(),
            ChildNumber::hardened(2).unwrap(),
            ChildNumber::hardened(3).unwrap(),
        ]);
        assert_eq!(derived, expected);
        let derived = derived.derive_child(ChildNumber::hardened(4).unwrap()).unwrap();
        expected.0.push(ChildNumber::hardened(4).unwrap());
        assert_eq!(derived, expected);
    }
}
