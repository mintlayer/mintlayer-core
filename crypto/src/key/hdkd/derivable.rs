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

use crate::key::hdkd::derivation_path::DerivationPath;

use super::child_number::ChildNumber;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum DerivationError {
    #[error("Invalid child number {0}")]
    InvalidChildNumber(u32),
    #[error("Malformed child number format")]
    InvalidChildNumberFormat,
    #[error("Malformed derivation path format")]
    InvalidDerivationPathFormat,
    #[error("Unsupported derivation for key type")]
    UnsupportedKeyType,
    #[error("Key derivation error")]
    KeyDerivationError,
    #[error("Derivation path too long")]
    PathTooLong,
    #[error("Cannot derive path: {0}")]
    CannotDerivePath(DerivationPath),
    #[error("Cannot derive hardened key from public key: {0}")]
    CannotDeriveHardenedKeyFromPublicKey(ChildNumber),
}

pub trait Derivable: Sized {
    /// Derive a child private key given a derivation path. The derivation path must include
    /// the path of this key. For example:
    /// - If this (self) key has the path m/1/2/3
    /// - Then the requested path should be m/1/2/3/<rest/of/the/path>
    fn derive_path(self, path: &DerivationPath) -> Result<Self, DerivationError> {
        let self_path_vec = self.get_derivation_path().as_vec();
        // The derivation path must be larger than the path of this key
        if path.len() <= self_path_vec.len() {
            return Err(DerivationError::CannotDerivePath(path.clone()));
        }
        // Make sure that the paths have a common sub-path
        let path_vec = path.as_vec();
        let (common_path, new_path) = path_vec.split_at(self_path_vec.len());
        if common_path != self_path_vec {
            return Err(DerivationError::CannotDerivePath(path.clone()));
        }
        // Derive the rest of the path
        new_path.iter().try_fold(self, |key, num| key.derive_child(*num))
    }

    /// Derive a single child key
    fn derive_child(self, num: ChildNumber) -> Result<Self, DerivationError>;

    /// Get the derivation path of this key
    fn get_derivation_path(&self) -> &DerivationPath;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct DummyDerivable(DerivationPath);

    impl Derivable for DummyDerivable {
        fn derive_child(self, num: ChildNumber) -> Result<Self, DerivationError> {
            let mut dummy_child = self.0.into_vec();
            dummy_child.push(num);
            Ok(Self(dummy_child.try_into().unwrap()))
        }

        fn get_derivation_path(&self) -> &DerivationPath {
            &self.0
        }
    }

    #[test]
    fn derivation_trait() {
        let dummy = DummyDerivable::default();
        let path = DerivationPath::from_str("m/1'/2'/3'").unwrap();
        let derived = dummy.derive_path(&path).unwrap();
        let mut expected = vec![
            ChildNumber::from_hardened(1.try_into().unwrap()),
            ChildNumber::from_hardened(2.try_into().unwrap()),
            ChildNumber::from_hardened(3.try_into().unwrap()),
        ];
        assert_eq!(derived.0.as_vec(), &expected);
        let derived =
            derived.derive_child(ChildNumber::from_hardened(4.try_into().unwrap())).unwrap();
        expected.push(ChildNumber::from_hardened(4.try_into().unwrap()));
        assert_eq!(derived.0.as_vec(), &expected);
        let path = DerivationPath::from_str("m/1'/2'/3'/4'/5").unwrap();
        let derived = derived.derive_path(&path).unwrap();
        expected.push(ChildNumber::from_normal(5.try_into().unwrap()));
        assert_eq!(derived.0.as_vec(), &expected);
    }
}
