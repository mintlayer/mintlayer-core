// Copyright (c) 2024 RBB S.r.l
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

use crypto::hash::{self, hash};
use utils::ensure;

use crate::script::HashType;

#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum HashlockError {
    #[error("Hash provided doesn't match the type")]
    IncorrectHashSize,

    #[error("Preimage doesn't match the hash")]
    HashMismatch,
}

impl From<std::convert::Infallible> for HashlockError {
    fn from(value: std::convert::Infallible) -> Self {
        match value {}
    }
}

pub trait HashlockChecker {
    type Error: std::error::Error;

    fn check_hashlock(
        &mut self,
        hash_type: HashType,
        hash: &[u8],
        preimage: &[u8],
    ) -> Result<(), Self::Error>;
}

pub struct NoOpHashlockChecker;

impl HashlockChecker for NoOpHashlockChecker {
    type Error = std::convert::Infallible;

    fn check_hashlock(
        &mut self,
        _hash_type: HashType,
        _hash: &[u8],
        _preimage: &[u8],
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub struct StandardHashlockChecker;

impl HashlockChecker for StandardHashlockChecker {
    type Error = HashlockError;

    fn check_hashlock(
        &mut self,
        hash_type: HashType,
        expected_hash: &[u8],
        preimage: &[u8],
    ) -> Result<(), Self::Error> {
        match hash_type {
            HashType::HASH160 => {
                ensure!(expected_hash.len() == 20, HashlockError::IncorrectHashSize);

                let actual_hash = hash::<hash::Ripemd160, _>(hash::<hash::Sha256, _>(preimage));

                (actual_hash.as_slice() == expected_hash)
                    .then_some(())
                    .ok_or(HashlockError::HashMismatch)
            }
            HashType::RIPEMD160 | HashType::SHA1 | HashType::SHA256 | HashType::HASH256 => {
                unimplemented!()
            }
        }
    }
}
