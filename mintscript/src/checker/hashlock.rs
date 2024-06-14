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

use crate::script::HashChallenge;

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
        hash_challenge: &HashChallenge,
        preimage: &[u8; 32],
    ) -> Result<(), Self::Error>;
}

pub struct NoOpHashlockChecker;

impl HashlockChecker for NoOpHashlockChecker {
    type Error = std::convert::Infallible;

    fn check_hashlock(
        &mut self,
        _hash_challenge: &HashChallenge,
        _preimage: &[u8; 32],
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub struct StandardHashlockChecker;

impl HashlockChecker for StandardHashlockChecker {
    type Error = HashlockError;

    fn check_hashlock(
        &mut self,
        hash_challenge: &HashChallenge,
        preimage: &[u8; 32],
    ) -> Result<(), Self::Error> {
        match hash_challenge {
            HashChallenge::HASH160(expected_hash) => {
                let actual_hash = hash::<hash::Ripemd160, _>(hash::<hash::Sha256, _>(preimage));

                ensure_hashes_equal(actual_hash.as_slice(), expected_hash)?;
            }
            HashChallenge::RIPEMD160(_)
            | HashChallenge::SHA1(_)
            | HashChallenge::SHA256(_)
            | HashChallenge::HASH256(_) => {
                unimplemented!()
            }
        }
        Ok(())
    }
}

fn ensure_hashes_equal(left: &[u8], right: &[u8]) -> Result<(), HashlockError> {
    (left == right).then_some(()).ok_or(HashlockError::HashMismatch)
}
