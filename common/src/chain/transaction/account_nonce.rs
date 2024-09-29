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

use serialization::{Decode, Encode};

/// An incremental value that represents sequential number of spending from an account.
/// It's equivalent to the nonce in Ethereum and helps preserving order of transactions and
/// avoid transaction replay.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Encode,
    Decode,
    serde::Serialize,
    serde::Deserialize,
    rpc_description::HasValueHint,
)]
pub struct AccountNonce(#[codec(compact)] u64);

impl AccountNonce {
    pub fn new(nonce: u64) -> Self {
        Self(nonce)
    }

    pub fn value(&self) -> u64 {
        self.0
    }

    pub fn increment(self) -> Option<Self> {
        self.0.checked_add(1).map(AccountNonce::new)
    }

    pub fn decrement(self) -> Option<Self> {
        self.0.checked_sub(1).map(AccountNonce::new)
    }
}

impl std::fmt::Display for AccountNonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use randomness::Rng;
    use rstest::rstest;
    use test_utils::random::Seed;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_nonce_increment(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        assert_eq!(AccountNonce::new(u64::MAX).increment(), None);

        let v = rng.gen_range(0..u64::MAX - 1);
        assert_eq!(
            AccountNonce::new(v).increment(),
            Some(AccountNonce::new(v + 1))
        );
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_nonce_decrement(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        assert_eq!(AccountNonce::new(0).decrement(), None);

        let v = rng.gen_range(1..u64::MAX);
        assert_eq!(
            AccountNonce::new(v).decrement(),
            Some(AccountNonce::new(v - 1))
        );
    }
}
