// Copyright (c) 2021-2024 RBB S.r.l
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

use crypto::key::hdkd::u31::U31;
use serde::{de::Error, Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AccountId(U31);

impl AccountId {
    pub fn new(index: U31) -> Self {
        Self(index)
    }

    pub fn account_index(&self) -> U31 {
        self.0
    }
}

impl Serialize for AccountId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.into_u32().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AccountId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let i = u32::deserialize(deserializer)?;
        let i = U31::from_u32(i).ok_or_else(|| {
            D::Error::custom(format!("Integer has invalid value for AccountId ({i})"))
        })?;
        Ok(Self::new(i))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;
    use test_utils::random::{Rng, Seed};

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_json_valid(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let id = AccountId::new(U31::from_u32_with_msb(rng.gen::<u32>()).0);

        let id_json = serde_json::to_string(&id).unwrap();
        let id_decoded = serde_json::from_str::<AccountId>(&id_json).unwrap();
        assert_eq!(id_decoded, id);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_json_invalid(#[case] seed: Seed) {
        use crypto::key::hdkd::u31::MSB_BIT;

        let mut rng = test_utils::random::make_seedable_rng(seed);

        let str = rng.gen_range(MSB_BIT..u32::MAX).to_string();

        serde_json::from_str::<AccountId>(&str).unwrap_err();
    }
}
