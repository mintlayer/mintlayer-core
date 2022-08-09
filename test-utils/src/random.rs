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

use crypto::random::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use std::{num::ParseIntError, str::FromStr};

#[derive(Debug, Copy, Clone)]
pub struct Seed(pub u64);

impl Seed {
    pub fn from_entropy() -> Self {
        Seed(crypto::random::make_true_rng().gen::<u64>())
    }

    pub fn from_u64(v: u64) -> Self {
        Seed(v)
    }
}

impl FromStr for Seed {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = s.parse::<u64>()?;
        Ok(Seed::from_u64(v))
    }
}

#[must_use]
pub fn make_seedable_rng(seed: Seed) -> impl Rng {
    ChaChaRng::seed_from_u64(seed.0)
}
