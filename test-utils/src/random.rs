// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crypto::random::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;

pub struct Seed(pub u64);

impl Seed {
    pub fn from_entropy() -> Self {
        Seed(crypto::random::make_true_rng().gen::<u64>())
    }

    pub fn from_u64(v: u64) -> Self {
        Seed(v)
    }
}

#[must_use]
pub fn make_seedable_rng(seed: Seed) -> impl Rng {
    ChaChaRng::seed_from_u64(seed.0)
}

/// Makes PRNG that should be used in unit tests to get deterministic values from non-deterministic seed.
///
/// # Example
///
/// ```
/// use test_utils::{make_seedable_rng, random::*};
/// let mut rng = make_seedable_rng!(Seed::from_entropy());
/// ```
/// If the test case fails a seed will be printed to std out, e.g:
///
/// `chainstate/src/detail/tests/double_spend_tests.rs:45 Using seed '4862969352335513650' for the PRNG`
///
/// That output can be used to reproduce the fail by passing the seed from printed integer instead of entropy:  
/// ```
/// use test_utils::{make_seedable_rng, random::*};
/// let mut rng = make_seedable_rng!(Seed::from_u64(4862969352335513650));
/// ```
#[macro_export]
macro_rules! make_seedable_rng {
    ($seed:expr) => {{
        println!(
            "{}:{} Using seed '{}' for the PRNG",
            file!(),
            line!(),
            $seed.0
        );
        make_seedable_rng($seed)
    }};
}
