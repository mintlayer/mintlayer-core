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

pub use rand::prelude::SliceRandom;
pub use rand::{seq, CryptoRng, Rng, RngCore, SeedableRng};

pub mod distributions {
    pub use rand::distributions::{Alphanumeric, DistString, Distribution, Standard};
    pub mod uniform {
        pub use rand::distributions::uniform::SampleRange;
    }
}

pub mod rngs {
    pub use rand::rngs::OsRng;
}

#[must_use]
pub fn make_true_rng() -> impl rand::Rng + rand::CryptoRng {
    rand::rngs::StdRng::from_entropy()
}

#[must_use]
pub fn make_pseudo_rng() -> impl rand::Rng {
    rand::rngs::ThreadRng::default()
}
