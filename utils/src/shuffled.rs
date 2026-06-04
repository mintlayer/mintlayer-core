// Copyright (c) 2026 RBB S.r.l
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

use std::convert::AsMut;

use randomness::{CryptoRng, SliceRandom as _};

/// An extension trait allowing to shuffle a container without creating an intermediate mutable
/// variable.
pub trait Shuffled<Item>: AsMut<[Item]> {
    fn shuffled(self, rng: &mut impl CryptoRng) -> Self;
}

impl<T, Item> Shuffled<Item> for T
where
    T: AsMut<[Item]>,
{
    fn shuffled(mut self, rng: &mut impl CryptoRng) -> Self {
        self.as_mut().shuffle(rng);
        self
    }
}
