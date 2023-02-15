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

use std::{
    iter::Sum,
    ops::{Add, Sub},
};

use common::primitives::Amount;
use utils::newtype;

newtype! {
    #[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Copy, Clone)]
    pub struct Fee(Amount);
}

impl Add for Fee {
    type Output = Option<Self>;

    fn add(self, rhs: Self) -> Self::Output {
        (self.0 + rhs.0).map(Self)
    }
}

impl Sub for Fee {
    type Output = Option<Self>;

    fn sub(self, rhs: Self) -> Self::Output {
        (self.0 - rhs.0).map(Self)
    }
}

impl Sum<Fee> for Option<Fee> {
    fn sum<I>(mut iter: I) -> Self
    where
        I: Iterator<Item = Fee>,
    {
        iter.try_fold(Fee(Amount::ZERO), std::ops::Add::add)
    }
}
