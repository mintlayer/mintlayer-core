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

#![allow(unused)]

use parity_scale_codec::{Decode, DecodeAll, Encode, HasCompact};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Encode, Decode)]
pub struct SimpleWrapper<T>(pub T);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Encode, Decode)]
pub struct OptionWrapper<T> {
    pub option: Option<T>,
}

impl<T> OptionWrapper<T> {
    pub fn new(option: Option<T>) -> Self {
        OptionWrapper { option }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Encode, Decode)]
pub struct CompactWrapper<T: HasCompact> {
    #[codec(compact)]
    pub field: T,
}

impl<T: HasCompact> CompactWrapper<T> {
    pub fn new(field: T) -> Self {
        CompactWrapper { field }
    }
}

pub fn check_encoding<T: Encode + DecodeAll + Eq + std::fmt::Debug>(x: T, expected: &[u8]) {
    assert_eq!(x.encode(), expected, "Invalid encoding");
    assert_eq!(T::decode_all(&mut &*expected), Ok(x), "Invalid decoding");
}
