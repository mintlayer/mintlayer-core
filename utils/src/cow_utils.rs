// Copyright (c) 2021-2025 RBB S.r.l
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

use std::borrow::Cow;

pub trait CowUtils<'a, T: Clone> {
    fn to_owned_cow(&self) -> Cow<'static, T>;
}

impl<'a, T: Clone> CowUtils<'a, T> for Cow<'a, T> {
    fn to_owned_cow(&self) -> Cow<'static, T> {
        Cow::Owned(self.clone().into_owned())
    }
}
