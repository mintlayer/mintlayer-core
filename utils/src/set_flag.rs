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

use std::ops::Deref;

/// Wrapper for the bool type that can only be set to true once
#[derive(Default)]
pub struct SetFlag(bool);

impl SetFlag {
    pub fn set(&mut self) {
        self.0 = true;
    }
}

impl Deref for SetFlag {
    type Target = bool;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
