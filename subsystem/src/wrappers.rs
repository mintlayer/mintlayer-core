// Copyright (c) 2022-2023 RBB S.r.l
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

//! Wrappers around objects to turn them into a subsystem.

use crate::Subsystem;

/// Simple stateful subsystem that does not need any customization, the object is used directly.
pub struct Direct<T>(T);

impl<T> Direct<T> {
    pub fn new(subsys: T) -> Self {
        Self(subsys)
    }
}

impl<T: Send + Sync + 'static> Subsystem for Direct<T> {
    type Interface = T;

    fn interface_ref(&self) -> &Self::Interface {
        &self.0
    }

    fn interface_mut(&mut self) -> &mut Self::Interface {
        &mut self.0
    }
}
