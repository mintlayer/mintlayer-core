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

use wallet_types::KeyPurpose;

pub struct WithPurpose<T> {
    pub receive: T,
    pub change: T,
}

impl<T> WithPurpose<T> {
    pub fn new(receive: T, change: T) -> Self {
        Self { receive, change }
    }

    pub fn get_for(&self, purpose: KeyPurpose) -> &T {
        match purpose {
            KeyPurpose::ReceiveFunds => &self.receive,
            KeyPurpose::Change => &self.change,
        }
    }

    pub fn mut_for(&mut self, purpose: KeyPurpose) -> &mut T {
        match purpose {
            KeyPurpose::ReceiveFunds => &mut self.receive,
            KeyPurpose::Change => &mut self.change,
        }
    }
}
