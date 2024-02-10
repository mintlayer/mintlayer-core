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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CachedOperation<T> {
    Write(T),
    Read(T),
    Erase,
}

impl<T> CachedOperation<T> {
    pub fn get(&self) -> Option<&T> {
        match self {
            CachedOperation::Write(v) | CachedOperation::Read(v) => Some(v),
            CachedOperation::Erase => None,
        }
    }

    pub fn take(self) -> Option<T> {
        match self {
            CachedOperation::Write(v) | CachedOperation::Read(v) => Some(v),
            CachedOperation::Erase => None,
        }
    }

    pub fn combine(self, other: Self) -> Self {
        match (self, other) {
            (CachedOperation::Write(_), CachedOperation::Write(other)) => {
                CachedOperation::Write(other)
            }
            (CachedOperation::Write(_), CachedOperation::Read(_)) => todo!(),
            (CachedOperation::Write(_), CachedOperation::Erase) => CachedOperation::Erase,
            (CachedOperation::Read(_), CachedOperation::Write(other)) => {
                CachedOperation::Write(other)
            }
            (CachedOperation::Read(_), CachedOperation::Read(other)) => {
                CachedOperation::Read(other)
            }
            (CachedOperation::Read(_), CachedOperation::Erase) => CachedOperation::Erase,
            (CachedOperation::Erase, CachedOperation::Write(_)) => todo!(),
            (CachedOperation::Erase, CachedOperation::Read(_)) => todo!(),
            (CachedOperation::Erase, CachedOperation::Erase) => todo!(),
        }
    }
}
