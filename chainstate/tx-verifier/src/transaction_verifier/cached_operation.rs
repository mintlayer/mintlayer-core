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

use core::fmt::Debug;

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
}

pub fn combine<T: Debug + PartialEq>(
    left: Option<CachedOperation<T>>,
    right: Option<CachedOperation<T>>,
) -> Option<CachedOperation<T>> {
    match (left, right) {
        (None, None) => None,
        (None, Some(v)) => Some(v),
        (Some(_), None) => panic!("data is missing"),
        (Some(left), Some(right)) => {
            let result = match (left, right) {
                (CachedOperation::Write(left), CachedOperation::Write(right)) => {
                    // It is possible to get into Write/Write situation if 2 txs are connected
                    // then verifier is derived and one of the txs is disconnected.
                    // Because in that case derived would fetch block undo there will be unused Write tx
                    // which on flush would lead here.
                    assert_eq!(
                        left, right,
                        "Data cannot change on multiple levels of hierarchy"
                    );
                    CachedOperation::Write(right)
                }
                (CachedOperation::Write(_), CachedOperation::Read(_)) => {
                    panic!("read after data been modified")
                }
                (CachedOperation::Write(_), CachedOperation::Erase) => CachedOperation::Erase,
                (CachedOperation::Read(_), CachedOperation::Write(right)) => {
                    CachedOperation::Write(right)
                }
                (CachedOperation::Read(_), CachedOperation::Read(right)) => {
                    CachedOperation::Read(right)
                }
                (CachedOperation::Read(_), CachedOperation::Erase) => CachedOperation::Erase,
                (CachedOperation::Erase, CachedOperation::Write(right)) => {
                    // it is possible in mempool to disconnect a tx and connect it again,
                    // e.g. if memory limit was raised
                    CachedOperation::Write(right)
                }
                (CachedOperation::Erase, CachedOperation::Read(_)) => {
                    panic!("read after data been erased")
                }
                (CachedOperation::Erase, CachedOperation::Erase) => CachedOperation::Erase,
            };
            Some(result)
        }
    }
}
