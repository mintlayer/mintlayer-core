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
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
};

use serialization::{Decode, Encode};

#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Debug, Encode, Decode)]
pub struct PeerId(u64);

impl FromStr for PeerId {
    type Err = <u64 as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        u64::from_str(s).map(Self)
    }
}

static NEXT_PEER_ID: AtomicU64 = AtomicU64::new(1);

impl PeerId {
    pub fn new() -> Self {
        let id = NEXT_PEER_ID.fetch_add(1, Ordering::Relaxed);
        Self(id)
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
