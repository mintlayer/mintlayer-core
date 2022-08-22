// Copyright (c) 2021-2022 RBB S.r.l
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

use std::fmt::{self, Display, Formatter};

use common::primitives::semver::SemVer;
use serialization::{Decode, Encode};

/// Protocol type and version.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct Protocol {
    version: SemVer,
    protocol: ProtocolType,
}

/// Protocol type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub enum ProtocolType {
    /// The publish/subscription protocol.
    PubSub,
    /// The ping protocol can be used as a simple application-layer health check. Corresponds to
    /// the "/ipfs/ping" protocol.
    Ping,
    /// The synchronisation protocol.
    Sync,
}

impl Protocol {
    /// Constructs a new protocol instance with given type and version.
    pub const fn new(protocol: ProtocolType, version: SemVer) -> Self {
        Self { protocol, version }
    }

    /// Returns a protocol type.
    pub fn protocol(&self) -> ProtocolType {
        self.protocol
    }

    /// Returns a protocol version.
    pub fn version(&self) -> SemVer {
        self.version
    }
}

impl Display for Protocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} {}", self.protocol, self.version)
    }
}
