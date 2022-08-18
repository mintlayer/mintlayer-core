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

use std::{
    collections::HashSet,
    fmt::{self, Display, Formatter},
};

use tap::TapFallible;

use common::primitives::semver::SemVer;
use logging::log;
use serialization::{Decode, Encode};

/// Protocol type and version.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Encode, Decode)]
pub struct Protocol {
    version: SemVer,
    protocol: ProtocolType,
}

/// Protocol type.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Encode, Decode)]
pub enum ProtocolType {
    // TODO: FIXME: Add the documentation.
    Pubsub,
    Ping,
    Sync,
}

impl Protocol {
    /// Constructs a new protocol instance with given type and version.
    pub const fn new(protocol: ProtocolType, version: SemVer) -> Self {
        Self { protocol, version }
    }

    /// Parses a protocol from the given string.
    ///
    /// A string must contain the name of a protocol and a version after the last slash. For
    /// example: "/meshsub/1.1.0" or "/mintlayer/sync/0.1.0".
    pub fn from_str(val: &str) -> Option<Self> {
        let (protocol, version) = val.rsplit_once('/')?;

        let protocol = match protocol {
            "/meshsub" => ProtocolType::Pubsub,
            "/ipfs/ping" => ProtocolType::Ping,
            "/mintlayer/sync" => ProtocolType::Sync,
            _ => {
                log::trace!("Ignoring unknown '{val}' protocol");
                return None;
            }
        };

        let version = SemVer::try_from(version)
            .tap_err(|e| log::trace!("Ignoring protocol with malformed version: {val} ({e:?})"))
            .ok()?;

        Some(Protocol::new(protocol, version))
    }

    pub fn protocol(&self) -> ProtocolType {
        self.protocol
    }

    pub fn version(&self) -> SemVer {
        self.version
    }
}

impl Display for Protocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} {}", self.protocol, self.version)
    }
}

// TODO: FIXME: Add the documentation.
// Describe that "invalid protocols are ignored"
pub fn parse_protocols<'a, I, P>(protocols: I) -> HashSet<Protocol>
where
    I: IntoIterator<Item = P>,
    P: AsRef<str>,
{
    protocols.into_iter().filter_map(|p| Protocol::from_str(p.as_ref())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_str() {
        let data = [
            ("/meshsub/1.1.0", ProtocolType::Pubsub, SemVer::new(1, 1, 0)),
            ("/ipfs/ping/2.3.4", ProtocolType::Ping, SemVer::new(2, 3, 4)),
            (
                "/mintlayer/sync/0.1.0",
                ProtocolType::Sync,
                SemVer::new(0, 1, 0),
            ),
        ];

        for (str, protocol, version) in data {
            let actual = Protocol::from_str(str).unwrap();
            assert_eq!(actual.protocol, protocol);
            assert_eq!(actual.version, version);
        }
    }

    #[test]
    fn parse_standard_protocols() {
        let expected: HashSet<_> = [
            Protocol::new(ProtocolType::Pubsub, SemVer::new(1, 1, 0)),
            Protocol::new(ProtocolType::Ping, SemVer::new(1, 0, 0)),
            Protocol::new(ProtocolType::Sync, SemVer::new(0, 1, 0)),
        ]
        .into_iter()
        .collect();
        let parsed = parse_protocols([
            "/meshsub/1.1.0",
            "/meshsub/1.0.0",
            "/ipfs/ping/1.0.0",
            "/ipfs/id/1.0.0",
            "/ipfs/id/push/1.0.0",
            "/mintlayer/sync/0.1.0",
        ]);
        assert_eq!(expected, parsed);
    }
}
