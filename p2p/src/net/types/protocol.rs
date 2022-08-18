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
    // TODO: FIXME.
    Pubsub,
    Ping,
    Handshake,
    Sync,
}

/*
    "/meshsub/1.1.0",
   "/meshsub/1.0.0",
   "/ipfs/ping/1.0.0",
   "/ipfs/id/1.0.0",
   "/ipfs/id/push/1.0.0",
   "/mintlayer/sync/0.1.0",
*/

impl Protocol {
    pub fn new(protocol: ProtocolType, version: SemVer) -> Self {
        Self { protocol, version }
    }

    // TODO: FIXME:
    // pub fn from_str(val: &str) -> Option<Self> {
    //     let (protocol, version) = val.rsplit_once('/')?;
    //     // TODO: tap_err?
    //     let version = match SemVer::try_from(val) {
    //         Err(e) => {
    //             log::trace!("Ignoring protocol with malformed version: {val} ({e:?})");
    //             return None;
    //         }
    //         Ok(v) => v,
    //     };
    //     let protocol = match protocol {
    //         "meshsub" => ProtocolType::Pubsub,
    //         "/mintlayer/sync/" => ProtocolType::Sync,
    //         _ => return None,
    //     };
    // }

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
    // TODO: Iterate instead of parsing?..
    // let protocols: HashSet<&str> = protocols.into_iter().map(|p| p.as_ref()).collect();
    //
    // let mut result = HashSet::new();
    //
    // if protocols.contains("/meshsub/1.0.0") && protocols.contains("/meshsub/1.1.0") {
    //     todo!();
    // }

    /*
        "/meshsub/1.1.0",
       "/meshsub/1.0.0",
       "/ipfs/ping/1.0.0",
       "/ipfs/id/1.0.0",
       "/ipfs/id/push/1.0.0",
       "/mintlayer/sync/0.1.0",
    */
    todo!();
    todo!();

    //result
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    // #[test]
    // fn from_str() {
    //     let data = [
    //         ("/meshsub/1.1.0", ProtocolType::Pubsub, SemVer::new(1, 1, 0)),
    //         ("/ipfs/ping/2.3.4", ProtocolType::Ping, SemVer::new(2, 3, 4)),
    //         ("/ipfs/id/1.0.0", ProtocolType::Ping, SemVer::new(2, 3, 4)),
    //         (
    //             "/ipfs/id/push/1.0.0",
    //             ProtocolType::Ping,
    //             SemVer::new(2, 3, 4),
    //         ),
    //         (
    //             "/mintlayer/sync/0.1.0",
    //             ProtocolType::Sync,
    //             SemVer::new(0, 1, 0),
    //         ),
    //     ];
    //
    //     for (str, protocol, version) in data {
    //         let actual = Protocol::from_str(str).unwrap();
    //         assert_eq!(actual.protocol, protocol);
    //         assert_eq!(actual.version, version);
    //     }
    // }

    #[test]
    fn FIXME_parse_protocols() {
        todo!();
        todo!();
        parse_protocols(["aaa", "bbb"]);
    }
}
