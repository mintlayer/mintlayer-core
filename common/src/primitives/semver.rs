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

use std::str::FromStr;

use serde::Serialize;
use serialization::{Decode, Encode};

// Note: this is not a real "semantic version" because it lacks the prerelease and build metadata
// parts. However it's not easy to change, since it's part of the p2p protocol, namely the Hello
// and HelloAck messages (also, it's probably not a good idea to send the additional info over
// the network anyway).
// TODO: perhaps it should be renamed at least.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, Copy, Clone, Serialize)]
pub struct SemVer {
    pub major: u8,
    pub minor: u8,
    pub patch: u16,
}

impl SemVer {
    pub const fn new(major: u8, minor: u8, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl FromStr for SemVer {
    type Err = &'static str;

    fn from_str(v: &str) -> Result<SemVer, Self::Err> {
        let split_version = v.split('.').collect::<Vec<_>>();
        if split_version.len() != 3 {
            return Err("Invalid version. Number of components is wrong.");
        }

        let parse_err: &'static str = "Parsing SemVer component to integer failed";
        let major = split_version[0].parse::<u8>().map_err(|_| parse_err)?;
        let minor = split_version[1].parse::<u8>().map_err(|_| parse_err)?;
        let patch = split_version[2].parse::<u16>().map_err(|_| parse_err)?;

        Ok(Self {
            major,
            minor,
            patch,
        })
    }
}

impl std::fmt::Display for SemVer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// TODO: this is redundant, but it's still used inside a macro in `regtest_chain_config_builder`.
// Refactor the macro and remove this.
impl TryFrom<String> for SemVer {
    type Error = <SemVer as FromStr>::Err;

    fn try_from(v: String) -> Result<SemVer, Self::Error> {
        Self::from_str(v.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serialization::DecodeAll;

    #[test]
    fn vertest_string() {
        let version = SemVer::new(1, 2, 3);
        assert_eq!(version.to_string(), "1.2.3");

        let version = SemVer::new(0xff, 0xff, 0xff);
        assert_eq!(version.to_string(), "255.255.255");

        let version = SemVer::new(0xff, 0xff, 0xffff);
        assert_eq!(version.to_string(), "255.255.65535");

        let version = SemVer::new(1, 2, 0x500);
        assert_eq!(version.to_string(), "1.2.1280");

        assert_eq!(
            SemVer::from_str(" "),
            Err("Invalid version. Number of components is wrong.")
        );

        assert_eq!(
            SemVer::from_str(""),
            Err("Invalid version. Number of components is wrong.")
        );

        assert_eq!(
            SemVer::from_str("1.2"),
            Err("Invalid version. Number of components is wrong.")
        );

        assert_eq!(
            SemVer::from_str("1"),
            Err("Invalid version. Number of components is wrong.")
        );

        let version = "hello";
        assert_eq!(
            SemVer::from_str(version),
            Err("Invalid version. Number of components is wrong.")
        );
        assert_eq!(
            SemVer::from_str(version),
            Err("Invalid version. Number of components is wrong.")
        );

        let version = "1.2.3";
        assert_eq!(SemVer::from_str(version), Ok(SemVer::new(1, 2, 3)));
        assert_eq!(
            SemVer::try_from(version.to_owned()),
            Ok(SemVer::new(1, 2, 3))
        );

        let version = "255.255.255";
        assert_eq!(SemVer::from_str(version), Ok(SemVer::new(255, 255, 255)));
        assert_eq!(
            SemVer::try_from(version.to_owned()),
            Ok(SemVer::new(255, 255, 255))
        );

        let version = "255.255.65535";
        assert_eq!(SemVer::from_str(version), Ok(SemVer::new(255, 255, 65535)));
        assert_eq!(
            SemVer::try_from(version.to_owned()),
            Ok(SemVer::new(255, 255, 65535))
        );

        let version = "255.255.65536";
        assert_eq!(
            SemVer::from_str(version),
            Err("Parsing SemVer component to integer failed")
        );
        assert_eq!(
            SemVer::try_from(version.to_owned()),
            Err("Parsing SemVer component to integer failed")
        );

        assert_eq!(
            SemVer::from_str("1.2.a"),
            Err("Parsing SemVer component to integer failed")
        );

        assert_eq!(
            SemVer::from_str("1.2."),
            Err("Parsing SemVer component to integer failed")
        );

        assert_eq!(
            SemVer::from_str("1..3"),
            Err("Parsing SemVer component to integer failed")
        );
    }

    #[test]
    fn vertest_encode_decode() {
        let encoded = SemVer::new(1, 2, 3).encode();
        assert_eq!(
            DecodeAll::decode_all(&mut &encoded[..]),
            Ok(SemVer::new(1, 2, 3))
        );

        let encoded = SemVer::new(0xff, 0xff, 0xff).encode();
        assert_eq!(
            DecodeAll::decode_all(&mut &encoded[..]),
            Ok(SemVer::new(0xff, 0xff, 0xff))
        );

        let encoded = SemVer::new(0xff, 0xff, 0xffff).encode();
        assert_eq!(
            DecodeAll::decode_all(&mut &encoded[..]),
            Ok(SemVer::new(0xff, 0xff, 0xffff))
        );

        let encoded = SemVer::new(1, 2, 0x500).encode();
        assert_eq!(
            DecodeAll::decode_all(&mut &encoded[..]),
            Ok(SemVer::new(1, 2, 0x500))
        );
    }

    #[test]
    fn ordering() {
        assert!(SemVer::new(0, 0, 0) < SemVer::new(0, 0, 1));
        assert!(SemVer::new(0, 0, u16::MAX) < SemVer::new(0, 1, 0));
        assert!(SemVer::new(0, 1, 0) < SemVer::new(0, 1, 1));
        assert!(SemVer::new(0, u8::MAX, 0) < SemVer::new(1, 0, 1));
        assert!(SemVer::new(0, u8::MAX, u16::MAX) < SemVer::new(1, 0, 1));
        assert!(SemVer::new(1, 0, 0) < SemVer::new(1, 0, 1));
        assert!(SemVer::new(1, 0, 1) < SemVer::new(1, 1, 0));
        assert!(SemVer::new(1, u8::MAX, u16::MAX) < SemVer::new(2, 0, 0));
    }
}
