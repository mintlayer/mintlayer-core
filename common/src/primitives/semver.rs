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
//
// Author(s): A. Altonen

use serialization::{Decode, Encode};

#[derive(Debug, PartialEq, Eq, Encode, Decode, Copy, Clone)]
pub struct SemVer {
    pub major: u8,
    pub minor: u8,
    pub patch: u16,
}

impl SemVer {
    pub fn new(major: u8, minor: u8, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl From<SemVer> for String {
    fn from(v: SemVer) -> String {
        format!("{}.{}.{}", v.major, v.minor, v.patch)
    }
}

impl TryFrom<&str> for SemVer {
    type Error = &'static str;

    fn try_from(v: &str) -> Result<SemVer, Self::Error> {
        match sscanf::scanf!(v, "{}.{}.{}", u8, u8, u16) {
            Err(_) => Err("String does not contain SemVer"),
            Ok((ma, mi, pa)) => Ok(SemVer::new(ma, mi, pa)),
        }
    }
}

impl TryFrom<String> for SemVer {
    type Error = &'static str;

    fn try_from(v: String) -> Result<SemVer, Self::Error> {
        match sscanf::scanf!(v, "{}.{}.{}", u8, u8, u16) {
            Err(_) => Err("String does not contain SemVer"),
            Ok((ma, mi, pa)) => Ok(SemVer::new(ma, mi, pa)),
        }
    }
}

impl std::fmt::Display for SemVer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vertest_string() {
        let version = SemVer::new(1, 2, 3);
        assert_eq!(String::from(version), "1.2.3");

        let version = SemVer::new(0xff, 0xff, 0xff);
        assert_eq!(String::from(version), "255.255.255");

        let version = SemVer::new(0xff, 0xff, 0xffff);
        assert_eq!(String::from(version), "255.255.65535");

        let version = SemVer::new(1, 2, 0x500);
        assert_eq!(String::from(version), "1.2.1280");

        let version = "hello";
        assert_eq!(
            SemVer::try_from(version),
            Err("String does not contain SemVer")
        );
        assert_eq!(
            SemVer::try_from(version),
            Err("String does not contain SemVer")
        );

        let version = "1.2.3".to_string();
        assert_eq!(SemVer::try_from(version.clone()), Ok(SemVer::new(1, 2, 3)));
        assert_eq!(SemVer::try_from(version), Ok(SemVer::new(1, 2, 3)));

        let version = "255.255.255";
        assert_eq!(SemVer::try_from(version), Ok(SemVer::new(255, 255, 255)));
        assert_eq!(SemVer::try_from(version), Ok(SemVer::new(255, 255, 255)));

        let version = "255.255.65535".to_string();
        assert_eq!(
            SemVer::try_from(version.clone()),
            Ok(SemVer::new(255, 255, 65535))
        );
        assert_eq!(SemVer::try_from(version), Ok(SemVer::new(255, 255, 65535)));

        let version = "255.255.65536";
        assert_eq!(
            SemVer::try_from(version),
            Err("String does not contain SemVer")
        );
        assert_eq!(
            SemVer::try_from(version.to_string()),
            Err("String does not contain SemVer")
        );
    }

    #[test]
    fn vertest_encode_decode() {
        let encoded = SemVer::new(1, 2, 3).encode();
        assert_eq!(Decode::decode(&mut &encoded[..]), Ok(SemVer::new(1, 2, 3)));

        let encoded = SemVer::new(0xff, 0xff, 0xff).encode();
        assert_eq!(
            Decode::decode(&mut &encoded[..]),
            Ok(SemVer::new(0xff, 0xff, 0xff))
        );

        let encoded = SemVer::new(0xff, 0xff, 0xffff).encode();
        assert_eq!(
            Decode::decode(&mut &encoded[..]),
            Ok(SemVer::new(0xff, 0xff, 0xffff))
        );

        let encoded = SemVer::new(1, 2, 0x500).encode();
        assert_eq!(
            Decode::decode(&mut &encoded[..]),
            Ok(SemVer::new(1, 2, 0x500))
        );
    }
}
