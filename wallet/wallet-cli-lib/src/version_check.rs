// Copyright (c) 2026 RBB S.r.l
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

/// Try parsing the version (which is supposed to come from the node, wallet-rpc-daemon or wallet-cli)
/// as a semver, and remove its build info (which is supposed to contain the Git commit hash).
/// If not parsable, return it as is.
pub fn parse_version_without_metadata(ver_str: &str) -> ParsedVersion {
    let ver_str = if let Some(space_pos) = ver_str.find(" ") {
        // In 1.2.1 and earlier, the wallet RPC `version` method would return a "pretty" version
        // string, e.g. "1.2.1 (HEAD hash: 22561ab99df5bbff5c545f58c05cbe7b8712d8c5)".
        // Handle this case explicitly to produce a nicer warning on version mismatch.
        #[allow(clippy::string_slice)]
        &ver_str[0..space_pos]
    } else {
        ver_str
    };

    if let Ok(ver) = semver::Version::parse(ver_str) {
        ParsedVersion::Semver(without_metadata(ver))
    } else {
        ParsedVersion::NonSemver(ver_str.to_owned())
    }
}

#[derive(Eq, PartialEq, Debug, derive_more::Display)]
pub enum ParsedVersion {
    #[display("{_0}")]
    Semver(semver::Version),

    // Note: normally, this variant should never be constructed, we have it "just in case".
    #[display("{_0}")]
    NonSemver(String),
}

fn without_metadata(mut ver: semver::Version) -> semver::Version {
    ver.build = semver::BuildMetadata::EMPTY;
    ver
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_version() {
        let ver_str = "1.2.3-foo+bar";
        let ver = parse_version_without_metadata(ver_str);
        let expected_ver = ParsedVersion::Semver(semver::Version {
            major: 1,
            minor: 2,
            patch: 3,
            pre: semver::Prerelease::new("foo").unwrap(),
            build: semver::BuildMetadata::EMPTY,
        });
        assert_eq!(ver, expected_ver);

        let ver_str = "1.2.3 (HEAD hash: 22561ab99df5bbff5c545f58c05cbe7b8712d8c5)";
        let ver = parse_version_without_metadata(ver_str);
        let expected_ver = ParsedVersion::Semver(semver::Version {
            major: 1,
            minor: 2,
            patch: 3,
            pre: semver::Prerelease::EMPTY,
            build: semver::BuildMetadata::EMPTY,
        });
        assert_eq!(ver, expected_ver);

        let ver_str = "foobar";
        let ver = parse_version_without_metadata(ver_str);
        let expected_ver = ParsedVersion::NonSemver("foobar".to_owned());
        assert_eq!(ver, expected_ver);
    }

    #[test]
    fn parsed_version_to_str() {
        let ver = ParsedVersion::Semver(semver::Version {
            major: 1,
            minor: 2,
            patch: 3,
            pre: semver::Prerelease::new("foo").unwrap(),
            build: semver::BuildMetadata::EMPTY,
        });
        let ver_str = ver.to_string();
        assert_eq!(ver_str, "1.2.3-foo");

        let ver = ParsedVersion::NonSemver("foobar".to_owned());
        let ver_str = ver.to_string();
        assert_eq!(ver_str, "foobar");
    }
}
