// Copyright (c) 2021-2024 RBB S.r.l
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
    collections::BTreeSet,
    net::{Ipv4Addr, Ipv6Addr},
};

use test_utils::assert_matches;

use super::*;

#[test]
fn network_address_printing_parsing() {
    // Domain name
    let addr: NetworkAddress = "bogus".parse().unwrap();
    assert_eq!(addr, NetworkAddress::Domain(DomainName("bogus".to_owned())));
    assert_eq!(addr.to_string(), "bogus");

    // Domain name part of which looks like an ip address.
    let addr: NetworkAddress = "1.2.3.4.com".parse().unwrap();
    assert_eq!(
        addr,
        NetworkAddress::Domain(DomainName("1.2.3.4.com".to_owned()))
    );
    assert_eq!(addr.to_string(), "1.2.3.4.com");

    // Ipv4 address.
    let addr: NetworkAddress = "1.2.3.4".parse().unwrap();
    assert_eq!(
        addr,
        NetworkAddress::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
    );
    assert_eq!(addr.to_string(), "1.2.3.4");

    // Ipv6 address.
    let addr: NetworkAddress = "1:2:3:4:5:6:7:8".parse().unwrap();
    assert_eq!(
        addr,
        NetworkAddress::Ip(IpAddr::V6(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8)))
    );
    assert_eq!(addr.to_string(), "1:2:3:4:5:6:7:8");

    // Some garbage.
    let err = "!@#$%^".parse::<NetworkAddress>().unwrap_err();
    assert_eq!(
        err,
        NetworkAddressParseError::NotIpAddressOrDomainName("!@#$%^".to_owned())
    );

    // "Ipv6 address in brackets" (without a port) is not a valid address or domain name.
    let err = "[1:2:3:4:5:6:7:8]".parse::<NetworkAddress>().unwrap_err();
    assert_eq!(
        err,
        NetworkAddressParseError::NotIpAddressOrDomainName("[1:2:3:4:5:6:7:8]".to_owned())
    );
}

// Printing/parsing of NetworkAddressWithOptionalPort when the port is missing.
#[test]
fn network_address_with_optional_port_printing_parsing_no_port() {
    // Domain name
    let addr: NetworkAddressWithOptionalPort = "bogus".parse().unwrap();
    assert_eq!(
        addr,
        NetworkAddress::Domain(DomainName("bogus".to_owned())).into()
    );
    assert_eq!(addr.to_string(), "bogus");

    // Ipv4 address.
    let addr: NetworkAddressWithOptionalPort = "1.2.3.4".parse().unwrap();
    assert_eq!(
        addr,
        NetworkAddress::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))).into()
    );
    assert_eq!(addr.to_string(), "1.2.3.4");

    // Ipv6 address.
    let addr: NetworkAddressWithOptionalPort = "1:2:3:4:5:6:7:8".parse().unwrap();
    assert_eq!(
        addr,
        NetworkAddress::Ip(IpAddr::V6(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8))).into()
    );
    assert_eq!(addr.to_string(), "1:2:3:4:5:6:7:8");

    // Some garbage.
    let err = "!@#$%^".parse::<NetworkAddressWithOptionalPort>().unwrap_err();
    assert_eq!(
        err,
        NetworkAddressParseError::NotIpAddressOrDomainName("!@#$%^".to_owned())
    );

    // "Ipv6 address in brackets" (without a port) is not a valid address or domain name.
    let err = "[1:2:3:4:5:6:7:8]".parse::<NetworkAddressWithOptionalPort>().unwrap_err();
    assert_eq!(
        err,
        NetworkAddressParseError::BadPortNumber("8]".to_owned())
    );
}

// Printing/parsing of NetworkAddressWithOptionalPort when the port is present.
#[test]
fn network_address_with_optional_port_printing_parsing_with_port() {
    // Domain name
    let addr: NetworkAddressWithOptionalPort = "bogus:123".parse().unwrap();
    assert_eq!(
        addr,
        NetworkAddressWithOptionalPort {
            address: NetworkAddress::Domain(DomainName("bogus".to_owned())),
            port: Some(123)
        }
    );
    assert_eq!(addr.to_string(), "bogus:123");

    // Domain name with a bad port
    let err = "bogus:foo".parse::<NetworkAddressWithOptionalPort>().unwrap_err();
    assert_eq!(
        err,
        NetworkAddressParseError::BadPortNumber("foo".to_owned())
    );

    // Domain name with a port out of range
    let err = "bogus:65536".parse::<NetworkAddressWithOptionalPort>().unwrap_err();
    assert_eq!(
        err,
        NetworkAddressParseError::BadPortNumber("65536".to_owned())
    );

    // Ipv4 address.
    let addr: NetworkAddressWithOptionalPort = "1.2.3.4:123".parse().unwrap();
    assert_eq!(
        addr,
        NetworkAddressWithOptionalPort {
            address: NetworkAddress::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            port: Some(123)
        }
    );
    assert_eq!(addr.to_string(), "1.2.3.4:123");

    // Ipv4 address with a bad port
    let err = "1.2.3.4:foo".parse::<NetworkAddressWithOptionalPort>().unwrap_err();
    assert_eq!(
        err,
        NetworkAddressParseError::BadPortNumber("foo".to_owned())
    );

    // Ipv4 address with a port out of range
    let err = "1.2.3.4:65536".parse::<NetworkAddressWithOptionalPort>().unwrap_err();
    assert_eq!(
        err,
        NetworkAddressParseError::BadPortNumber("65536".to_owned())
    );

    // Ipv6 address.
    let addr: NetworkAddressWithOptionalPort = "[1:2:3:4:5:6:7:8]:123".parse().unwrap();
    assert_eq!(
        addr,
        NetworkAddressWithOptionalPort {
            address: NetworkAddress::Ip(IpAddr::V6(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8))),
            port: Some(123)
        }
    );
    assert_eq!(addr.to_string(), "[1:2:3:4:5:6:7:8]:123");

    // Ipv6 address with a bad port
    let err = "[1:2:3:4:5:6:7:8]:foo".parse::<NetworkAddressWithOptionalPort>().unwrap_err();
    assert_eq!(
        err,
        NetworkAddressParseError::BadPortNumber("foo".to_owned())
    );

    // Ipv6 address with a port out of range
    let err = "[1:2:3:4:5:6:7:8]:65536".parse::<NetworkAddressWithOptionalPort>().unwrap_err();
    assert_eq!(
        err,
        NetworkAddressParseError::BadPortNumber("65536".to_owned())
    );
}

// Parsing into NetworkAddressWithPort when no port is specified.
// Should fail with MissingPortNumber unless something is wrong with the address part itself.
#[test]
fn network_address_with_port_parsing_no_port() {
    // Domain name
    let err = "bogus".parse::<NetworkAddressWithPort>().unwrap_err();
    assert_eq!(
        err,
        NetworkAddressParseError::MissingPortNumber("bogus".to_owned())
    );

    // Ipv4 address.
    let err = "1.2.3.4".parse::<NetworkAddressWithPort>().unwrap_err();
    assert_eq!(
        err,
        NetworkAddressParseError::MissingPortNumber("1.2.3.4".to_owned())
    );

    // Ipv6 address.
    let err = "1:2:3:4:5:6:7:8".parse::<NetworkAddressWithPort>().unwrap_err();
    assert_eq!(
        err,
        NetworkAddressParseError::MissingPortNumber("1:2:3:4:5:6:7:8".to_owned())
    );

    // Some garbage.
    let err = "!@#$%^".parse::<NetworkAddressWithPort>().unwrap_err();
    assert_eq!(
        err,
        NetworkAddressParseError::NotIpAddressOrDomainName("!@#$%^".to_owned())
    );

    // "Ipv6 address in brackets" (without a port) is not a valid address or domain name.
    let err = "[1:2:3:4:5:6:7:8]".parse::<NetworkAddressWithPort>().unwrap_err();
    assert_eq!(
        err,
        NetworkAddressParseError::BadPortNumber("8]".to_owned())
    );
}

// Printing/parsing of NetworkAddressWithPort when the port is present.
#[test]
fn network_address_with_port_printing_parsing_with_port() {
    // Domain name
    let addr: NetworkAddressWithPort = "bogus:123".parse().unwrap();
    assert_eq!(
        addr,
        NetworkAddressWithPort {
            address: NetworkAddress::Domain(DomainName("bogus".to_owned())),
            port: 123
        }
    );
    assert_eq!(addr.to_string(), "bogus:123");

    // Domain name with a bad port
    let err = "bogus:foo".parse::<NetworkAddressWithPort>().unwrap_err();
    assert_eq!(
        err,
        NetworkAddressParseError::BadPortNumber("foo".to_owned())
    );

    // Domain name with a port out of range
    let err = "bogus:65536".parse::<NetworkAddressWithPort>().unwrap_err();
    assert_eq!(
        err,
        NetworkAddressParseError::BadPortNumber("65536".to_owned())
    );

    // Ipv4 address.
    let addr: NetworkAddressWithPort = "1.2.3.4:123".parse().unwrap();
    assert_eq!(
        addr,
        NetworkAddressWithPort {
            address: NetworkAddress::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            port: 123
        }
    );
    assert_eq!(addr.to_string(), "1.2.3.4:123");

    // Ipv4 address with a bad port
    let err = "1.2.3.4:foo".parse::<NetworkAddressWithPort>().unwrap_err();
    assert_eq!(
        err,
        NetworkAddressParseError::BadPortNumber("foo".to_owned())
    );

    // Ipv4 address with a port out of range
    let err = "1.2.3.4:65536".parse::<NetworkAddressWithPort>().unwrap_err();
    assert_eq!(
        err,
        NetworkAddressParseError::BadPortNumber("65536".to_owned())
    );

    // Ipv6 address.
    let addr: NetworkAddressWithPort = "[1:2:3:4:5:6:7:8]:123".parse().unwrap();
    assert_eq!(
        addr,
        NetworkAddressWithPort {
            address: NetworkAddress::Ip(IpAddr::V6(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8))),
            port: 123
        }
    );
    assert_eq!(addr.to_string(), "[1:2:3:4:5:6:7:8]:123");

    // Ipv6 address with a bad port
    let err = "[1:2:3:4:5:6:7:8]:foo".parse::<NetworkAddressWithPort>().unwrap_err();
    assert_eq!(
        err,
        NetworkAddressParseError::BadPortNumber("foo".to_owned())
    );

    // Ipv6 address with a port out of range
    let err = "[1:2:3:4:5:6:7:8]:65536".parse::<NetworkAddressWithPort>().unwrap_err();
    assert_eq!(
        err,
        NetworkAddressParseError::BadPortNumber("65536".to_owned())
    );
}

#[tokio::test]
async fn network_address_resolution() {
    // Resolving a non-existent domain name should fail.
    let addr: NetworkAddress = "bogus".parse().unwrap();
    let err = addr.resolve().await.err().unwrap();
    assert_matches!(
        err,
        NameResolutionError::CannotResolve {
            resolvable_name,
            error_str: _
        } if resolvable_name == "bogus"
    );

    let localhost_v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let localhost_v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let localhosts = [localhost_v4, localhost_v6].into_iter().collect::<BTreeSet<_>>();

    // Resolving an existing domain should succeed.
    let addr: NetworkAddress = "localhost".parse().unwrap();
    let result = addr.resolve().await.unwrap().collect::<BTreeSet<_>>();
    // Note: "localhost" may resolve to either v4 or v6 localhost, or to both.
    assert!(!result.is_empty());
    assert_eq!(
        result.union(&localhosts).copied().collect::<BTreeSet<_>>(),
        localhosts
    );

    // "Resolving" an ip address should just return the address.
    let addr = NetworkAddress::Ip(localhost_v4);
    let result = addr.resolve().await.unwrap().collect::<Vec<_>>();
    assert_eq!(result, &[localhost_v4]);
}
