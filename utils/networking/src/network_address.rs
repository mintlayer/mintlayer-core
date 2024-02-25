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
    fmt::Display,
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use itertools::Either;
use serde_with::{DeserializeFromStr, SerializeDisplay};
use thiserror::Error;

use crate::{
    ip_or_socket_address::IpOrSocketAddress,
    resolvable_name::{NameResolutionError, ResolvableName},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainName(String);

impl Display for DomainName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for DomainName {
    type Err = DomainNameParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Note: the 'addr' crate also has the 'parse_dns_name' function, which considers
        // '[1:2:3:4:5:6:7:8]' to be a domain name.
        match addr::parse_domain_name(s) {
            Ok(_) => Ok(DomainName(s.to_owned())),
            Err(_) => Err(DomainNameParseError {
                erroneous_domain_name: s.to_owned(),
            }),
        }
    }
}

#[derive(Error, Debug)]
#[error("Not a domain name: '{erroneous_domain_name}'")]
pub struct DomainNameParseError {
    erroneous_domain_name: String,
}

impl ResolvableName for DomainName {
    type ResolvedAddress = IpAddr;

    async fn resolve(&self) -> Result<impl Iterator<Item = IpAddr> + '_, NameResolutionError> {
        // Note: for historical reasons, std::net::ToSocketAddrs, which is used internally
        // by tokio::net::lookup_host, expects a pair of (host, port) and resolves it to
        // SocketAddr, despite the fact that the port number is useless during name resolution.
        // So, we specify the fake port number 0 here and then ignore it in the result.
        Ok(tokio::net::lookup_host((self.0.as_str(), 0))
            .await
            .map_err(|error| NameResolutionError::CannotResolve {
                resolvable_name: self.0.clone(),
                error_str: error.to_string(),
            })?
            .map(|socket_addr| socket_addr.ip()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkAddress {
    Ip(IpAddr),
    Domain(DomainName),
}

impl NetworkAddress {
    pub fn as_ip_address(&self) -> Option<&IpAddr> {
        match self {
            Self::Ip(addr) => Some(addr),
            Self::Domain(_) => None,
        }
    }
}

impl ResolvableName for NetworkAddress {
    type ResolvedAddress = IpAddr;

    async fn resolve(
        &self,
    ) -> Result<impl Iterator<Item = Self::ResolvedAddress> + '_, NameResolutionError> {
        match self {
            Self::Ip(ip) => Ok(Either::Left(std::iter::once(*ip))),
            Self::Domain(domain_name) => Ok(Either::Right(domain_name.resolve().await?)),
        }
    }
}

impl FromStr for NetworkAddress {
    type Err = NetworkAddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(ip) = s.parse::<IpAddr>() {
            Ok(NetworkAddress::Ip(ip))
        } else {
            Ok(NetworkAddress::Domain(s.parse::<DomainName>()?))
        }
    }
}

impl Display for NetworkAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(addr) => {
                write!(f, "{addr}")
            }
            Self::Domain(domain_name) => {
                write!(f, "{domain_name}")
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkAddressWithPort {
    pub address: NetworkAddress,
    pub port: u16,
}

impl FromStr for NetworkAddressWithPort {
    type Err = NetworkAddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let addr_with_opt_port = s.parse::<NetworkAddressWithOptionalPort>()?;
        if let Some(port) = addr_with_opt_port.port {
            Ok(Self {
                address: addr_with_opt_port.address,
                port,
            })
        } else {
            Err(NetworkAddressParseError::MissingPortNumber(s.to_owned()))
        }
    }
}

impl Display for NetworkAddressWithPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write_addr_port(&self.address, Some(self.port), f)
    }
}

impl From<SocketAddr> for NetworkAddressWithPort {
    fn from(value: SocketAddr) -> Self {
        Self {
            address: NetworkAddress::Ip(value.ip()),
            port: value.port(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, DeserializeFromStr, SerializeDisplay)]
pub struct NetworkAddressWithOptionalPort {
    pub address: NetworkAddress,
    pub port: Option<u16>,
}

impl ResolvableName for NetworkAddressWithOptionalPort {
    type ResolvedAddress = IpOrSocketAddress;

    async fn resolve(
        &self,
    ) -> Result<impl Iterator<Item = IpOrSocketAddress> + '_, NameResolutionError> {
        Ok(self.address.resolve().await?.map(|ip_addr| {
            if let Some(port) = self.port {
                IpOrSocketAddress::new_socket_address(SocketAddr::new(ip_addr, port))
            } else {
                IpOrSocketAddress::new_ip(ip_addr)
            }
        }))
    }
}

impl FromStr for NetworkAddressWithOptionalPort {
    type Err = NetworkAddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // With ipv6 addresses, finding the port separator is not super trivial, so we want
        // to delegate that work to SocketAddr's FromStr. But it won't consider something like
        // '1:2:3:4:5:6:7:8' as a valid ipv6 address, so try IpAddr's FromStr first.

        if let Ok(ip_addr) = s.parse::<IpAddr>() {
            return Ok(Self {
                address: NetworkAddress::Ip(ip_addr),
                port: None,
            });
        }

        if let Ok(socket_addr) = s.parse::<SocketAddr>() {
            return Ok(Self {
                address: NetworkAddress::Ip(socket_addr.ip()),
                port: Some(socket_addr.port()),
            });
        }

        let separator = ':';
        assert!(separator.is_ascii());
        let separator_len = 1;

        // Use rfind instead of find to produce better errors; e.g. for something like
        // '[1:2:3:4:5:6:7:8]:foo' we'd prefer the error 'BadPortNumber("foo")' instead of
        // 'BadPortNumber("2:3:4:5:6:7:8]:foo")'
        let separator_pos = s.rfind(separator);

        // Parse the port first, to produce a slightly more understandable error.
        // E.g. when parsing '[1:2:3:4:5:6:7:8]', which is not a valid address, we could produce
        // either 'NotIpAddressOrDomainName("[1")' or 'BadPortNumber("2:3:4:5:6:7:8]")'.
        // The former looks too cryptic, so we choose the latter.
        let port = if let Some(pos) = separator_pos {
            // Note: the position "pos + separator_len" is guaranteed to be at a character boundary.
            #[allow(clippy::string_slice)]
            let port_str = &s[pos + separator_len..];
            let port: u16 = port_str
                .parse()
                .map_err(|_| NetworkAddressParseError::BadPortNumber(port_str.to_owned()))?;
            Some(port)
        } else {
            None
        };

        // Note: the position "separator_pos" is guaranteed to be at a character boundary.
        #[allow(clippy::string_slice)]
        let addr_str = &s[..separator_pos.unwrap_or(s.len())];
        let address: NetworkAddress = addr_str.parse()?;

        Ok(Self { address, port })
    }
}

impl From<NetworkAddressWithPort> for NetworkAddressWithOptionalPort {
    fn from(value: NetworkAddressWithPort) -> Self {
        Self {
            address: value.address,
            port: Some(value.port),
        }
    }
}

impl Display for NetworkAddressWithOptionalPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write_addr_port(&self.address, self.port, f)
    }
}

impl From<NetworkAddress> for NetworkAddressWithOptionalPort {
    fn from(address: NetworkAddress) -> Self {
        Self {
            address,
            port: None,
        }
    }
}

fn write_addr_port(
    address: &NetworkAddress,
    port: Option<u16>,
    write_to: &mut impl std::fmt::Write,
) -> std::fmt::Result {
    if let Some(port) = port {
        if let Some(ip_addr) = address.as_ip_address() {
            // Handle printing brackets for ipv6 addresses by delegating the job to SocketAddr.
            write!(write_to, "{}", SocketAddr::new(*ip_addr, port))
        } else {
            write!(write_to, "{}:{}", address, port)
        }
    } else {
        write!(write_to, "{}", address)
    }
}

#[derive(Error, Debug, Eq, PartialEq)]
pub enum NetworkAddressParseError {
    #[error("Not an IP address or domain name: '{0}'")]
    NotIpAddressOrDomainName(String),
    #[error("Bad port number: '{0}'")]
    BadPortNumber(String),
    #[error("Port number is missing in '{0}'")]
    MissingPortNumber(String),
}

impl From<DomainNameParseError> for NetworkAddressParseError {
    fn from(value: DomainNameParseError) -> Self {
        Self::NotIpAddressOrDomainName(value.erroneous_domain_name)
    }
}

#[cfg(test)]
#[path = "network_address_tests.rs"]
mod tests;
