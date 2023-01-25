// Copyright 2021 Protocol Labs.
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

// Based on libp2p sources:
// https://github.com/libp2p/rust-libp2p/blob/73cbbe29679f5d56d81d5477d3796e82712f9ac2/protocols/autonat/src/behaviour.rs

pub trait IsGlobalIp {
    fn is_global_unicast_ip(&self) -> bool;
}

impl IsGlobalIp for std::net::Ipv4Addr {
    // NOTE: The below logic is based on `std::net::Ipv4Addr::is_global`,
    // which is at the time of writing behind the unstable `ip` feature.
    // See https://github.com/rust-lang/rust/issues/27709 for more info.
    fn is_global_unicast_ip(&self) -> bool {
        // Copied from the unstable method `std::net::Ipv4Addr::is_shared`.
        fn is_shared(addr: &std::net::Ipv4Addr) -> bool {
            addr.octets()[0] == 100 && (addr.octets()[1] & 0b1100_0000 == 0b0100_0000)
        }

        // Copied from the unstable method `std::net::Ipv4Addr::is_reserved`.
        fn is_reserved(addr: &std::net::Ipv4Addr) -> bool {
            addr.octets()[0] & 240 == 240 && !addr.is_broadcast()
        }

        // Copied from the unstable method `std::net::Ipv4Addr::is_benchmarking`.
        fn is_benchmarking(addr: &std::net::Ipv4Addr) -> bool {
            addr.octets()[0] == 198 && (addr.octets()[1] & 0xfe) == 18
        }

        // Addresses reserved for future protocols (`192.0.0.0/24`)
        fn is_future_protocol(addr: &std::net::Ipv4Addr) -> bool {
            addr.octets()[0] == 192 && addr.octets()[1] == 0 && addr.octets()[2] == 0
        }

        // The 0.0.0.0/8 block is reserved
        fn is_reserved2(addr: &std::net::Ipv4Addr) -> bool {
            addr.octets()[0] == 0
        }

        !self.is_multicast()
            && !self.is_private()
            && !self.is_loopback()
            && !self.is_link_local()
            && !self.is_broadcast()
            && !self.is_documentation()
            && !is_shared(self)
            && !is_future_protocol(self)
            && !is_reserved(self)
            && !is_benchmarking(self)
            && !is_reserved2(self)
    }
}

impl IsGlobalIp for std::net::Ipv6Addr {
    // NOTE: The below logic is based on `std::net::Ipv6Addr::is_global`,
    // which is at the time of writing behind the unstable `ip` feature.
    // See https://github.com/rust-lang/rust/issues/27709 for more info.
    fn is_global_unicast_ip(&self) -> bool {
        // Copied from the unstable method `std::net::Ipv6Addr::is_unicast_link_local`.
        fn is_unicast_link_local(addr: &std::net::Ipv6Addr) -> bool {
            (addr.segments()[0] & 0xffc0) == 0xfe80
        }
        // Copied from the unstable method `std::net::Ipv6Addr::is_unique_local`.
        fn is_unique_local(addr: &std::net::Ipv6Addr) -> bool {
            (addr.segments()[0] & 0xfe00) == 0xfc00
        }
        // Copied from the unstable method `std::net::Ipv6Addr::is_documentation`.
        fn is_documentation(addr: &std::net::Ipv6Addr) -> bool {
            (addr.segments()[0] == 0x2001) && (addr.segments()[1] == 0xdb8)
        }

        // Copied from the unstable method `std::net::Ipv6Addr::is_unicast_global`.
        !self.is_multicast()
            && !self.is_loopback()
            && !self.is_unspecified()
            && !is_unicast_link_local(self)
            && !is_unique_local(self)
            && !is_documentation(self)
    }
}

#[cfg(test)]
mod tests {
    use super::IsGlobalIp;

    fn is_global_unicast(ip: &str) -> bool {
        match ip.parse::<std::net::IpAddr>().unwrap() {
            std::net::IpAddr::V4(ip) => ip.is_global_unicast_ip(),
            std::net::IpAddr::V6(ip) => ip.is_global_unicast_ip(),
        }
    }

    #[test]
    fn test_addresses() {
        let global_unicast_ips = ["142.250.184.142", "2a00:1450:4017:815::200e"];

        let non_global_unicast_ips = [
            "0.0.0.0",             // Unspecified
            "255.255.255.255",     // Broadcast
            "127.0.0.0",           // Local
            "127.255.255.255",     // Local
            "10.0.0.0",            // Private
            "10.255.255.255",      // Private
            "100.64.0.0",          // Private
            "100.127.255.255",     // Private
            "172.16.0.0",          // Private
            "172.31.255.255",      // Private
            "192.168.0.0",         // Private
            "192.168.255.255",     // Private
            "169.254.1.0",         // Link-local
            "224.0.0.0",           // Multicast
            "239.255.255.255",     // Multicast
            "::",                  // Unspecified
            "::1",                 // Local
            "fd12:3456:789a:1::1", // Private
            "ff02::1",             // Multicast
        ];

        for ip in global_unicast_ips {
            assert!(
                is_global_unicast(ip),
                "{ip} is expected to be global unicast IP address"
            );
        }
        for ip in non_global_unicast_ips {
            assert!(
                !is_global_unicast(ip),
                "{ip} is expected to be not global unicast IP address"
            );
        }
    }
}
