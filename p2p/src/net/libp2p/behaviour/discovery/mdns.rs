// Copyright (c) 2022 RBB S.r.l
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

//! Multicast DNS (mDNS) discovery behaviour for the libp2p backend

use crate::config;
use libp2p::{
    core::connection::{ConnectedPoint, ConnectionId},
    mdns,
    swarm::{
        handler::DummyConnectionHandler, NetworkBehaviour as SwarmNetworkBehaviour,
        NetworkBehaviourAction, PollParameters,
    },
    PeerId,
};
use logging::log;
use std::task::{Context, Poll};

pub enum Mdns {
    /// mDNS has been enabled
    Enabled(Box<mdns::Mdns>),

    /// mDNS has been disabled
    Disabled,
}

impl Mdns {
    pub async fn new(config: &config::MdnsConfig) -> Self {
        match config {
            config::MdnsConfig::Enabled {
                query_interval,
                enable_ipv6_mdns_discovery,
            } => {
                match mdns::Mdns::new(mdns::MdnsConfig {
                    ttl: Default::default(),
                    query_interval: std::time::Duration::from_millis(**query_interval),
                    enable_ipv6: **enable_ipv6_mdns_discovery,
                })
                .await
                {
                    Ok(mdns) => Mdns::Enabled(Box::new(mdns)),
                    Err(err) => {
                        log::error!("Failed to initialize mDNS: {:?}", err);
                        Mdns::Disabled
                    }
                }
            }
            config::MdnsConfig::Disabled => Mdns::Disabled,
        }
    }

    pub fn inject_connection_closed(
        &mut self,
        peer_id: &PeerId,
        connection_id: &ConnectionId,
        endpoint: &ConnectedPoint,
        event: DummyConnectionHandler,
        remaining_established: usize,
    ) {
        if let Mdns::Enabled(mdns) = self {
            mdns.inject_connection_closed(
                peer_id,
                connection_id,
                endpoint,
                event,
                remaining_established,
            );
        }
    }

    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        params: &mut impl PollParameters,
    ) -> Poll<
        NetworkBehaviourAction<
            mdns::MdnsEvent,
            <mdns::Mdns as SwarmNetworkBehaviour>::ConnectionHandler,
        >,
    > {
        match self {
            Mdns::Disabled => Poll::Pending,
            Mdns::Enabled(mdns) => mdns.poll(cx, params),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::{swarm::AddressRecord, Multiaddr, PeerId};
    use std::{future::Future, pin::Pin};

    #[tokio::test]
    async fn mdns_disabled() {
        let mdns = Mdns::new(&config::MdnsConfig::default()).await;
        assert!(std::matches!(mdns, Mdns::Disabled));
    }

    #[tokio::test]
    async fn mdns_enabled() {
        struct MdnsTester {
            mdns: Mdns,
            poll_params: TestParams,
        }

        impl Future for MdnsTester {
            type Output = NetworkBehaviourAction<
                mdns::MdnsEvent,
                <mdns::Mdns as SwarmNetworkBehaviour>::ConnectionHandler,
            >;

            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let mut poll_params = self.poll_params.clone();
                self.mdns.poll(cx, &mut poll_params)
            }
        }

        #[derive(Clone)]
        struct TestParams {
            peer_id: PeerId,
            addr: Multiaddr,
        }

        impl PollParameters for TestParams {
            type SupportedProtocolsIter = std::vec::IntoIter<Vec<u8>>;
            type ListenedAddressesIter = std::vec::IntoIter<Multiaddr>;
            type ExternalAddressesIter = std::vec::IntoIter<AddressRecord>;

            fn supported_protocols(&self) -> Self::SupportedProtocolsIter {
                vec![].into_iter()
            }

            fn listened_addresses(&self) -> Self::ListenedAddressesIter {
                vec![self.addr.clone()].into_iter()
            }

            fn external_addresses(&self) -> Self::ExternalAddressesIter {
                vec![].into_iter()
            }

            fn local_peer_id(&self) -> &PeerId {
                &self.peer_id
            }
        }

        let tester1 = MdnsTester {
            mdns: Mdns::new(&config::MdnsConfig::Enabled {
                query_interval: 200.into(),
                enable_ipv6_mdns_discovery: false.into(),
            })
            .await,
            poll_params: TestParams {
                peer_id: PeerId::random(),
                addr: "/ip6/::1/tcp/9999".parse().unwrap(),
            },
        };
        let tester2 = MdnsTester {
            mdns: Mdns::new(&config::MdnsConfig::Enabled {
                query_interval: 200.into(),
                enable_ipv6_mdns_discovery: false.into(),
            })
            .await,
            poll_params: TestParams {
                peer_id: PeerId::random(),
                addr: "/ip6/::1/tcp/8888".parse().unwrap(),
            },
        };
        assert!(std::matches!(tester1.mdns, Mdns::Enabled(_)));
        assert!(std::matches!(tester2.mdns, Mdns::Enabled(_)));

        tokio::select! {
            event = tester1 => match event {
                NetworkBehaviourAction::GenerateEvent(mdns::MdnsEvent::Discovered(addrs)) => {
                    assert_ne!(addrs.len(), 0);
                }
                _ => panic!("invalid event received: {:?}", event),
            },
            event = tester2 => match event {
                NetworkBehaviourAction::GenerateEvent(mdns::MdnsEvent::Discovered(addrs)) => {
                    assert_ne!(addrs.len(), 0);
                }
                _ => panic!("invalid event received: {:?}", event),
            }
        }
    }
}
