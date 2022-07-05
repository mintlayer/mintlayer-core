// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): A. Altonen

//! Multicast DNS (mDNS) discovery behaviour for the libp2p backend

use libp2p::{
    mdns,
    swarm::{
        NetworkBehaviour as SwarmNetworkBehaviour,
        NetworkBehaviourAction, PollParameters,
    },
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
    pub async fn new(enabled: bool) -> Self {
        if enabled {
            match mdns::Mdns::new(Default::default()).await {
                Ok(mdns) => Mdns::Enabled(Box::new(mdns)),
                Err(err) => {
                    log::error!("Failed to initialize mDNS: {:?}", err);
                    Mdns::Disabled
                }
            }
        } else {
            Mdns::Disabled
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
    use std::{future::Future, pin::Pin, task::Waker};

    #[tokio::test]
    async fn mdns_disabled() {
        let mdns = Mdns::new(false).await;
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

        tokio::spawn(async move {
            let mut tester2 = MdnsTester {
                mdns: Mdns::new(true).await,
                poll_params: TestParams {
                    peer_id: PeerId::random(),
                    addr: "/ip6/::1/tcp/8888".parse().unwrap(),
                },
            };

            if let NetworkBehaviourAction::GenerateEvent(mdns::MdnsEvent::Discovered(addrs)) =
                tester2.await
            {
                assert!(addrs
                    .map(|(_peer_id, addr)| addr)
                    .any(|addr| addr == "/ip6/::1/tcp/9999".parse().unwrap()));
            } else {
                panic!("invalid event received")
            }
        });

        let mut tester = MdnsTester {
            mdns: Mdns::new(true).await,
            poll_params: TestParams {
                peer_id: PeerId::random(),
                addr: "/ip6/::1/tcp/9999".parse().unwrap(),
            },
        };
        assert!(std::matches!(tester.mdns, Mdns::Enabled(_)));

        if let NetworkBehaviourAction::GenerateEvent(mdns::MdnsEvent::Discovered(addrs)) =
            tester.await
        {
            assert!(addrs
                .map(|(_peer_id, addr)| addr)
                .any(|addr| addr == "/ip6/::1/tcp/8888".parse().unwrap()));
        } else {
            panic!("invalid event received")
        }
    }
}
