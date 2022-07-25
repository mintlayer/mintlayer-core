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

use libp2p::multiaddr::Protocol;
use p2p::net::{
    libp2p::{Libp2pDiscoveryStrategy, Libp2pService},
    types::ConnectivityEvent,
    ConnectivityService, NetworkingService,
};
use p2p_test_utils::make_libp2p_addr;
use std::sync::Arc;

// verify that libp2p mdns peer discovery works
#[tokio::test]
async fn test_libp2p_peer_discovery() {
    let config = Arc::new(common::chain::config::create_mainnet());
    let (mut serv, _, _) = Libp2pService::start(
        make_libp2p_addr(),
        &[Libp2pDiscoveryStrategy::MulticastDns],
        Arc::clone(&config),
        std::time::Duration::from_secs(10),
    )
    .await
    .unwrap();

    let (mut serv2, _, _) = Libp2pService::start(
        make_libp2p_addr(),
        &[Libp2pDiscoveryStrategy::MulticastDns],
        Arc::clone(&config),
        std::time::Duration::from_secs(10),
    )
    .await
    .unwrap();

    loop {
        let (serv_res, _) = tokio::join!(serv.poll_next(), serv2.poll_next());

        match serv_res.unwrap() {
            ConnectivityEvent::Discovered { peers } => {
                assert!(!peers.is_empty());

                // verify that all discovered addresses are either ipv4 or ipv6,
                // they have tcp as the transport protocol and that all end with the peer id
                for peer in peers {
                    for addr in peer.ip6.iter().chain(peer.ip4.iter()) {
                        let mut components = addr.iter();
                        assert!(matches!(
                            components.next(),
                            Some(Protocol::Ip6(_) | Protocol::Ip4(_))
                        ));
                        assert!(matches!(components.next(), Some(Protocol::Tcp(_))));
                        assert!(matches!(components.next(), Some(Protocol::P2p(_))));
                    }
                }

                return;
            }
            e => panic!("unexpected event: {:?}", e),
        }
    }
}
