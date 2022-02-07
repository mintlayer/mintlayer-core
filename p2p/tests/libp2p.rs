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
#![cfg(not(loom))]
#![allow(unused)]
extern crate test_utils;

use common::{chain::config, sync::Arc};
use libp2p::Multiaddr;
use p2p::{
    net::{
        self,
        libp2p::{Libp2pService, Libp2pStrategy},
        Event, NetworkService,
    },
    P2P,
};

// verify that libp2p mdns peer discovery works
// #[tokio::test(flavor = "multi_thread")]
// async fn test_libp2p_peer_discovery() {
//     let config = Arc::new(config::create_mainnet());
//     let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
//     let mut serv = Libp2pService::new(addr.clone(), &[Libp2pStrategy::MulticastDns], &[])
//         .await
//         .unwrap();

//     tokio::spawn(async move {
//         let mut p2p = P2P::<Libp2pService>::new(256, 32, addr, Arc::clone(&config)).await.unwrap();
//         let _ = p2p.run().await;
//     });

//     loop {
//         // let serv_res: Event<Libp2pService> = serv.poll_next().await.unwrap();
//         // match serv_res {
//         //     Event::PeerDiscovered(peers) => {
//         //         assert_eq!(peers.0.len(), 1);

//         //         let addrs = &peers.0.iter().next().unwrap().1;
//         //         assert_eq!(addrs.len(), 2);

//         //         assert!(matches!(
//         //             addrs[0],
//         //             net::Address::Ip4(_) | net::Address::Ip6(_)
//         //         ));
//         //         assert!(matches!(
//         //             addrs[1],
//         //             net::Address::Ip4(_) | net::Address::Ip6(_)
//         //         ));
//         //         return;
//         //     }
//         //     e => panic!("unexpected event: {:?}", e),
//         // }
//     }
// }
