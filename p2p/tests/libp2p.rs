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
extern crate test_utils;

use common::{chain::config, sync::Arc};
use libp2p::{multiaddr::Protocol, Multiaddr};
use p2p::{
    message::{self, ConnectivityMessage, MessageType},
    net::{
        self,
        libp2p::{Libp2pService, Libp2pStrategy},
        Event, FloodsubTopic, NetworkService,
    },
    P2P,
};

// verify that libp2p mdns peer discovery works
#[tokio::test(flavor = "multi_thread")]
async fn test_libp2p_peer_discovery() {
    let config = Arc::new(config::create_mainnet());
    let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
    let mut serv = Libp2pService::new(addr.clone(), &[Libp2pStrategy::MulticastDns], &[])
        .await
        .unwrap();

    tokio::spawn(async move {
        let mut p2p = P2P::<Libp2pService>::new(256, 32, addr, Arc::clone(&config)).await.unwrap();
        let _ = p2p.run().await;
    });

    loop {
        let serv_res: Event<Libp2pService> = serv.poll_next().await.unwrap();
        match serv_res {
            Event::PeerDiscovered(peers) => {
                assert_eq!(peers.len(), 1);

                let addrs = &peers.get(0).unwrap();

                // libp2p may have discovered an ipv4 address
                // but there must be at least one ipv6 address available
                assert_eq!(addrs.ip6.len(), 1);

                let mut addr = addrs.ip6[0].iter();
                assert!(matches!(addr.next(), Some(Protocol::Ip6(_))));
                assert!(matches!(addr.next(), Some(Protocol::Tcp(_))));
                assert!(matches!(addr.next(), Some(Protocol::P2p(_))));

                return;
            }
            e => panic!("unexpected event: {:?}", e),
        }
    }
}

// verify that libp2p floodsub works
#[tokio::test(flavor = "multi_thread")]
async fn test_libp2p_floodsub() {
    let addr1: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
    let mut server1 = Libp2pService::new(addr1, &[], &[FloodsubTopic::Transactions]).await.unwrap();

    let addr2: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
    let mut server2 = Libp2pService::new(addr2, &[], &[FloodsubTopic::Transactions]).await.unwrap();

    let (server1_res, server2_res) =
        tokio::join!(server1.connect(server2.addr.clone()), server2.poll_next());
    let server2_res: Event<Libp2pService> = server2_res.unwrap();
    let server1_id = match server2_res {
        Event::IncomingConnection(id, _socket) => id,
        _ => panic!("invalid event received, expected incoming connection"),
    };
    let server2_id = server1_res.unwrap().0;

    server1.register_peer(server2_id).await.unwrap();
    server2.register_peer(server1_id).await.unwrap();

    // wait a little bit to allow the servers to exchange their topic information
    std::thread::sleep(std::time::Duration::from_millis(300));

    tokio::spawn(async move {
        loop {
            let serv_res: Event<Libp2pService> = server2.poll_next().await.unwrap();
            if let Event::MessageReceived(topic, _message) = serv_res {
                assert_eq!(
                    server2
                        .publish(
                            topic,
                            &message::Message {
                                magic: [0u8; 4],
                                msg: MessageType::Connectivity(ConnectivityMessage::Pong {
                                    nonce: u64::MAX
                                }),
                            }
                        )
                        .await,
                    Ok(())
                );
            }
        }
    });

    assert_eq!(
        server1
            .publish(
                net::FloodsubTopic::Transactions,
                &message::Message {
                    magic: [0u8; 4],
                    msg: MessageType::Connectivity(ConnectivityMessage::Ping { nonce: u64::MAX }),
                }
            )
            .await,
        Ok(())
    );

    let serv_res: Event<Libp2pService> = server1.poll_next().await.unwrap();
    match serv_res {
        Event::MessageReceived(_, message) => {
            assert_eq!(
                message,
                message::Message {
                    magic: [0u8; 4],
                    msg: MessageType::Connectivity(ConnectivityMessage::Pong { nonce: u64::MAX }),
                }
            );
        }
        _ => panic!("invalid event received"),
    }
}
