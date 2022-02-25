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
    error::{Libp2pError, P2pError},
    message::{self, ConnectivityMessage, MessageType},
    net::{
        self,
        libp2p::{Libp2pService, Libp2pStrategy},
        ConnectivityEvent, ConnectivityService, FloodsubEvent, FloodsubService, FloodsubTopic,
        NetworkService,
    },
    P2P,
};

// verify that libp2p mdns peer discovery works
#[tokio::test(flavor = "multi_thread")]
async fn test_libp2p_peer_discovery() {
    let config = Arc::new(config::create_mainnet());
    let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
    let (mut serv, _) = Libp2pService::start(addr.clone(), &[Libp2pStrategy::MulticastDns], &[])
        .await
        .unwrap();

    tokio::spawn(async move {
        let mut p2p = P2P::<Libp2pService>::new(256, 32, addr, Arc::clone(&config)).await.unwrap();
        let _ = p2p.run().await;
    });

    loop {
        let serv_res: ConnectivityEvent<Libp2pService> = serv.poll_next().await.unwrap();
        match serv_res {
            ConnectivityEvent::PeerDiscovered { peers } => {
                assert!(!peers.is_empty());

                // verify that all discovered addresses are either ipv4 or ipv6,
                // they have tcp as the transport protocol and that all end with the peer id
                for peer in peers {
                    for addr in peer.ip6.iter().chain(peer.ip4.iter()) {
                        let mut components = addr.iter();
                        assert!(matches!(
                            components.next(),
                            Some(Protocol::Ip6(_)) | Some(Protocol::Ip4(_))
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

// verify that libp2p floodsub works
#[tokio::test]
async fn test_libp2p_floodsub() {
    let addr1: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
    let (mut conn1, mut flood1) =
        Libp2pService::start(addr1, &[], &[FloodsubTopic::Transactions]).await.unwrap();

    let addr2: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
    let (mut conn2, mut flood2) =
        Libp2pService::start(addr2, &[], &[FloodsubTopic::Transactions]).await.unwrap();

    let (conn1_res, conn2_res) =
        tokio::join!(conn1.connect(conn2.local_addr().clone()), conn2.poll_next());
    let conn2_res: ConnectivityEvent<Libp2pService> = conn2_res.unwrap();
    let conn1_id = match conn2_res {
        ConnectivityEvent::IncomingConnection { peer_id, socket: _ } => peer_id,
        _ => panic!("invalid event received, expected incoming connection"),
    };
    let conn2_id = conn1_res.unwrap().0;

    let (_, _) = tokio::join!(conn1.register_peer(conn2_id), conn2.register_peer(conn1_id));

    // spam the message on the floodsub until it succeeds (= until we have a peer)
    loop {
        let res = flood1
            .publish(
                net::FloodsubTopic::Transactions,
                &message::Message {
                    magic: [0u8; 4],
                    msg: MessageType::Connectivity(ConnectivityMessage::Ping { nonce: u64::MAX }),
                },
            )
            .await;

        if res.is_ok() {
            break;
        } else {
            assert_eq!(
                res,
                Err(P2pError::Libp2pError(Libp2pError::PublishError(
                    "NoPeers".to_string()
                )))
            );
        }
    }

    // poll an event from the network for server2
    let res2: Result<FloodsubEvent<Libp2pService>, _> = flood2.poll_next().await;
    let FloodsubEvent::MessageReceived {
        peer_id: _,
        topic,
        message: _,
    } = res2.unwrap();
    let flood2_send_fut = flood2.publish(
        topic,
        &message::Message {
            magic: [0u8; 4],
            msg: MessageType::Connectivity(ConnectivityMessage::Pong { nonce: u64::MAX }),
        },
    );

    // receive the response (pong) from server2 through floodsub
    let (res1, res2): (Result<FloodsubEvent<Libp2pService>, _>, _) =
        tokio::join!(flood1.poll_next(), flood2_send_fut);

    assert!(res2.is_ok());
    let FloodsubEvent::MessageReceived {
        peer_id: _,
        topic: _,
        message,
    } = res1.unwrap();

    assert_eq!(
        message,
        message::Message {
            magic: [0u8; 4],
            msg: MessageType::Connectivity(ConnectivityMessage::Pong { nonce: u64::MAX }),
        }
    );
}
