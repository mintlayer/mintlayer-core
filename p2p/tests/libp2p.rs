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
extern crate test_utils;

use libp2p::{multiaddr::Protocol, Multiaddr};
use p2p::{
    error::{Libp2pError, P2pError},
    message::{self, ConnectivityMessage, MessageType},
    net::{
        self,
        libp2p::{Libp2pConnectivityHandle, Libp2pService, Libp2pStrategy},
        ConnectivityEvent, ConnectivityService, NetworkService, PubSubEvent, PubSubService,
        PubSubTopic,
    },
};

// verify that libp2p mdns peer discovery works
#[tokio::test]
async fn test_libp2p_peer_discovery() {
    let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
    let (mut serv, _) = Libp2pService::start(
        addr.clone(),
        &[Libp2pStrategy::MulticastDns],
        &[],
        std::time::Duration::from_secs(10),
    )
    .await
    .unwrap();

    let addr2: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
    let (mut serv2, _) = Libp2pService::start(
        addr2.clone(),
        &[Libp2pStrategy::MulticastDns],
        &[],
        std::time::Duration::from_secs(10),
    )
    .await
    .unwrap();

    loop {
        let (serv_res, _) = tokio::join!(serv.poll_next(), serv2.poll_next());

        match serv_res.unwrap() {
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

// verify that libp2p pubsubsub works
#[tokio::test]
async fn test_libp2p_pubsubsub() {
    let addr1: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
    let (mut conn1, mut flood1) = Libp2pService::start(
        addr1,
        &[],
        &[PubSubTopic::Transactions],
        std::time::Duration::from_secs(10),
    )
    .await
    .unwrap();

    let addr2: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
    let (mut conn2, mut flood2) = Libp2pService::start(
        addr2,
        &[],
        &[PubSubTopic::Transactions],
        std::time::Duration::from_secs(10),
    )
    .await
    .unwrap();

    let (conn1_res, conn2_res) =
        tokio::join!(conn1.connect(conn2.local_addr().clone()), conn2.poll_next());
    let conn2_res: ConnectivityEvent<Libp2pService> = conn2_res.unwrap();
    let conn1_id = match conn2_res {
        ConnectivityEvent::IncomingConnection { peer_id, socket: _ } => peer_id,
        _ => panic!("invalid event received, expected incoming connection"),
    };
    let conn2_id = conn1_res.unwrap().0;

    let (_, _) = tokio::join!(conn1.register_peer(conn2_id), conn2.register_peer(conn1_id));

    // spam the message on the pubsubsub until it succeeds (= until we have a peer)
    loop {
        let res = pubsub1
            .publish(
                net::PubSubTopic::Transactions,
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
    let res2: Result<PubSubEvent<Libp2pService>, _> = pubsub2.poll_next().await;
    let PubSubEvent::MessageReceived {
        peer_id: _,
        topic,
        message: _,
        message_id: _,
    } = res2.unwrap();
    let pubsub2_send_fut = pubsub2.publish(
        topic,
        &message::Message {
            magic: [0u8; 4],
            msg: MessageType::Connectivity(ConnectivityMessage::Pong { nonce: u64::MAX }),
        },
    );

    // receive the response (pong) from server2 through pubsubsub
    let (res1, res2): (Result<PubSubEvent<Libp2pService>, _>, _) =
        tokio::join!(pubsub1.poll_next(), pubsub2_send_fut);

    assert!(res2.is_ok());
    let PubSubEvent::MessageReceived {
        peer_id: _,
        topic: _,
        message,
        message_id: _,
    } = res1.unwrap();

    assert_eq!(
        message,
        message::Message {
            magic: [0u8; 4],
            msg: MessageType::Connectivity(ConnectivityMessage::Pong { nonce: u64::MAX }),
        }
    );
}

async fn connect_peers(
    peer1: &mut Libp2pConnectivityHandle<Libp2pService>,
    peer2: &mut Libp2pConnectivityHandle<Libp2pService>,
) {
    let (peer1_res, peer2_res) =
        tokio::join!(peer1.connect(peer2.local_addr().clone()), peer2.poll_next());

    let peer2_res: ConnectivityEvent<Libp2pService> = peer2_res.unwrap();
    let peer1_id = match peer2_res {
        ConnectivityEvent::IncomingConnection { peer_id, socket: _ } => peer_id,
        _ => panic!("invalid event received, expected incoming connection"),
    };

    let peer2_id = peer1_res.unwrap().0;
    let (_, _) = tokio::join!(peer1.register_peer(peer2_id), peer2.register_peer(peer1_id));
}

// test libp2p floodsub with multiple peers and verify that as our libp2p requires message
// validation, peers don't automatically forward the messages
#[tokio::test]
async fn test_libp2p_floodsub_3_peers() {
    let addr1: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
    let (mut conn1, mut pubsub1) =
        Libp2pService::start(addr1, &[], &[PubSubTopic::Transactions]).await.unwrap();

    let (mut peer1, mut peer2, mut peer3) = {
        let mut peers = futures::future::join_all((0..3).map(|_| async {
            let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
            let res = Libp2pService::start(addr, &[], &[PubSubTopic::Transactions]).await.unwrap();
            (res.0, res.1)
        }))
        .await;

        (
            peers.pop().unwrap(),
            peers.pop().unwrap(),
            peers.pop().unwrap(),
        )
    };

    // connect peers into a partial mesh
    connect_peers(&mut conn1, &mut peer1.0).await;
    connect_peers(&mut peer1.0, &mut peer2.0).await;
    connect_peers(&mut peer2.0, &mut peer3.0).await;

    // spam the message on the pubsubsub until it succeeds (= until we have a peer)
    loop {
        let res = pubsub1
            .publish(
                net::PubSubTopic::Transactions,
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

    // verify that all peers received the message even though they weren't directy connected
    let res: Result<PubSubEvent<Libp2pService>, _> = peer1.1.poll_next().await;
    let (peer_id, message_id) = if let Ok(PubSubEvent::MessageReceived {
        peer_id,
        message_id,
        ..
    }) = res
    {
        (peer_id, message_id)
    } else {
        panic!("invalid message received");
    };

    // try to poll the to other gossipsubs and verify that as `peer1` hasn't registered
    // the message as valid, it is not forwarded and the code instead timeouts
    // if the message would've been forward to `peer2` and `peer3`, the messages would
    // be received instantaneously and the cod wouldn't timeout

    tokio::select! {
        _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {
        }
        _ = peer2.1.poll_next() => {
            panic!("peer2 received message")
        }
        _ = peer3.1.poll_next() => {
            panic!("peer3 received message")
        }
    }

    assert_eq!(
        peer1
            .1
            .report_validation_result(peer_id, message_id, net::ValidationResult::Accept)
            .await,
        Ok(())
    );

    // verify that the peer2 gets the message
    let res: Result<PubSubEvent<Libp2pService>, _> = peer2.1.poll_next().await;
    let (peer_id, message_id) = if let Ok(PubSubEvent::MessageReceived {
        peer_id,
        message_id,
        ..
    }) = res
    {
        (peer_id, message_id)
    } else {
        panic!("invalid message received");
    };

    // verify that peer3 didn't get the message until peer2 validated it
    tokio::select! {
        _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {
        }
        _ = peer3.1.poll_next() => {
            panic!("peer3 received message")
        }
    }

    assert_eq!(
        peer2
            .1
            .report_validation_result(peer_id, message_id, net::ValidationResult::Accept)
            .await,
        Ok(())
    );

    let res: Result<PubSubEvent<Libp2pService>, _> = peer3.1.poll_next().await;
    assert!(std::matches!(
        res.unwrap(),
        PubSubEvent::MessageReceived { .. }
    ));
}
