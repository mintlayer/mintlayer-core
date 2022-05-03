// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): A. Altonen
#![allow(unused)]

// TODO: implement getters for requests and responses

use common::chain::config;
use common::chain::ChainConfig;
use common::{
    chain::{
        block::{consensus_data::ConsensusData, Block, BlockHeader},
        transaction::Transaction,
    },
    primitives::{id, Id, Idable},
};
use futures::FutureExt;
use libp2p::PeerId;
use logging::log;
use p2p::{
    error::{self, P2pError},
    event,
    message::{Message, MessageType, SyncingMessage, SyncingRequest, SyncingResponse},
    net::{
        self, libp2p::Libp2pService, ConnectivityService, NetworkService, PubSubService,
        PubSubTopic, SyncingService,
    },
    sync::{mock_consensus, SyncManager, SyncState},
};
use rand::Rng;
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
};
use tokio::sync::{mpsc, oneshot};

macro_rules! get_message {
    ($expression:expr, $($pattern:pat_param)|+, $ret:expr) => {
        match $expression {
            $($pattern)|+ => $ret,
            e => panic!("invalid message received: {:#?}", e)
        }
    }
}

async fn accept_n_blocks(
    rx: &mut mpsc::Receiver<event::P2pEvent>,
    cons: &mut mock_consensus::Consensus,
    blocks: usize,
) {
    for i in 0..blocks {
        get_message!(
            rx.recv().await.unwrap(),
            event::P2pEvent::NewBlock { block, response },
            {
                cons.accept_block(block);
                response.send(());
            }
        );
    }
}

async fn get_locator(
    rx: &mut mpsc::Receiver<event::P2pEvent>,
    cons: &mut mock_consensus::Consensus,
) {
    get_message!(
        rx.recv().await.unwrap(),
        event::P2pEvent::GetLocator { response },
        {
            response.send(cons.get_locator());
        }
    );
}

async fn get_uniq_headers_and_verify(
    rx: &mut mpsc::Receiver<event::P2pEvent>,
    cons: &mut mock_consensus::Consensus,
    remote: &[BlockHeader],
) {
    get_message!(
        rx.recv().await.unwrap(),
        event::P2pEvent::GetUniqHeaders { headers, response },
        {
            let uniq = cons.get_uniq_headers(&headers);
            assert_eq!(&uniq, remote);
            response.send(Some(uniq));
        }
    );
}

async fn get_blocks(
    rx: &mut mpsc::Receiver<event::P2pEvent>,
    cons: &mut mock_consensus::Consensus,
) {
    get_message!(
        rx.recv().await.unwrap(),
        event::P2pEvent::GetBlocks { headers, response },
        {
            response.send(cons.get_blocks(&headers));
        }
    );
}

// async fn peer_get_headers<T, F, Fut>(
//     rx: &mut mpsc::Receiver<event::PeerEvent<T>>,
//     cons: &mut mock_consensus::Consensus,
//     f: F,
// ) where
//     T: NetworkService + std::fmt::Debug,
//     F: FnOnce(Vec<BlockHeader>) -> Fut,
//     Fut: futures::Future<Output = ()>,
// {
//     get_message!(
//         rx.recv().await.unwrap(),
//         event::PeerEvent::Syncing(event::SyncEvent::GetHeaders { locator }),
//         {
//             f(cons.get_headers(&locator)).await;
//         }
//     );
// }

async fn respond_to_header_request<T>(
    mgr1: &mut SyncManager<T>,
    mgr2: &mut SyncManager<T>,
    remote_cons: &mut mock_consensus::Consensus,
) where
    T: NetworkService,
    T::SyncingHandle: SyncingService<T>,
{
    if let net::SyncingMessage::Request {
        peer_id,
        request_id,
        request:
            Message {
                msg:
                    MessageType::Syncing(SyncingMessage::Request(SyncingRequest::GetHeaders {
                        locator,
                    })),
                magic,
            },
    } = mgr2.handle_mut().poll_next().await.unwrap()
    {
        mgr2.handle_mut()
            .send_response(
                request_id,
                Message {
                    magic,
                    msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
                        headers: remote_cons.get_headers(&locator),
                    })),
                },
            )
            .await
            .unwrap();
    } else {
        panic!("invalid message");
    }

    let event = mgr1.handle_mut().poll_next().await.unwrap();
    mgr1.on_syncing_event(event).await.unwrap();
    mgr1.check_state().unwrap();
}

async fn respond_to_block_request<T>(
    mgr1: &mut SyncManager<T>,
    mgr2: &mut SyncManager<T>,
    remote_cons: &mut mock_consensus::Consensus,
) where
    T: NetworkService,
    T::SyncingHandle: SyncingService<T>,
{
    if let net::SyncingMessage::Request {
        peer_id,
        request_id,
        request:
            Message {
                msg:
                    MessageType::Syncing(SyncingMessage::Request(SyncingRequest::GetBlocks { headers })),
                magic,
            },
    } = mgr2.handle_mut().poll_next().await.unwrap()
    {
        assert_eq!(headers.len(), 1);
        let blocks = remote_cons.get_blocks(&headers).into_iter().collect::<Vec<_>>();
        mgr2.handle_mut()
            .send_response(
                request_id,
                Message {
                    magic,
                    msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Blocks {
                        blocks,
                    })),
                },
            )
            .await
            .unwrap();
    } else {
        panic!("invalid message");
    }

    let event = mgr1.handle_mut().poll_next().await.unwrap();
    mgr1.on_syncing_event(event).await.unwrap();
    mgr1.check_state().unwrap();
}

async fn send_header_request<T>(
    mgr1: &mut SyncManager<T>,
    mgr2: &mut SyncManager<T>,
    peer_id: T::PeerId,
    remote_cons: &mut mock_consensus::Consensus,
    expected_headers: Vec<BlockHeader>,
) -> Vec<BlockHeader>
where
    T: NetworkService,
    T::SyncingHandle: SyncingService<T>,
{
    mgr2.handle_mut()
        .send_request(
            peer_id,
            Message {
                magic: [1, 2, 3, 4],
                msg: MessageType::Syncing(SyncingMessage::Request(SyncingRequest::GetHeaders {
                    locator: remote_cons.get_locator(),
                })),
            },
        )
        .await
        .unwrap();

    let event = mgr1.handle_mut().poll_next().await.unwrap();
    mgr1.on_syncing_event(event).await.unwrap();
    mgr1.check_state().unwrap();

    if let net::SyncingMessage::Response {
        peer_id,
        request_id,
        response:
            Message {
                msg:
                    MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers { headers })),
                magic,
            },
    } = mgr2.handle_mut().poll_next().await.unwrap()
    {
        let uniq = remote_cons.get_uniq_headers(&headers);
        assert_eq!(uniq, expected_headers);

        uniq
    } else {
        panic!("invalid message");
    }
}

async fn make_sync_manager<T>(
    addr: T::Address,
) -> (
    SyncManager<T>,
    T::ConnectivityHandle,
    mpsc::Sender<event::SyncControlEvent<T>>,
    mpsc::Sender<event::PeerSyncEvent<T>>,
    mpsc::Receiver<event::P2pEvent>,
)
where
    T: NetworkService + std::fmt::Debug,
    T::PubSubHandle: PubSubService<T>,
    T::SyncingHandle: SyncingService<T>,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let (tx_sync, rx_sync) = tokio::sync::mpsc::channel(64);
    let (tx_peer, rx_peer) = tokio::sync::mpsc::channel(64);
    let (tx_p2p, rx_p2p) = tokio::sync::mpsc::channel(64);

    let config = Arc::new(common::chain::config::create_mainnet());
    let (conn, _, sync) = T::start(
        addr,
        &[],
        &[],
        Arc::clone(&config),
        std::time::Duration::from_secs(10),
    )
    .await
    .unwrap();

    (
        SyncManager::<T>::new(Arc::clone(&config), sync, rx_sync, tx_p2p),
        conn,
        tx_sync,
        tx_peer,
        rx_p2p,
    )
}

async fn connect_services<T>(conn1: &mut T::ConnectivityHandle, conn2: &mut T::ConnectivityHandle)
where
    T: NetworkService,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let (conn1_res, conn2_res) =
        tokio::join!(conn1.connect(conn2.local_addr().clone()), conn2.poll_next());
    let conn2_res: net::ConnectivityEvent<T> = conn2_res.unwrap();
    let conn1_id = match conn2_res {
        net::ConnectivityEvent::IncomingConnection { peer_info, .. } => peer_info.peer_id,
        _ => panic!("invalid event received, expected incoming connection"),
    };
}

// verify that if local and remote nodes are in sync (they have the same mainchain)
// no blocks are exchanged after getheaders messages have been exchanged
#[tokio::test]
async fn local_and_remote_in_sync() {
    // create one common chain for both local and remote and two services
    let mut remote_cons = mock_consensus::Consensus::with_height(8);

    let (mut mgr1, mut conn1, _, _, mut rx_p2p1) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;
    let (mut mgr2, mut conn2, _, _, mut rx_p2p2) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;

    // connect the two managers together so that they can exchange messages
    connect_services::<Libp2pService>(&mut conn1, &mut conn2).await;

    let mut local_cons = remote_cons.clone();
    let handle = tokio::spawn(async move {
        // verify that the first message that the consensus receives is the locator request
        get_locator(&mut rx_p2p1, &mut local_cons).await;

        // verify that after getheaders has been sent (internally) and remote peer has responded
        // to it with their (possibly) new headers, getuniqheaders request is received and as local
        // and remote node are in sync, `get_uniq_headers()` returns an empty vector
        get_uniq_headers_and_verify(&mut rx_p2p1, &mut local_cons, &[]).await;

        local_cons
    });

    assert_eq!(mgr1.register_peer(*conn2.peer_id()).await, Ok(()));

    if let net::SyncingMessage::Request {
        peer_id,
        request_id,
        request:
            Message {
                msg:
                    MessageType::Syncing(SyncingMessage::Request(SyncingRequest::GetHeaders {
                        locator,
                    })),
                magic,
            },
    } = mgr2.handle_mut().poll_next().await.unwrap()
    {
        let headers = remote_cons.get_headers(&locator);
        mgr2.handle_mut()
            .send_response(
                request_id,
                Message {
                    magic,
                    msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
                        headers,
                    })),
                },
            )
            .await
            .unwrap();
    } else {
        panic!("invalid message");
    }

    // read response from the remote peer and verify that they didn't send any headers
    let event = mgr1.handle_mut().poll_next().await.unwrap();
    mgr1.on_syncing_event(event).await.unwrap();
    mgr1.check_state().unwrap();

    let local_cons = handle.await.unwrap();
    assert_eq!(local_cons.mainchain, remote_cons.mainchain);
    assert_eq!(mgr1.state(), &SyncState::Idle);
}

// local and remote nodes are in the same chain but remote is ahead 7 blocks
//
// this the remote node is synced first and as it's ahead of local node,
// no blocks are downloaded whereas loca node downloads the 7 new blocks from remote
#[tokio::test]
async fn remote_ahead_by_7_blocks() {
    let (mut mgr1, mut conn1, _, _, mut rx_p2p1) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;
    let (mut mgr2, mut conn2, _, _, mut rx_p2p2) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;

    // connect the two managers together so that they can exchange messages
    connect_services::<Libp2pService>(&mut conn1, &mut conn2).await;

    // create two chains and add 7 more blocks to remote's chain
    let mut remote_cons = mock_consensus::Consensus::with_height(8);
    let mut local_cons = remote_cons.clone();
    let mut new_block_hdrs = vec![];

    // TODO: use proper random source
    let mut rng = rand::thread_rng();
    let offset = rng.gen::<u32>();

    for i in 0..7 {
        let cur_id = remote_cons.mainchain.blkid.clone();
        let block = Block::new(
            vec![],
            Some(cur_id),
            1337u32 + offset + i + 1,
            ConsensusData::None,
        )
        .unwrap();
        new_block_hdrs.push(block.header().clone());
        remote_cons.accept_block(block);
    }

    // verify that the chains are different
    assert_ne!(local_cons.mainchain, remote_cons.mainchain);

    let handle = tokio::spawn(async move {
        // verify that the first message that the consensus receives is the locator request
        get_locator(&mut rx_p2p1, &mut local_cons).await;

        // verify that as the remote is ahead of local by 7 blocks, extracting the unique
        // headers from the header response results in 7 new headers and that the headers
        // belong to the 7 new blocks that were added to the remote chain
        get_uniq_headers_and_verify(&mut rx_p2p1, &mut local_cons, &new_block_hdrs).await;

        // local syncmanager sent block request to remote and for each now block it receives,
        // it sends the blockindex a newblock event that tells it to accept the new block
        accept_n_blocks(&mut rx_p2p1, &mut local_cons, 7).await;

        // after block downloads, verify that the chains are in sync
        get_locator(&mut rx_p2p1, &mut local_cons).await;
        get_uniq_headers_and_verify(&mut rx_p2p1, &mut local_cons, &[]).await;

        // return the updates blockindex after the tests have been run
        // so it can be compared against remote's blockindex
        local_cons
    });

    // add peer to the hashmap of known peers and send getheaders request to them
    assert_eq!(mgr1.register_peer(*conn2.peer_id()).await, Ok(()));

    // verify that when the connection has been established,
    // the remote peer will receive getheaders request
    if let net::SyncingMessage::Request {
        peer_id,
        request_id,
        request:
            Message {
                msg:
                    MessageType::Syncing(SyncingMessage::Request(SyncingRequest::GetHeaders {
                        locator,
                    })),
                magic,
            },
    } = mgr2.handle_mut().poll_next().await.unwrap()
    {
        let headers = remote_cons.get_headers(&locator);
        mgr2.handle_mut()
            .send_response(
                request_id,
                Message {
                    magic,
                    msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
                        headers,
                    })),
                },
            )
            .await
            .unwrap();
    } else {
        panic!("invalid message");
    }

    let event = mgr1.handle_mut().poll_next().await.unwrap();
    mgr1.on_syncing_event(event).await.unwrap();
    mgr1.check_state().unwrap();

    // TODO: implement respond_to_block_request
    // respond to getblocks request received from the local node
    for i in 0..7 {
        if let net::SyncingMessage::Request {
            peer_id,
            request_id,
            request:
                Message {
                    msg:
                        MessageType::Syncing(SyncingMessage::Request(SyncingRequest::GetBlocks {
                            headers,
                        })),
                    magic,
                },
        } = mgr2.handle_mut().poll_next().await.unwrap()
        {
            assert_eq!(headers.len(), 1);
            let blocks = remote_cons.get_blocks(&headers).into_iter().collect::<Vec<_>>();
            mgr2.handle_mut()
                .send_response(
                    request_id,
                    Message {
                        magic,
                        msg: MessageType::Syncing(SyncingMessage::Response(
                            SyncingResponse::Blocks { blocks },
                        )),
                    },
                )
                .await
                .unwrap();
        } else {
            panic!("invalid message");
        }

        let event = mgr1.handle_mut().poll_next().await.unwrap();
        mgr1.on_syncing_event(event).await.unwrap();
        mgr1.check_state().unwrap();
    }

    if let net::SyncingMessage::Request {
        peer_id,
        request_id,
        request:
            Message {
                msg:
                    MessageType::Syncing(SyncingMessage::Request(SyncingRequest::GetHeaders {
                        locator,
                    })),
                magic,
            },
    } = mgr2.handle_mut().poll_next().await.unwrap()
    {
        mgr2.handle_mut()
            .send_response(
                request_id,
                Message {
                    magic,
                    msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
                        headers: remote_cons.get_headers(&locator),
                    })),
                },
            )
            .await
            .unwrap();
    } else {
        panic!("invalid message");
    }

    let event = mgr1.handle_mut().poll_next().await.unwrap();
    mgr1.on_syncing_event(event).await.unwrap();
    mgr1.check_state().unwrap();

    let local_cons = handle.await.unwrap();
    assert_eq!(local_cons.mainchain, remote_cons.mainchain);
    assert_eq!(mgr1.check_state(), Ok(()));
    assert_eq!(mgr1.state(), &SyncState::Idle);
}

// local and remote nodes are in the same chain but local is ahead of remote by 12 blocks
#[tokio::test]
async fn local_ahead_by_12_blocks() {
    let (mut mgr1, mut conn1, _, _, mut rx_p2p1) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;
    let (mut mgr2, mut conn2, _, _, mut rx_p2p2) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;

    // connect the two managers together so that they can exchange messages
    connect_services::<Libp2pService>(&mut conn1, &mut conn2).await;

    // create two chains and add 12 more blocks to local's chain
    let mut remote_cons = mock_consensus::Consensus::with_height(8);
    let mut local_cons = remote_cons.clone();
    let mut new_block_hdrs = vec![];

    // TODO: use proper random source
    let mut rng = rand::thread_rng();
    let offset = rng.gen::<u32>();

    // add 12 more blocks to local's chain
    for i in 0..12 {
        let cur_id = local_cons.mainchain.blkid.clone();
        let block = Block::new(
            vec![],
            Some(cur_id),
            1337u32 + offset + i + 1,
            ConsensusData::None,
        )
        .unwrap();
        new_block_hdrs.push(block.header().clone());
        local_cons.accept_block(block);
    }

    // verify that the chains are different
    assert_ne!(local_cons.mainchain, remote_cons.mainchain);

    let handle = tokio::spawn(async move {
        // verify that the first message that the consensus receives is the locator request
        get_locator(&mut rx_p2p1, &mut local_cons).await;

        // as local is ahead of remote, getuniqheaders returns an empty vector
        get_uniq_headers_and_verify(&mut rx_p2p1, &mut local_cons, &[]).await;

        // verify that as the local node is ahead of remote by 12 blocks,
        // the header response contains at least 12 headers
        get_message!(
            rx_p2p1.recv().await.unwrap(),
            event::P2pEvent::GetHeaders { locator, response },
            {
                let headers = local_cons.get_headers(&locator);
                assert!(headers.len() >= 12);
                response.send(headers);
            }
        );

        // verify that remote downloads the blocks it doesn't have and does a reorg
        for _ in 0..12 {
            get_blocks(&mut rx_p2p1, &mut local_cons).await;
        }

        local_cons
    });

    // add peer to the hashmap of known peers and send getheaders request to them
    assert_eq!(mgr1.register_peer(*conn2.peer_id()).await, Ok(()));

    // respond to header request coming from remote
    respond_to_header_request(&mut mgr1, &mut mgr2, &mut remote_cons).await;

    // send header request to remote and read response
    let headers = send_header_request(
        &mut mgr1,
        &mut mgr2,
        *conn1.peer_id(),
        &mut remote_cons,
        new_block_hdrs,
    )
    .await;

    // TODO: implement send_block_request()
    for header in headers {
        mgr2.handle_mut()
            .send_request(
                *conn1.peer_id(),
                Message {
                    magic: [1, 2, 3, 4],
                    msg: MessageType::Syncing(SyncingMessage::Request(SyncingRequest::GetBlocks {
                        headers: vec![header],
                    })),
                },
            )
            .await
            .unwrap();

        let event = mgr1.handle_mut().poll_next().await.unwrap();
        mgr1.on_syncing_event(event).await.unwrap();
        mgr1.check_state().unwrap();

        if let net::SyncingMessage::Response {
            peer_id,
            request_id,
            response:
                Message {
                    msg:
                        MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Blocks {
                            blocks,
                        })),
                    magic,
                },
        } = mgr2.handle_mut().poll_next().await.unwrap()
        {
            assert_eq!(blocks.len(), 1);
            remote_cons.accept_block(blocks[0].clone());
        } else {
            panic!("invalid message");
        }
    }

    let local_cons = handle.await.unwrap();
    assert_eq!(local_cons.mainchain, remote_cons.mainchain);
    assert_eq!(mgr1.state(), &SyncState::Idle);
}

// local and remote nodes are in different chains and remote has longer chain
// verify that local downloads all blocks are reorgs
#[tokio::test(flavor = "multi_thread")]
async fn remote_local_diff_chains_remote_higher() {
    let (mut mgr1, mut conn1, _, _, mut rx_p2p1) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;
    let (mut mgr2, mut conn2, _, _, mut rx_p2p2) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;

    // connect the two managers together so that they can exchange messages
    connect_services::<Libp2pService>(&mut conn1, &mut conn2).await;

    // create two chains and add 12 more blocks to local's chain
    let mut remote_cons = mock_consensus::Consensus::with_height(8);
    let mut local_cons = remote_cons.clone();
    let mut new_remote_block_hdrs = vec![];
    let mut new_local_block_hdrs = vec![];

    // TODO: use proper random source
    let mut rng = rand::thread_rng();
    let offset = rng.gen::<u32>();

    // add 8 more blocks to remote's chain
    for i in 0..8 {
        let cur_id = remote_cons.mainchain.blkid.clone();
        let block = Block::new(
            vec![],
            Some(cur_id),
            1337u32 + offset + i + 1,
            ConsensusData::None,
        )
        .unwrap();
        new_remote_block_hdrs.push(block.header().clone());
        remote_cons.accept_block(block);
    }

    // TODO: use proper random source
    let offset = rng.gen::<u32>();

    // add 5 more blocks to local's chain
    for i in 0..5 {
        let cur_id = local_cons.mainchain.blkid.clone();
        let block = Block::new(
            vec![],
            Some(cur_id),
            1337u32 + offset + i + 1,
            ConsensusData::None,
        )
        .unwrap();
        new_local_block_hdrs.push(block.header().clone());
        local_cons.accept_block(block);
    }

    // verify that the chains are different and make a copy of the remote chain
    let remote_orig_cons = remote_cons.clone();
    assert_ne!(local_cons.mainchain, remote_cons.mainchain);

    let handle = tokio::spawn(async move {
        // verify that the first message that the consensus receives is the locator request
        get_locator(&mut rx_p2p1, &mut local_cons).await;

        // as remote is a different branch that has 8 new blocks since the common ancestor
        // `get_uniq_headers()` will return those headers from the entire response
        get_uniq_headers_and_verify(&mut rx_p2p1, &mut local_cons, &new_remote_block_hdrs).await;

        // as the local node is in a different branch than remote that has 5 blocks
        // since the common ancestors, the response contains at least 5 headers
        get_message!(
            rx_p2p1.recv().await.unwrap(),
            event::P2pEvent::GetHeaders { locator, response },
            {
                let headers = local_cons.get_headers(&locator);
                assert!(headers.len() >= 5);
                response.send(headers);
            }
        );

        // accept the 8 new blocks received from remote
        // (internally `accept_block()` does a reorg which is tested later in the test)
        accept_n_blocks(&mut rx_p2p1, &mut local_cons, 8).await;

        // after block downloads, verify that the chains are in sync
        get_locator(&mut rx_p2p1, &mut local_cons).await;
        get_uniq_headers_and_verify(&mut rx_p2p1, &mut local_cons, &[]).await;

        for i in 0..5 {
            // respond to block request received from remote
            get_blocks(&mut rx_p2p1, &mut local_cons).await;
        }

        local_cons
    });

    // add peer to the hashmap of known peers and send getheaders request to them
    assert_eq!(mgr1.register_peer(*conn2.peer_id()).await, Ok(()));

    // respond to the header request sent by mgr1
    respond_to_header_request(&mut mgr1, &mut mgr2, &mut remote_cons).await;

    // send header request
    mgr2.handle_mut()
        .send_request(
            *conn1.peer_id(),
            Message {
                magic: [1, 2, 3, 4],
                msg: MessageType::Syncing(SyncingMessage::Request(SyncingRequest::GetHeaders {
                    locator: remote_cons.get_locator(),
                })),
            },
        )
        .await
        .unwrap();

    let event = mgr1.handle_mut().poll_next().await.unwrap();
    mgr1.on_syncing_event(event).await.unwrap();
    mgr1.check_state().unwrap();

    let mut dl_blocks = vec![];

    for i in 0..9 {
        match mgr2.handle_mut().poll_next().await.unwrap() {
            net::SyncingMessage::Request {
                peer_id,
                request_id,
                request:
                    Message {
                        msg:
                            MessageType::Syncing(SyncingMessage::Request(SyncingRequest::GetBlocks {
                                headers,
                            })),
                        magic,
                    },
            } => {
                let blocks = remote_cons.get_blocks(&headers).into_iter().collect::<Vec<_>>();
                mgr2.handle_mut()
                    .send_response(
                        request_id,
                        Message {
                            magic,
                            msg: MessageType::Syncing(SyncingMessage::Response(
                                SyncingResponse::Blocks { blocks },
                            )),
                        },
                    )
                    .await
                    .unwrap();
                let event = mgr1.handle_mut().poll_next().await.unwrap();
                mgr1.on_syncing_event(event).await.unwrap();
                mgr1.check_state().unwrap();
            }
            net::SyncingMessage::Response {
                peer_id,
                request_id,
                response:
                    Message {
                        msg:
                            MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
                                headers,
                            })),
                        magic,
                    },
            } => {
                let uniq = remote_cons.get_uniq_headers(&headers);
                assert_eq!(uniq.len(), 5);
                assert_eq!(uniq, new_local_block_hdrs);
                dl_blocks = uniq;
            }
            msg => {
                panic!("invalid message received {:?}", msg)
            }
        }
    }

    // respond to the header request sent by mgr1
    respond_to_header_request(&mut mgr1, &mut mgr2, &mut remote_cons).await;

    for header in dl_blocks {
        mgr2.handle_mut()
            .send_request(
                *conn1.peer_id(),
                Message {
                    magic: [1, 2, 3, 4],
                    msg: MessageType::Syncing(SyncingMessage::Request(SyncingRequest::GetBlocks {
                        headers: vec![header],
                    })),
                },
            )
            .await
            .unwrap();

        let event = mgr1.handle_mut().poll_next().await.unwrap();
        mgr1.on_syncing_event(event).await.unwrap();
        mgr1.check_state().unwrap();

        if let net::SyncingMessage::Response {
            peer_id,
            request_id,
            response:
                Message {
                    msg:
                        MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Blocks {
                            blocks,
                        })),
                    magic,
                },
        } = mgr2.handle_mut().poll_next().await.unwrap()
        {
            assert_eq!(blocks.len(), 1);
            remote_cons.accept_block(blocks[0].clone());
        } else {
            panic!("invalid message");
        }
    }

    // wait for the blockindex task to finish
    let local_cons = handle.await.unwrap();

    // verify that even though remote downloaded blocks from local node, it did not do a reorg
    assert_eq!(remote_orig_cons.mainchain, remote_cons.mainchain);
    assert_eq!(
        remote_orig_cons.blks.store.len() + 5,
        remote_cons.blks.store.len()
    );

    // verify also that local did a reorg as its chain was shorter
    assert_eq!(remote_cons.mainchain, local_cons.mainchain);
    assert_eq!(mgr1.check_state(), Ok(()));
    assert_eq!(mgr1.state(), &SyncState::Idle);
}

// remote and local are in different branches and local has longer chain
#[tokio::test(flavor = "multi_thread")]
async fn remote_local_diff_chains_local_higher() {
    let (mut mgr1, mut conn1, _, _, mut rx_p2p1) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;
    let (mut mgr2, mut conn2, _, _, mut rx_p2p2) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;

    // connect the two managers together so that they can exchange messages
    connect_services::<Libp2pService>(&mut conn1, &mut conn2).await;

    // create two chains and add 16 more blocks to local's chain and 3 to remote's chain
    let mut remote_cons = mock_consensus::Consensus::with_height(8);
    let mut local_cons = remote_cons.clone();
    let mut new_remote_block_hdrs = vec![];
    let mut new_local_block_hdrs = vec![];

    // TODO: use proper random source
    let mut rng = rand::thread_rng();
    let offset = rng.gen::<u32>();

    // add 3 more blocks to remote's chain
    for i in 0..3 {
        let cur_id = remote_cons.mainchain.blkid.clone();
        let block = Block::new(
            vec![],
            Some(cur_id),
            1337u32 + offset + i + 1,
            ConsensusData::None,
        )
        .unwrap();
        new_remote_block_hdrs.push(block.header().clone());
        remote_cons.accept_block(block);
    }

    // TODO: use proper random source
    let offset = rng.gen::<u32>();

    // add 16 more blocks to local's chain
    for i in 0..16 {
        let cur_id = local_cons.mainchain.blkid.clone();
        let block = Block::new(
            vec![],
            Some(cur_id),
            1337u32 + offset + i + 1,
            ConsensusData::None,
        )
        .unwrap();
        new_local_block_hdrs.push(block.header().clone());
        local_cons.accept_block(block);
    }

    // // verify that the chains are different and make a copy of the local chain
    let local_orig_cons = local_cons.clone();
    let remote_orig_cons = remote_cons.clone();
    assert_ne!(local_cons.mainchain, remote_cons.mainchain);

    let handle = tokio::spawn(async move {
        // verify that the first message that the consensus receives is the locator request
        get_locator(&mut rx_p2p1, &mut local_cons).await;

        // verify that the  uniq headers received from remote
        // are the ones they added before the test started
        get_uniq_headers_and_verify(&mut rx_p2p1, &mut local_cons, &new_remote_block_hdrs).await;

        get_message!(
            rx_p2p1.recv().await.unwrap(),
            event::P2pEvent::GetHeaders { locator, response },
            {
                let headers = local_cons.get_headers(&locator);
                assert!(headers.len() >= 16);
                response.send(headers);
            }
        );

        // accept the remote blocks to our chain but because the height of that
        // chhain is shorter than ours, no reorg happens which is tested later on
        accept_n_blocks(&mut rx_p2p1, &mut local_cons, 3).await;

        // after block downloads, verify that the chains are in sync
        get_locator(&mut rx_p2p1, &mut local_cons).await;
        get_uniq_headers_and_verify(&mut rx_p2p1, &mut local_cons, &[]).await;

        for i in 0..16 {
            get_blocks(&mut rx_p2p1, &mut local_cons).await;
        }

        local_cons
    });

    // add peer to the hashmap of known peers and send getheaders request to them
    assert_eq!(mgr1.register_peer(*conn2.peer_id()).await, Ok(()));

    // respond to header request coming from remote
    respond_to_header_request(&mut mgr1, &mut mgr2, &mut remote_cons).await;

    // send header request
    mgr2.handle_mut()
        .send_request(
            *conn1.peer_id(),
            Message {
                magic: [1, 2, 3, 4],
                msg: MessageType::Syncing(SyncingMessage::Request(SyncingRequest::GetHeaders {
                    locator: remote_cons.get_locator(),
                })),
            },
        )
        .await
        .unwrap();

    let event = mgr1.handle_mut().poll_next().await.unwrap();
    mgr1.on_syncing_event(event).await.unwrap();
    mgr1.check_state().unwrap();

    let mut dl_blocks = vec![];

    for i in 0..4 {
        match mgr2.handle_mut().poll_next().await.unwrap() {
            net::SyncingMessage::Request {
                peer_id,
                request_id,
                request:
                    Message {
                        msg:
                            MessageType::Syncing(SyncingMessage::Request(SyncingRequest::GetBlocks {
                                headers,
                            })),
                        magic,
                    },
            } => {
                let blocks = remote_cons.get_blocks(&headers).into_iter().collect::<Vec<_>>();
                mgr2.handle_mut()
                    .send_response(
                        request_id,
                        Message {
                            magic,
                            msg: MessageType::Syncing(SyncingMessage::Response(
                                SyncingResponse::Blocks { blocks },
                            )),
                        },
                    )
                    .await
                    .unwrap();
                let event = mgr1.handle_mut().poll_next().await.unwrap();
                mgr1.on_syncing_event(event).await.unwrap();
                mgr1.check_state().unwrap();
            }
            net::SyncingMessage::Response {
                peer_id,
                request_id,
                response:
                    Message {
                        msg:
                            MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
                                headers,
                            })),
                        magic,
                    },
            } => {
                let uniq = remote_cons.get_uniq_headers(&headers);
                assert_eq!(uniq.len(), 16);
                assert_eq!(uniq, new_local_block_hdrs);
                dl_blocks = uniq;
            }
            msg => {
                panic!("invalid message received {:?}", msg)
            }
        }
    }

    // respond to the header request sent by mgr1
    respond_to_header_request(&mut mgr1, &mut mgr2, &mut remote_cons).await;

    // TODO: implement send_block_request
    for header in dl_blocks {
        mgr2.handle_mut()
            .send_request(
                *conn1.peer_id(),
                Message {
                    magic: [1, 2, 3, 4],
                    msg: MessageType::Syncing(SyncingMessage::Request(SyncingRequest::GetBlocks {
                        headers: vec![header],
                    })),
                },
            )
            .await
            .unwrap();

        let event = mgr1.handle_mut().poll_next().await.unwrap();
        mgr1.on_syncing_event(event).await.unwrap();
        mgr1.check_state().unwrap();

        if let net::SyncingMessage::Response {
            peer_id,
            request_id,
            response:
                Message {
                    msg:
                        MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Blocks {
                            blocks,
                        })),
                    magic,
                },
        } = mgr2.handle_mut().poll_next().await.unwrap()
        {
            assert_eq!(blocks.len(), 1);
            remote_cons.accept_block(blocks[0].clone());
        } else {
            panic!("invalid message");
        }
    }

    // wait for the blockindex task to finish
    let local_cons = handle.await.unwrap();

    // verify that even though local downloaded blocks from
    // local node, it did not do a reorg
    assert_eq!(local_orig_cons.mainchain, local_cons.mainchain);
    assert_eq!(
        local_orig_cons.blks.store.len() + 3,
        local_cons.blks.store.len()
    );
    assert_ne!(remote_orig_cons.mainchain, remote_cons.mainchain);
    assert_eq!(
        remote_orig_cons.blks.store.len() + 16,
        remote_cons.blks.store.len()
    );

    // verify also that local did a reorg as its chain was shorter
    assert_eq!(remote_cons.mainchain, local_cons.mainchain);
    assert_eq!(mgr1.check_state(), Ok(()));
    assert_eq!(mgr1.state(), &SyncState::Idle);
}

// connect two remote nodes and as all three nodes are in different chains,
// local node downloads all blocks
#[tokio::test(flavor = "multi_thread")]
async fn two_remote_nodes_different_chains() {
    let (mut mgr1, mut conn1, _, _, mut rx_p2p1) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;
    let (mut mgr2, mut conn2, _, _, _) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;
    let (mut mgr3, mut conn3, _, _, _) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;

    // connect the managers together so they can exchange messages via libp2p
    connect_services::<Libp2pService>(&mut conn1, &mut conn2).await;
    connect_services::<Libp2pService>(&mut conn1, &mut conn3).await;

    // create 3 chains where two of them have new unique blocks
    let mut remote1_cons = mock_consensus::Consensus::with_height(8);
    let mut remote2_cons = remote1_cons.clone();
    let mut local_cons = remote1_cons.clone();
    let mut local_orig_cons = remote1_cons.clone();
    let mut new_remote1_block_hdrs = vec![];
    let mut new_remote2_block_hdrs = vec![];

    // TODO: use proper random source
    let mut rng = rand::thread_rng();
    let offset = rng.gen::<u32>();

    // add 8 blocks to remote1's chain
    for i in 0..8 {
        let cur_id = remote1_cons.mainchain.blkid.clone();
        let block = Block::new(
            vec![],
            Some(cur_id),
            1337u32 + offset + i + 1,
            ConsensusData::None,
        )
        .unwrap();
        new_remote1_block_hdrs.push(block.header().clone());
        remote1_cons.accept_block(block);
    }

    // TODO: use proper random source
    let offset = rng.gen::<u32>();

    // add 5 blocks to remote2's chain
    for i in 0..5 {
        let cur_id = remote2_cons.mainchain.blkid.clone();
        let block = Block::new(
            vec![],
            Some(cur_id),
            1337u32 + offset + i + 1,
            ConsensusData::None,
        )
        .unwrap();
        new_remote2_block_hdrs.push(block.header().clone());
        remote2_cons.accept_block(block);
    }

    let local_orig_cons = local_cons.clone();
    let remote1_orig_cons = remote1_cons.clone();
    let remote2_orig_cons = remote2_cons.clone();

    assert_ne!(local_cons.mainchain, remote1_cons.mainchain);
    assert_ne!(local_cons.mainchain, remote2_cons.mainchain);
    assert_ne!(remote1_cons.mainchain, remote2_cons.mainchain);

    let handle = tokio::spawn(async move {
        // verify that the first message that the consensus receives is the locator request
        get_locator(&mut rx_p2p1, &mut local_cons).await;

        // as remote_1 is a different branch that has 8 new blocks since the common ancestor
        // `get_uniq_headers()` will return those headers from the entire response
        get_uniq_headers_and_verify(&mut rx_p2p1, &mut local_cons, &new_remote1_block_hdrs).await;

        // accept the blocks from first remote node (reorg done)
        accept_n_blocks(&mut rx_p2p1, &mut local_cons, 8).await;

        // after block downloads, verify that the chains are in sync
        get_locator(&mut rx_p2p1, &mut local_cons).await;
        get_uniq_headers_and_verify(&mut rx_p2p1, &mut local_cons, &[]).await;

        get_message!(
            rx_p2p1.recv().await.unwrap(),
            event::P2pEvent::GetHeaders { locator, response },
            {
                response.send(local_cons.get_headers(&locator));
            }
        );

        // handler locator and header request for the second peer
        get_locator(&mut rx_p2p1, &mut local_cons).await;
        get_uniq_headers_and_verify(&mut rx_p2p1, &mut local_cons, &new_remote2_block_hdrs).await;

        // accept the blcoks from the second remote node (no reorg is done)
        accept_n_blocks(&mut rx_p2p1, &mut local_cons, 5).await;

        // after block downloads, verify that the chains are in sync
        get_locator(&mut rx_p2p1, &mut local_cons).await;
        get_uniq_headers_and_verify(&mut rx_p2p1, &mut local_cons, &[]).await;

        local_cons
    });

    // register first peere to sync manager
    assert_eq!(mgr1.register_peer(*conn2.peer_id()).await, Ok(()));

    // respond to header request coming from mgr1
    respond_to_header_request(&mut mgr1, &mut mgr2, &mut remote1_cons).await;

    // respond to block requests coming from mgr1
    for i in 0..8 {
        respond_to_block_request(&mut mgr1, &mut mgr2, &mut remote1_cons).await;
    }

    // respond to header request coming from remote
    respond_to_header_request(&mut mgr1, &mut mgr2, &mut remote1_cons).await;

    let headers = send_header_request(
        &mut mgr1,
        &mut mgr2,
        *conn1.peer_id(),
        &mut remote1_cons,
        vec![],
    )
    .await;
    assert!(headers.is_empty());

    // register first peere to sync manager
    assert_eq!(mgr1.register_peer(*conn3.peer_id()).await, Ok(()));

    // respond to header request coming from mgr1
    respond_to_header_request(&mut mgr1, &mut mgr3, &mut remote2_cons).await;

    // respond to block requests coming from mgr1
    for i in 0..5 {
        respond_to_block_request(&mut mgr1, &mut mgr3, &mut remote2_cons).await;
    }

    // respond to header request coming from remote
    respond_to_header_request(&mut mgr1, &mut mgr3, &mut remote2_cons).await;

    // wait for the blockindex task to finish
    let local_cons = handle.await.unwrap();

    // verify also that local did a reorg as its chain was shorter
    assert_ne!(local_orig_cons.mainchain, local_cons.mainchain);
    assert_eq!(remote1_cons.mainchain, local_cons.mainchain);
    assert_ne!(remote2_cons.mainchain, local_cons.mainchain);
    assert_eq!(
        local_orig_cons.blks.store.len() + 13,
        local_cons.blks.store.len()
    );
    assert_eq!(mgr1.check_state(), Ok(()));
    assert_eq!(mgr1.state(), &SyncState::Idle);
}

// connect two remote nodes that are in sync and ahead of local
// verify that downloads blocks from both nodes
//
// force the headers to be exchanged first and make the local
// node download full copy of the chain
#[tokio::test]
async fn two_remote_nodes_same_chain() {
    let (mut mgr1, mut conn1, _, _, mut rx_p2p) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;
    let (mut mgr2, mut conn2, _, _, _) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;
    let (mut mgr3, mut conn3, _, _, _) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;

    // connect the managers together so they can exchange messages via libp2p
    connect_services::<Libp2pService>(&mut conn1, &mut conn2).await;
    connect_services::<Libp2pService>(&mut conn1, &mut conn3).await;

    // create two chains, one for local and one for the two remote nodes
    let mut remote_cons = mock_consensus::Consensus::with_height(8);
    let mut local_cons = remote_cons.clone();
    let mut local_orig_cons = remote_cons.clone();
    let mut new_remote_block_hdrs = vec![];

    // TODO: use proper random source
    let mut rng = rand::thread_rng();
    let offset = rng.gen::<u32>();

    // add 10 blocks to remotes' chain
    for i in 0..10 {
        let cur_id = remote_cons.mainchain.blkid.clone();
        let block = Block::new(
            vec![],
            Some(cur_id),
            1337u32 + offset + i + 1,
            ConsensusData::None,
        )
        .unwrap();
        new_remote_block_hdrs.push(block.header().clone());
        remote_cons.accept_block(block);
    }

    let handle = tokio::spawn(async move {
        get_locator(&mut rx_p2p, &mut local_cons).await;
        get_locator(&mut rx_p2p, &mut local_cons).await;
        let mut getuniqheaders_last = false;

        get_uniq_headers_and_verify(&mut rx_p2p, &mut local_cons, &new_remote_block_hdrs).await;
        get_uniq_headers_and_verify(&mut rx_p2p, &mut local_cons, &new_remote_block_hdrs).await;

        for i in 0..24 {
            match rx_p2p.recv().await.unwrap() {
                event::P2pEvent::NewBlock { block, response } => {
                    local_cons.accept_block(block);
                    response.send(());
                }
                event::P2pEvent::GetLocator { response } => {
                    response.send(local_cons.get_locator());
                }
                event::P2pEvent::GetUniqHeaders { headers, response } => {
                    let uniq = local_cons.get_uniq_headers(&headers);
                    assert_eq!(&uniq, &[]);
                    response.send(Some(uniq));
                }
                e => panic!("invalid message received: {:#?}", e),
            }
        }

        local_cons
    });

    // add both peers to the hashmap of known peers and send getheaders request to them
    for peer in &[*conn2.peer_id(), *conn3.peer_id()] {
        assert_eq!(mgr1.register_peer(*peer).await, Ok(()));
    }

    let mgr_handle = tokio::spawn(async move {
        for _ in 0..24 {
            tokio::select! {
                event = mgr1.handle_mut().poll_next() => {
                    mgr1.on_syncing_event(event.unwrap()).await.unwrap();
                    mgr1.check_state().unwrap();
                },
                _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                    panic!("syncing test timed out");
                }
            }
        }

        mgr1
    });

    for i in 0..24 {
        let (event, dest_peer_id) = tokio::select! {
            event = mgr2.handle_mut().poll_next() => { (event.unwrap(), conn2.peer_id()) },
            event = mgr3.handle_mut().poll_next() => { (event.unwrap(), conn3.peer_id()) },
        };

        match event {
            net::SyncingMessage::Request {
                peer_id: _,
                request_id,
                request:
                    Message {
                        msg:
                            MessageType::Syncing(SyncingMessage::Request(SyncingRequest::GetBlocks {
                                headers,
                            })),
                        magic,
                    },
            } => {
                let blocks = remote_cons.get_blocks(&headers).into_iter().collect::<Vec<_>>();
                let response = Message {
                    magic,
                    msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Blocks {
                        blocks,
                    })),
                };

                if dest_peer_id == conn2.peer_id() {
                    mgr2.handle_mut().send_response(request_id, response).await.unwrap();
                } else {
                    mgr3.handle_mut().send_response(request_id, response).await.unwrap();
                }
            }
            net::SyncingMessage::Request {
                peer_id: _,
                request_id,
                request:
                    Message {
                        msg:
                            MessageType::Syncing(SyncingMessage::Request(SyncingRequest::GetHeaders {
                                locator,
                            })),
                        magic,
                    },
            } => {
                let response = Message {
                    magic,
                    msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
                        headers: remote_cons.get_headers(&locator),
                    })),
                };

                if dest_peer_id == conn2.peer_id() {
                    mgr2.handle_mut().send_response(request_id, response).await.unwrap();
                } else {
                    mgr3.handle_mut().send_response(request_id, response).await.unwrap();
                }
            }
            msg => {
                panic!("invalid message received {:?}", msg)
            }
        }
    }

    // wait for consensus and mgr1 to finish
    let local_cons = handle.await.unwrap();
    let mut mgr1 = mgr_handle.await.unwrap();

    // verify also that local did a reorg as its chain was shorter
    assert_ne!(local_orig_cons.mainchain, local_cons.mainchain);
    assert_eq!(remote_cons.mainchain, local_cons.mainchain);
    assert_eq!(
        local_orig_cons.blks.store.len() + 10,
        local_cons.blks.store.len()
    );

    // verify that both peers contributed to block requests
    assert_eq!(mgr1.check_state(), Ok(()));
    assert_eq!(mgr1.state(), &SyncState::Idle);
}

// connect two remote nodes that are in sync and ahead of local
// verify that downloads blocks from both nodes
//
// when local node has downloaded all blocks, add new blocks to
// the remote chain and verify that local node downloads the new blocks too
#[tokio::test(flavor = "multi_thread")]
async fn two_remote_nodes_same_chain_new_blocks() {
    let (mut mgr1, mut conn1, _, _, mut rx_p2p) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;
    let (mut mgr2, mut conn2, _, _, _) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;
    let (mut mgr3, mut conn3, _, _, _) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;

    // connect the managers together so they can exchange messages via libp2p
    connect_services::<Libp2pService>(&mut conn1, &mut conn2).await;
    connect_services::<Libp2pService>(&mut conn1, &mut conn3).await;

    // create two chains, one for local and one for the two remote nodes
    let mut remote_cons = mock_consensus::Consensus::with_height(8);
    let mut local_cons = remote_cons.clone();
    let mut local_orig_cons = remote_cons.clone();
    let mut new_remote_block_hdrs = vec![];

    // TODO: use proper random source
    let mut rng = rand::thread_rng();
    let offset = rng.gen::<u32>();

    // add 10 blocks to remotes' chain
    for i in 0..10 {
        let cur_id = remote_cons.mainchain.blkid.clone();
        let block = Block::new(
            vec![],
            Some(cur_id),
            1337u32 + offset + i + 1,
            ConsensusData::None,
        )
        .unwrap();
        new_remote_block_hdrs.push(block.header().clone());
        remote_cons.accept_block(block);
    }

    let handle = tokio::spawn(async move {
        get_locator(&mut rx_p2p, &mut local_cons).await;
        get_locator(&mut rx_p2p, &mut local_cons).await;

        for i in 0..40 {
            tokio::select! {
                event = rx_p2p.recv().fuse() => match event.unwrap() {
                    event::P2pEvent::GetUniqHeaders { headers, response } => {
                        let uniq = local_cons.get_uniq_headers(&headers);
                        response.send(Some(uniq));
                    }
                    event::P2pEvent::NewBlock { block, response } => {
                        local_cons.accept_block(block);
                        response.send(());
                    }
                    event::P2pEvent::GetLocator { response } => {
                        response.send(local_cons.get_locator());
                    }
                    event::P2pEvent::GetUniqHeaders { headers, response } => {
                        let uniq = local_cons.get_uniq_headers(&headers);
                        response.send(Some(uniq));
                    }
                    e => panic!("invalid message received: {:#?}", e),
                },
                _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => {
                    panic!("consensus task timed out");
                }
            }
        }

        local_cons
    });

    // add both peers to the hashmap of known peers and send getheaders request to them
    for peer in &[*conn2.peer_id(), *conn3.peer_id()] {
        assert_eq!(mgr1.register_peer(*peer).await, Ok(()));
    }

    let mgr_handle = tokio::spawn(async move {
        for _ in 0..36 {
            tokio::select! {
                event = mgr1.handle_mut().poll_next() => {
                    mgr1.on_syncing_event(event.unwrap()).await.unwrap();
                    mgr1.check_state().unwrap();
                },
                _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => {
                    panic!("syncing test timed out");
                }
            }
        }

        mgr1
    });

    let mut gethdrs = HashSet::new();
    let mut reqs = HashMap::new();

    for i in 0..24 {
        let (event, dest_peer_id) = tokio::select! {
            event = mgr2.handle_mut().poll_next() => { (event.unwrap(), conn2.peer_id()) },
            event = mgr3.handle_mut().poll_next() => { (event.unwrap(), conn3.peer_id()) },
        };

        match event {
            net::SyncingMessage::Request {
                peer_id: _,
                request_id,
                request:
                    Message {
                        msg:
                            MessageType::Syncing(SyncingMessage::Request(SyncingRequest::GetBlocks {
                                headers,
                            })),
                        magic,
                    },
            } => {
                let blocks = remote_cons.get_blocks(&headers).into_iter().collect::<Vec<_>>();
                let response = Message {
                    magic,
                    msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Blocks {
                        blocks,
                    })),
                };

                if dest_peer_id == conn2.peer_id() {
                    mgr2.handle_mut().send_response(request_id, response).await.unwrap();
                } else {
                    mgr3.handle_mut().send_response(request_id, response).await.unwrap();
                }
            }
            net::SyncingMessage::Request {
                peer_id,
                request_id,
                request:
                    Message {
                        msg:
                            MessageType::Syncing(SyncingMessage::Request(SyncingRequest::GetHeaders {
                                locator,
                            })),
                        magic,
                    },
            } => {
                if !gethdrs.insert(dest_peer_id) {
                    reqs.insert(dest_peer_id, (request_id, locator.clone()));
                    continue;
                }

                let response = Message {
                    magic,
                    msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
                        headers: remote_cons.get_headers(&locator),
                    })),
                };

                if dest_peer_id == conn2.peer_id() {
                    mgr2.handle_mut().send_response(request_id, response).await.unwrap();
                } else {
                    mgr3.handle_mut().send_response(request_id, response).await.unwrap();
                }
            }
            msg => {
                panic!("invalid message received {:?}", msg)
            }
        }
    }

    // TODO: use different rand
    // now that the headers have been changed and some block may have been
    // downloaded, add more blocks to the remote chain that the local node
    // doens't know about and when it has downloaded all blocks it knows about,
    // it'll check if the remote nodes know any blocks and these blocks are
    // advertised at that point
    let offset = rng.gen::<u32>();

    for i in 0..5 {
        let cur_id = remote_cons.mainchain.blkid.clone();
        let block = Block::new(
            vec![],
            Some(cur_id),
            1337u32 + offset + i + 1,
            ConsensusData::None,
        )
        .unwrap();
        remote_cons.accept_block(block);
    }

    for (peer_id, (request_id, locator)) in &reqs {
        let response = Message {
            magic: [1, 2, 3, 4],
            msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
                headers: remote_cons.get_headers(locator),
            })),
        };

        if *peer_id == conn2.peer_id() {
            mgr2.handle_mut().send_response(*request_id, response).await.unwrap();
        } else {
            mgr3.handle_mut().send_response(*request_id, response).await.unwrap();
        }
    }

    for i in 0..12 {
        let (event, dest_peer_id) = tokio::select! {
            event = mgr2.handle_mut().poll_next() => { (event.unwrap(), conn2.peer_id()) },
            event = mgr3.handle_mut().poll_next() => { (event.unwrap(), conn3.peer_id()) },
        };

        match event {
            net::SyncingMessage::Request {
                peer_id: _,
                request_id,
                request:
                    Message {
                        msg:
                            MessageType::Syncing(SyncingMessage::Request(SyncingRequest::GetBlocks {
                                headers,
                            })),
                        magic,
                    },
            } => {
                let blocks = remote_cons.get_blocks(&headers).into_iter().collect::<Vec<_>>();
                let response = Message {
                    magic,
                    msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Blocks {
                        blocks,
                    })),
                };

                if dest_peer_id == conn2.peer_id() {
                    mgr2.handle_mut().send_response(request_id, response).await.unwrap();
                } else {
                    mgr3.handle_mut().send_response(request_id, response).await.unwrap();
                }
            }
            net::SyncingMessage::Request {
                peer_id,
                request_id,
                request:
                    Message {
                        msg:
                            MessageType::Syncing(SyncingMessage::Request(SyncingRequest::GetHeaders {
                                locator,
                            })),
                        magic,
                    },
            } => {
                let response = Message {
                    magic,
                    msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
                        headers: remote_cons.get_headers(&locator),
                    })),
                };

                if dest_peer_id == conn2.peer_id() {
                    mgr2.handle_mut().send_response(request_id, response).await.unwrap();
                } else {
                    mgr3.handle_mut().send_response(request_id, response).await.unwrap();
                }
            }
            msg => {
                panic!("invalid message received {:?}", msg)
            }
        }
    }

    let (local_cons, mgr1) = tokio::join!(handle, mgr_handle);
    let local_cons = local_cons.unwrap();
    let mut mgr1 = mgr1.unwrap();

    // verify also that local did a reorg as its chain was shorter
    assert_ne!(local_orig_cons.mainchain, local_cons.mainchain);
    assert_eq!(remote_cons.mainchain, local_cons.mainchain);
    assert_eq!(
        local_orig_cons.blks.store.len() + 15,
        local_cons.blks.store.len()
    );
    assert_eq!(mgr1.check_state(), Ok(()));
    assert_eq!(mgr1.state(), &SyncState::Idle);
}
