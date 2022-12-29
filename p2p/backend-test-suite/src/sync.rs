// Copyright (c) 2021-2022 RBB S.r.l
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
    collections::{HashSet, VecDeque},
    fmt::Debug,
    sync::Arc,
};

use tokio::sync::mpsc;

use chainstate::{chainstate_interface::ChainstateInterface, BlockSource};
use common::{
    chain::{config::ChainConfig, GenBlock},
    primitives::{Id, Idable},
};

use p2p::testing_utils::TestTransportMaker;
use p2p::{
    config::{MdnsConfig, NodeType, P2pConfig},
    error::P2pError,
    event::{PeerManagerEvent, SyncControlEvent},
    message::{BlockListRequest, BlockListResponse, HeaderListResponse, Request, Response},
    net::{
        types::{ConnectivityEvent, SyncingEvent},
        ConnectivityService, NetworkingService, SyncingMessagingService,
    },
    peer_manager::helpers::connect_services,
    sync::BlockSyncManager,
    sync::SyncState,
};
use p2p_test_utils::TestBlockInfo;

tests![
    local_and_remote_in_sync,
    remote_ahead_by_7_blocks,
    local_ahead_by_12_blocks,
    remote_local_diff_chains_local_higher,
    remote_local_diff_chains_remote_higher,
    two_remote_nodes_different_chains,
    two_remote_nodes_same_chains,
    two_remote_nodes_same_chains_new_blocks,
    connect_disconnect_resyncing,
    disconnect_unresponsive_peer,
];

async fn local_and_remote_in_sync<A, S>()
where
    A: TestTransportMaker<Transport = S::Transport, Address = S::Address>,
    S: NetworkingService + Debug + 'static,
    S::ConnectivityHandle: ConnectivityService<S>,
    S::SyncingMessagingHandle: SyncingMessagingService<S>,
{
    let config = Arc::new(common::chain::config::create_unit_test_config());
    let (handle1, handle2) = init_chainstate_2(Arc::clone(&config), 8).await;
    let mgr1_handle = handle1.clone();
    let mgr2_handle = handle2.clone();

    let (mut mgr1, mut conn1, _, _) = make_sync_manager::<S>(
        A::make_transport(),
        A::make_address(),
        handle1,
        P2pConfig::default(),
    )
    .await;
    let (mut mgr2, mut conn2, _, _) = make_sync_manager::<S>(
        A::make_transport(),
        A::make_address(),
        handle2,
        P2pConfig::default(),
    )
    .await;

    // connect the two managers together so that they can exchange messages
    connect_services::<S>(&mut conn1, &mut conn2).await;
    assert_eq!(mgr1.register_peer(*conn2.peer_id()).await, Ok(()));

    // ensure that only a header request is received from the remote and
    // as the nodes are tracking the same chain, no further messages are exchanged
    let (res1, res2) = tokio::join!(
        process_header_request(&mut mgr2, &mgr2_handle),
        advance_mgr_state(&mut mgr1)
    );

    assert_eq!(res1, Ok(()));
    assert_eq!(res2, Ok(()));

    assert!(same_tip(&mgr1_handle, &mgr2_handle).await);
    assert_eq!(mgr1.state(), &SyncState::Done);
}

// local and remote nodes are in the same chain but remote is ahead 7 blocks
//
// this the remote node is synced first and as it's ahead of local node,
// no blocks are downloaded whereas local node downloads the 7 new blocks from remote
async fn remote_ahead_by_7_blocks<A, S>()
where
    A: TestTransportMaker<Transport = S::Transport, Address = S::Address>,
    S: NetworkingService + 'static + Debug,
    S::ConnectivityHandle: ConnectivityService<S>,
    S::SyncingMessagingHandle: SyncingMessagingService<S>,
{
    let config = Arc::new(common::chain::config::create_unit_test_config());
    let (handle1, handle2) = init_chainstate_2(Arc::clone(&config), 8).await;
    let mgr1_handle = handle1.clone();
    let mgr2_handle = handle2.clone();

    let (mut mgr1, mut conn1, _, _) = make_sync_manager::<S>(
        A::make_transport(),
        A::make_address(),
        handle1,
        P2pConfig::default(),
    )
    .await;
    let (mut mgr2, mut conn2, _, _) = make_sync_manager::<S>(
        A::make_transport(),
        A::make_address(),
        handle2,
        P2pConfig::default(),
    )
    .await;

    // add 7 more blocks on top of the best block (which is also known by mgr1)
    assert!(same_tip(&mgr1_handle, &mgr2_handle).await);
    p2p_test_utils::add_more_blocks(Arc::clone(&config), &mgr2_handle, 7).await;
    assert!(!same_tip(&mgr1_handle, &mgr2_handle).await);

    // add peer to the hashmap of known peers and send getheaders request to them
    connect_services::<S>(&mut conn1, &mut conn2).await;
    assert_eq!(mgr1.register_peer(*conn2.peer_id()).await, Ok(()));

    let handle = tokio::spawn(async move {
        for _ in 0..9 {
            advance_mgr_state(&mut mgr1).await.unwrap();
        }

        mgr1
    });

    for _ in 0..9 {
        match mgr2.handle_mut().poll_next().await.unwrap() {
            SyncingEvent::Request {
                peer_id: _,
                request_id,
                request: Request::HeaderListRequest(request),
            } => {
                let headers = mgr2_handle
                    .call(move |this| this.get_headers(request.into_locator()))
                    .await
                    .unwrap()
                    .unwrap();
                mgr2.handle_mut()
                    .send_response(
                        request_id,
                        Response::HeaderListResponse(HeaderListResponse::new(headers)),
                    )
                    .await
                    .unwrap()
            }
            SyncingEvent::Request {
                peer_id: _,
                request_id,
                request: Request::BlockListRequest(request),
            } => {
                assert_eq!(request.block_ids().len(), 1);
                let id = request.block_ids()[0];
                let blocks = vec![mgr2_handle
                    .call(move |this| this.get_block(id))
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap()];
                mgr2.handle_mut()
                    .send_response(
                        request_id,
                        Response::BlockListResponse(BlockListResponse::new(blocks)),
                    )
                    .await
                    .unwrap();
            }
            SyncingEvent::Response {
                peer_id: _,
                request_id: _,
                response: Response::HeaderListResponse(_response),
            } => {}
            msg => panic!("invalid message received: {:?}", msg),
        }
    }

    let mut mgr1 = handle.await.unwrap();
    mgr1.update_state();

    assert!(same_tip(&mgr1_handle, &mgr2_handle).await);
    assert_eq!(mgr1.state(), &SyncState::Done);
}

// local and remote nodes are in the same chain but local is ahead of remote by 12 blocks
async fn local_ahead_by_12_blocks<A, T>()
where
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
    T: NetworkingService + 'static + Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let addr1 = A::make_address();
    let addr2 = A::make_address();

    let config = Arc::new(common::chain::config::create_unit_test_config());
    let (handle1, handle2) = init_chainstate_2(Arc::clone(&config), 8).await;
    let mgr1_handle = handle1.clone();
    let mgr2_handle = handle2.clone();

    let (mut mgr1, mut conn1, _, _) =
        make_sync_manager::<T>(A::make_transport(), addr1, handle1, P2pConfig::default()).await;
    let (mut mgr2, mut conn2, _, _) =
        make_sync_manager::<T>(A::make_transport(), addr2, handle2, P2pConfig::default()).await;

    // add 12 more blocks on top of the best block (which is also known by mgr2)
    assert!(same_tip(&mgr1_handle, &mgr2_handle).await);
    p2p_test_utils::add_more_blocks(Arc::clone(&config), &mgr1_handle, 12).await;
    assert!(!same_tip(&mgr1_handle, &mgr2_handle).await);

    // add peer to the hashmap of known peers and send getheaders request to them
    connect_services::<T>(&mut conn1, &mut conn2).await;
    assert_eq!(mgr1.register_peer(*conn2.peer_id()).await, Ok(()));
    assert_eq!(mgr2.register_peer(*conn1.peer_id()).await, Ok(()));

    let handle = tokio::spawn(async move {
        for _ in 0..14 {
            advance_mgr_state(&mut mgr1).await.unwrap();
        }

        mgr1
    });

    let mut work = VecDeque::new();

    loop {
        match mgr2.handle_mut().poll_next().await.unwrap() {
            SyncingEvent::Request {
                peer_id: _,
                request_id,
                request: Request::HeaderListRequest(request),
            } => {
                let headers = mgr2_handle
                    .call(move |this| this.get_headers(request.into_locator()))
                    .await
                    .unwrap()
                    .unwrap();
                mgr2.handle_mut()
                    .send_response(
                        request_id,
                        Response::HeaderListResponse(HeaderListResponse::new(headers)),
                    )
                    .await
                    .unwrap()
            }
            SyncingEvent::Response {
                peer_id,
                request_id: _,
                response: Response::BlockListResponse(response),
            } => {
                assert_eq!(response.blocks().len(), 1);
                let block = response.blocks()[0].clone();
                mgr2_handle
                    .call_mut(move |this| this.process_block(block, BlockSource::Peer))
                    .await
                    .unwrap()
                    .unwrap();

                if let Some(header) = work.pop_front() {
                    mgr2.handle_mut()
                        .send_request(
                            peer_id,
                            Request::BlockListRequest(BlockListRequest::new(vec![header])),
                        )
                        .await
                        .unwrap();
                } else {
                    // all blocks have been downloaded
                    break;
                }
            }
            SyncingEvent::Response {
                peer_id,
                request_id: _,
                response: Response::HeaderListResponse(response),
            } => {
                assert_eq!(response.headers().len(), 12);
                let headers = mgr2_handle
                    .call(move |this| this.filter_already_existing_blocks(response.into_headers()))
                    .await
                    .unwrap()
                    .unwrap();
                work = headers.into_iter().map(|header| header.get_id()).collect::<VecDeque<_>>();
                let header = work.pop_front().unwrap();
                mgr2.handle_mut()
                    .send_request(
                        peer_id,
                        Request::BlockListRequest(BlockListRequest::new(vec![header])),
                    )
                    .await
                    .unwrap();
            }
            msg => panic!("invalid message received: {:?}", msg),
        }
    }

    let mut mgr1 = handle.await.unwrap();
    mgr1.update_state();
    mgr2.update_state();

    assert!(same_tip(&mgr1_handle, &mgr2_handle).await);
    assert_eq!(mgr1.state(), &SyncState::Done);
}

// local and remote nodes are in the same chain but local is ahead of remote by 14 blocks
// verify that remote nodes does a reorg
async fn remote_local_diff_chains_local_higher<A, S>()
where
    A: TestTransportMaker<Transport = S::Transport, Address = S::Address>,
    S: NetworkingService + Debug + 'static,
    S::ConnectivityHandle: ConnectivityService<S>,
    S::SyncingMessagingHandle: SyncingMessagingService<S>,
{
    let addr1 = A::make_address();
    let addr2 = A::make_address();

    let config = Arc::new(common::chain::config::create_unit_test_config());
    let (handle1, handle2) = init_chainstate_2(Arc::clone(&config), 8).await;
    let mgr1_handle = handle1.clone();
    let mgr2_handle = handle2.clone();

    let (mut mgr1, mut conn1, _, _) =
        make_sync_manager::<S>(A::make_transport(), addr1, handle1, P2pConfig::default()).await;
    let (mut mgr2, mut conn2, _, _) =
        make_sync_manager::<S>(A::make_transport(), addr2, handle2, P2pConfig::default()).await;

    // add 14 more blocks to local chain and 7 more blocks to remote chain
    assert!(same_tip(&mgr1_handle, &mgr2_handle).await);
    p2p_test_utils::add_more_blocks(Arc::clone(&config), &mgr1_handle, 14).await;

    assert!(!same_tip(&mgr1_handle, &mgr2_handle).await);
    p2p_test_utils::add_more_blocks(Arc::clone(&config), &mgr2_handle, 7).await;

    // save local and remote tips so we can verify who did a reorg
    let local_tip = get_tip(&mgr1_handle).await;
    let remote_tip = get_tip(&mgr2_handle).await;

    // add peer to the hashmap of known peers and send getheaders request to them
    connect_services::<S>(&mut conn1, &mut conn2).await;
    assert_eq!(mgr1.register_peer(*conn2.peer_id()).await, Ok(()));
    assert_eq!(mgr2.register_peer(*conn1.peer_id()).await, Ok(()));

    let handle = tokio::spawn(async move {
        for _ in 0..24 {
            advance_mgr_state(&mut mgr1).await.unwrap();
        }

        mgr1
    });

    let mut work = VecDeque::new();

    for _ in 0..24 {
        match mgr2.handle_mut().poll_next().await.unwrap() {
            SyncingEvent::Request {
                peer_id: _,
                request_id,
                request: Request::HeaderListRequest(request),
            } => {
                let headers = mgr2_handle
                    .call(move |this| this.get_headers(request.into_locator()))
                    .await
                    .unwrap()
                    .unwrap();
                mgr2.handle_mut()
                    .send_response(
                        request_id,
                        Response::HeaderListResponse(HeaderListResponse::new(headers)),
                    )
                    .await
                    .unwrap()
            }
            SyncingEvent::Request {
                peer_id: _,
                request_id,
                request: Request::BlockListRequest(request),
            } => {
                assert_eq!(request.block_ids().len(), 1);
                let id = request.block_ids()[0];
                let blocks = vec![mgr2_handle
                    .call(move |this| this.get_block(id))
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap()];
                mgr2.handle_mut()
                    .send_response(
                        request_id,
                        Response::BlockListResponse(BlockListResponse::new(blocks)),
                    )
                    .await
                    .unwrap();
            }
            SyncingEvent::Response {
                peer_id,
                request_id: _,
                response: Response::BlockListResponse(response),
            } => {
                assert_eq!(response.blocks().len(), 1);
                let block = response.blocks()[0].clone();
                mgr2_handle
                    .call_mut(move |this| this.process_block(block, BlockSource::Peer))
                    .await
                    .unwrap()
                    .unwrap();

                if let Some(header) = work.pop_front() {
                    mgr2.handle_mut()
                        .send_request(
                            peer_id,
                            Request::BlockListRequest(BlockListRequest::new(vec![header])),
                        )
                        .await
                        .unwrap();
                }
            }
            SyncingEvent::Response {
                peer_id,
                request_id: _,
                response: Response::HeaderListResponse(response),
            } => {
                let headers = mgr2_handle
                    .call(move |this| this.filter_already_existing_blocks(response.into_headers()))
                    .await
                    .unwrap()
                    .unwrap();
                work = headers.into_iter().map(|header| header.get_id()).collect::<VecDeque<_>>();
                let header = work.pop_front().unwrap();
                mgr2.handle_mut()
                    .send_request(
                        peer_id,
                        Request::BlockListRequest(BlockListRequest::new(vec![header])),
                    )
                    .await
                    .unwrap();
            }
            msg => panic!("invalid message received: {:?}", msg),
        }
    }

    let mut mgr1 = handle.await.unwrap();
    mgr1.update_state();
    mgr2.update_state();

    assert!(same_tip(&mgr1_handle, &mgr2_handle).await);
    assert!(get_tip(&mgr1_handle).await == local_tip);
    assert!(get_tip(&mgr2_handle).await != remote_tip);
    assert_eq!(mgr1.state(), &SyncState::Done);
}

// local and remote nodes are in different chains and remote has longer chain
// verify that local node does a reorg
async fn remote_local_diff_chains_remote_higher<A, S>()
where
    A: TestTransportMaker<Transport = S::Transport, Address = S::Address>,
    S: NetworkingService + 'static + Debug,
    S::ConnectivityHandle: ConnectivityService<S>,
    S::SyncingMessagingHandle: SyncingMessagingService<S>,
{
    let addr1 = A::make_address();
    let addr2 = A::make_address();

    let config = Arc::new(common::chain::config::create_unit_test_config());
    let (handle1, handle2) = init_chainstate_2(Arc::clone(&config), 8).await;
    let mgr1_handle = handle1.clone();
    let mgr2_handle = handle2.clone();

    let (mut mgr1, mut conn1, _, _) =
        make_sync_manager::<S>(A::make_transport(), addr1, handle1, P2pConfig::default()).await;
    let (mut mgr2, mut conn2, _, _) =
        make_sync_manager::<S>(A::make_transport(), addr2, handle2, P2pConfig::default()).await;

    // add 5 more blocks to local chain and 12 more blocks to remote chain
    assert!(same_tip(&mgr1_handle, &mgr2_handle).await);
    p2p_test_utils::add_more_blocks(Arc::clone(&config), &mgr1_handle, 5).await;

    assert!(!same_tip(&mgr1_handle, &mgr2_handle).await);
    p2p_test_utils::add_more_blocks(Arc::clone(&config), &mgr2_handle, 12).await;

    // save local and remote tips so we can verify who did a reorg
    let local_tip = get_tip(&mgr1_handle).await;
    let remote_tip = get_tip(&mgr2_handle).await;

    // add peer to the hashmap of known peers and send getheaders request to them
    connect_services::<S>(&mut conn1, &mut conn2).await;
    assert_eq!(mgr1.register_peer(*conn2.peer_id()).await, Ok(()));
    assert_eq!(mgr2.register_peer(*conn1.peer_id()).await, Ok(()));

    let handle = tokio::spawn(async move {
        for _ in 0..20 {
            advance_mgr_state(&mut mgr1).await.unwrap();
        }

        mgr1
    });

    let mut work = VecDeque::new();

    for _ in 0..20 {
        match mgr2.handle_mut().poll_next().await.unwrap() {
            SyncingEvent::Request {
                peer_id: _,
                request_id,
                request: Request::HeaderListRequest(request),
            } => {
                let headers = mgr2_handle
                    .call(move |this| this.get_headers(request.into_locator()))
                    .await
                    .unwrap()
                    .unwrap();
                mgr2.handle_mut()
                    .send_response(
                        request_id,
                        Response::HeaderListResponse(HeaderListResponse::new(headers)),
                    )
                    .await
                    .unwrap()
            }
            SyncingEvent::Request {
                peer_id: _,
                request_id,
                request: Request::BlockListRequest(request),
            } => {
                assert_eq!(request.block_ids().len(), 1);
                let id = request.block_ids()[0];
                let blocks = vec![mgr2_handle
                    .call(move |this| this.get_block(id))
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap()];
                mgr2.handle_mut()
                    .send_response(
                        request_id,
                        Response::BlockListResponse(BlockListResponse::new(blocks)),
                    )
                    .await
                    .unwrap();
            }
            SyncingEvent::Response {
                peer_id,
                request_id: _,
                response: Response::BlockListResponse(response),
            } => {
                assert_eq!(response.blocks().len(), 1);
                let block = response.blocks()[0].clone();
                mgr2_handle
                    .call_mut(move |this| this.process_block(block, BlockSource::Peer))
                    .await
                    .unwrap()
                    .unwrap();

                if let Some(header) = work.pop_front() {
                    mgr2.handle_mut()
                        .send_request(
                            peer_id,
                            Request::BlockListRequest(BlockListRequest::new(vec![header])),
                        )
                        .await
                        .unwrap();
                }
            }
            SyncingEvent::Response {
                peer_id,
                request_id: _,
                response: Response::HeaderListResponse(response),
            } => {
                let headers = mgr2_handle
                    .call(move |this| this.filter_already_existing_blocks(response.into_headers()))
                    .await
                    .unwrap()
                    .unwrap();
                work = headers.into_iter().map(|header| header.get_id()).collect::<VecDeque<_>>();
                let header = work.pop_front().unwrap();
                mgr2.handle_mut()
                    .send_request(
                        peer_id,
                        Request::BlockListRequest(BlockListRequest::new(vec![header])),
                    )
                    .await
                    .unwrap();
            }
            msg => panic!("invalid message received: {:?}", msg),
        }
    }

    let mut mgr1 = handle.await.unwrap();
    mgr1.update_state();
    mgr2.update_state();

    assert!(same_tip(&mgr1_handle, &mgr2_handle).await);
    assert!(get_tip(&mgr1_handle).await != local_tip);
    assert!(get_tip(&mgr2_handle).await == remote_tip);
    assert_eq!(mgr1.state(), &SyncState::Done);
}

async fn two_remote_nodes_different_chains<A, S>()
where
    A: TestTransportMaker<Transport = S::Transport, Address = S::Address>,
    S: NetworkingService + 'static + Debug,
    S::ConnectivityHandle: ConnectivityService<S>,
    S::SyncingMessagingHandle: SyncingMessagingService<S>,
{
    let config = Arc::new(common::chain::config::create_unit_test_config());
    let (handle1, handle2, handle3) = init_chainstate_3(Arc::clone(&config), 8).await;
    let mgr1_handle = handle1.clone();
    let mgr2_handle = handle2.clone();
    let mgr3_handle = handle3.clone();

    let (mut mgr1, mut conn1, _, _) = make_sync_manager::<S>(
        A::make_transport(),
        A::make_address(),
        handle1,
        P2pConfig::default(),
    )
    .await;
    let (mut mgr2, mut conn2, _, _) = make_sync_manager::<S>(
        A::make_transport(),
        A::make_address(),
        handle2,
        P2pConfig::default(),
    )
    .await;
    let (mut mgr3, mut conn3, _, _) = make_sync_manager::<S>(
        A::make_transport(),
        A::make_address(),
        handle3,
        P2pConfig::default(),
    )
    .await;

    // add 5 more blocks for first remote and 7 blocks to second remote
    p2p_test_utils::add_more_blocks(Arc::clone(&config), &mgr2_handle, 5).await;
    p2p_test_utils::add_more_blocks(Arc::clone(&config), &mgr3_handle, 7).await;

    // save local and remote tips so we can verify who did a reorg
    let mgr2_tip = get_tip(&mgr2_handle).await;
    let mgr3_tip = get_tip(&mgr3_handle).await;

    // connect remote peers to local peer
    connect_services::<S>(&mut conn1, &mut conn2).await;
    connect_services::<S>(&mut conn1, &mut conn3).await;

    assert_eq!(mgr1.register_peer(*conn2.peer_id()).await, Ok(()));
    assert_eq!(mgr1.register_peer(*conn3.peer_id()).await, Ok(()));
    assert_eq!(mgr2.register_peer(*conn1.peer_id()).await, Ok(()));
    assert_eq!(mgr3.register_peer(*conn1.peer_id()).await, Ok(()));

    let handle = tokio::spawn(async move {
        for _ in 0..18 {
            advance_mgr_state(&mut mgr1).await.unwrap();
        }

        mgr1
    });

    for _ in 0..18 {
        let (event, dest_peer_id, mgr_handle) = tokio::select! {
            event = mgr2.handle_mut().poll_next() => { (event.unwrap(), conn2.peer_id(), &mgr2_handle) },
            event = mgr3.handle_mut().poll_next() => { (event.unwrap(), conn3.peer_id(), &mgr3_handle) },
        };

        match event {
            SyncingEvent::Request {
                peer_id: _,
                request_id,
                request: Request::HeaderListRequest(request),
            } => {
                let headers = mgr_handle
                    .call(move |this| this.get_headers(request.into_locator()))
                    .await
                    .unwrap()
                    .unwrap();
                let msg = Response::HeaderListResponse(HeaderListResponse::new(headers));

                if dest_peer_id == conn2.peer_id() {
                    mgr2.handle_mut().send_response(request_id, msg).await.unwrap()
                } else {
                    mgr3.handle_mut().send_response(request_id, msg).await.unwrap()
                }
            }
            SyncingEvent::Request {
                peer_id: _,
                request_id,
                request: Request::BlockListRequest(request),
            } => {
                assert_eq!(request.block_ids().len(), 1);
                let id = request.block_ids()[0];
                let msg = Response::BlockListResponse(BlockListResponse::new(vec![mgr_handle
                    .call(move |this| this.get_block(id))
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap()]));

                if dest_peer_id == conn2.peer_id() {
                    mgr2.handle_mut().send_response(request_id, msg).await.unwrap();
                } else {
                    mgr3.handle_mut().send_response(request_id, msg).await.unwrap();
                }
            }
            SyncingEvent::Response {
                peer_id: _,
                request_id: _,
                response: Response::HeaderListResponse(_response),
            } => {}
            msg => panic!("invalid message received: {:?}", msg),
        }
    }
    let mut mgr1 = handle.await.unwrap();
    mgr1.update_state();

    assert!(same_tip(&mgr1_handle, &mgr3_handle).await);
    assert!(get_tip(&mgr2_handle).await == mgr2_tip);
    assert!(get_tip(&mgr3_handle).await == mgr3_tip);
    assert_eq!(mgr1.state(), &SyncState::Done);
}

async fn two_remote_nodes_same_chains<A, S>()
where
    A: TestTransportMaker<Transport = S::Transport, Address = S::Address>,
    S: NetworkingService + 'static + Debug,
    S::ConnectivityHandle: ConnectivityService<S>,
    S::SyncingMessagingHandle: SyncingMessagingService<S>,
{
    let config = Arc::new(common::chain::config::create_unit_test_config());
    let (handle1, handle2, handle3) = init_chainstate_3(Arc::clone(&config), 8).await;
    let mgr1_handle = handle1.clone();
    let mgr2_handle = handle2.clone();
    let mgr3_handle = handle3.clone();

    let (mut mgr1, mut conn1, _, _) = make_sync_manager::<S>(
        A::make_transport(),
        A::make_address(),
        handle1,
        P2pConfig::default(),
    )
    .await;
    let (mut mgr2, mut conn2, _, _) = make_sync_manager::<S>(
        A::make_transport(),
        A::make_address(),
        handle2,
        P2pConfig::default(),
    )
    .await;
    let (mut mgr3, mut conn3, _, _) = make_sync_manager::<S>(
        A::make_transport(),
        A::make_address(),
        handle3,
        P2pConfig::default(),
    )
    .await;

    // add the same 32 new blocks for both mgr2 and mgr3
    let blocks = p2p_test_utils::create_n_blocks(
        Arc::clone(&config),
        TestBlockInfo::from_tip(&mgr2_handle, &config).await,
        32,
    );

    p2p_test_utils::import_blocks(&mgr2_handle, blocks.clone()).await;
    p2p_test_utils::import_blocks(&mgr3_handle, blocks).await;

    // save local and remote tips so we can verify who did a reorg
    let mgr2_tip = get_tip(&mgr2_handle).await;
    let mgr3_tip = get_tip(&mgr3_handle).await;

    assert!(same_tip(&mgr2_handle, &mgr3_handle).await);
    assert!(!same_tip(&mgr2_handle, &mgr1_handle).await);

    // connect remote peers to local peer
    connect_services::<S>(&mut conn1, &mut conn2).await;
    connect_services::<S>(&mut conn1, &mut conn3).await;

    assert_eq!(mgr1.register_peer(*conn2.peer_id()).await, Ok(()));
    assert_eq!(mgr1.register_peer(*conn3.peer_id()).await, Ok(()));
    assert_eq!(mgr2.register_peer(*conn1.peer_id()).await, Ok(()));
    assert_eq!(mgr3.register_peer(*conn1.peer_id()).await, Ok(()));

    let (tx, mut rx) = mpsc::unbounded_channel();
    let handle = tokio::spawn(async move {
        loop {
            advance_mgr_state(&mut mgr1).await.unwrap();

            if mgr1.state() == &SyncState::Done {
                break;
            }
        }

        tx.send(()).unwrap();
        mgr1
    });

    loop {
        let (event, dest_peer_id, mgr_handle) = tokio::select! {
            event = mgr2.handle_mut().poll_next() => { (event.unwrap(), conn2.peer_id(), &mgr2_handle) },
            event = mgr3.handle_mut().poll_next() => { (event.unwrap(), conn3.peer_id(), &mgr3_handle) },
            _event = rx.recv() => { break },
        };

        match event {
            SyncingEvent::Request {
                peer_id: _,
                request_id,
                request: Request::HeaderListRequest(request),
            } => {
                let headers = mgr_handle
                    .call(move |this| this.get_headers(request.into_locator()))
                    .await
                    .unwrap()
                    .unwrap();
                let msg = Response::HeaderListResponse(HeaderListResponse::new(headers));

                if dest_peer_id == conn2.peer_id() {
                    mgr2.handle_mut().send_response(request_id, msg).await.unwrap()
                } else {
                    mgr3.handle_mut().send_response(request_id, msg).await.unwrap()
                }
            }
            SyncingEvent::Request {
                peer_id: _,
                request_id,
                request: Request::BlockListRequest(request),
            } => {
                assert_eq!(request.block_ids().len(), 1);
                let id = request.block_ids()[0];
                let msg = Response::BlockListResponse(BlockListResponse::new(vec![mgr_handle
                    .call(move |this| this.get_block(id))
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap()]));

                if dest_peer_id == conn2.peer_id() {
                    mgr2.handle_mut().send_response(request_id, msg).await.unwrap();
                } else {
                    mgr3.handle_mut().send_response(request_id, msg).await.unwrap();
                }
            }
            SyncingEvent::Response {
                peer_id: _,
                request_id: _,
                response: Response::HeaderListResponse(_response),
            } => {}
            msg => panic!("invalid message received: {:?}", msg),
        }
    }
    let mut mgr1 = handle.await.unwrap();
    mgr1.update_state();

    assert!(same_tip(&mgr1_handle, &mgr3_handle).await);
    assert!(get_tip(&mgr2_handle).await == mgr2_tip);
    assert!(get_tip(&mgr3_handle).await == mgr3_tip);
    assert_eq!(mgr1.state(), &SyncState::Done);
}

async fn two_remote_nodes_same_chains_new_blocks<A, S>()
where
    A: TestTransportMaker<Transport = S::Transport, Address = S::Address>,
    S: NetworkingService + 'static + Debug,
    S::ConnectivityHandle: ConnectivityService<S>,
    S::SyncingMessagingHandle: SyncingMessagingService<S>,
{
    let config = Arc::new(common::chain::config::create_unit_test_config());
    let (handle1, handle2, handle3) = init_chainstate_3(Arc::clone(&config), 8).await;
    let mgr1_handle = handle1.clone();
    let mgr2_handle = handle2.clone();
    let mgr3_handle = handle3.clone();

    let (mut mgr1, mut conn1, _, _) = make_sync_manager::<S>(
        A::make_transport(),
        A::make_address(),
        handle1,
        P2pConfig::default(),
    )
    .await;
    let (mut mgr2, mut conn2, _, _) = make_sync_manager::<S>(
        A::make_transport(),
        A::make_address(),
        handle2,
        P2pConfig::default(),
    )
    .await;
    let (mut mgr3, mut conn3, _, _) = make_sync_manager::<S>(
        A::make_transport(),
        A::make_address(),
        handle3,
        P2pConfig::default(),
    )
    .await;

    // add the same 32 new blocks for both mgr2 and mgr3
    let blocks = p2p_test_utils::create_n_blocks(
        Arc::clone(&config),
        TestBlockInfo::from_tip(&mgr2_handle, &config).await,
        32,
    );

    p2p_test_utils::import_blocks(&mgr2_handle, blocks.clone()).await;
    p2p_test_utils::import_blocks(&mgr3_handle, blocks).await;

    // connect remote peers to local peer
    connect_services::<S>(&mut conn1, &mut conn2).await;
    connect_services::<S>(&mut conn1, &mut conn3).await;

    assert_eq!(mgr1.register_peer(*conn2.peer_id()).await, Ok(()));
    assert_eq!(mgr1.register_peer(*conn3.peer_id()).await, Ok(()));
    assert_eq!(mgr2.register_peer(*conn1.peer_id()).await, Ok(()));
    assert_eq!(mgr3.register_peer(*conn1.peer_id()).await, Ok(()));

    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut gethdr_received = HashSet::new();
    let mut blocks = vec![];

    let handle = tokio::spawn(async move {
        loop {
            advance_mgr_state(&mut mgr1).await.unwrap();

            if mgr1.state() == &SyncState::Done {
                break;
            }
        }

        tx.send(()).unwrap();
        mgr1
    });

    loop {
        let (event, dest_peer_id, mgr_handle) = tokio::select! {
            event = mgr2.handle_mut().poll_next() => { (event.unwrap(), conn2.peer_id(), &mgr2_handle) },
            event = mgr3.handle_mut().poll_next() => { (event.unwrap(), conn3.peer_id(), &mgr3_handle) },
            _event = rx.recv() => { break },
        };

        match event {
            SyncingEvent::Request {
                peer_id: _,
                request_id,
                request: Request::HeaderListRequest(request),
            } => {
                let headers = mgr_handle
                    .call(move |this| this.get_headers(request.into_locator()))
                    .await
                    .unwrap()
                    .unwrap();
                let msg = Response::HeaderListResponse(HeaderListResponse::new(headers));

                if dest_peer_id == conn2.peer_id() {
                    mgr2.handle_mut().send_response(request_id, msg).await.unwrap()
                } else {
                    mgr3.handle_mut().send_response(request_id, msg).await.unwrap()
                }

                if gethdr_received.insert(dest_peer_id) {
                    if blocks.is_empty() {
                        blocks = p2p_test_utils::create_n_blocks(
                            Arc::clone(&config),
                            TestBlockInfo::from_tip(&mgr2_handle, &config).await,
                            10,
                        );
                    }

                    if dest_peer_id == conn2.peer_id() {
                        p2p_test_utils::import_blocks(&mgr2_handle, blocks.clone()).await;
                    } else {
                        p2p_test_utils::import_blocks(&mgr3_handle, blocks.clone()).await;
                    }
                }
            }
            SyncingEvent::Request {
                peer_id: _,
                request_id,
                request: Request::BlockListRequest(request),
            } => {
                assert_eq!(request.block_ids().len(), 1);
                let id = request.block_ids()[0];
                let msg = Response::BlockListResponse(BlockListResponse::new(vec![mgr_handle
                    .call(move |this| this.get_block(id))
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap()]));

                if dest_peer_id == conn2.peer_id() {
                    mgr2.handle_mut().send_response(request_id, msg).await.unwrap();
                } else {
                    mgr3.handle_mut().send_response(request_id, msg).await.unwrap();
                }
            }
            SyncingEvent::Response {
                peer_id: _,
                request_id: _,
                response: Response::HeaderListResponse(_response),
            } => {}
            msg => panic!("invalid message received: {:?}", msg),
        }
    }
    let mut mgr1 = handle.await.unwrap();
    mgr1.update_state();

    assert!(same_tip(&mgr1_handle, &mgr3_handle).await);
    assert!(same_tip(&mgr2_handle, &mgr3_handle).await);
    assert_eq!(mgr1.state(), &SyncState::Done);
}

// // connect two nodes, they are in sync so no blocks are downloaded
// // then disconnect them, add more blocks to remote chains and reconnect the nodes
// // verify that local node downloads the blocks and after that they are in sync
async fn connect_disconnect_resyncing<A, S>()
where
    A: TestTransportMaker<Transport = S::Transport, Address = S::Address>,
    S: NetworkingService + 'static + Debug,
    S::ConnectivityHandle: ConnectivityService<S>,
    S::SyncingMessagingHandle: SyncingMessagingService<S>,
{
    let config = Arc::new(common::chain::config::create_unit_test_config());
    let (handle1, handle2) = init_chainstate_2(Arc::clone(&config), 8).await;
    let mgr1_handle = handle1.clone();
    let mgr2_handle = handle2.clone();

    let (mut mgr1, mut conn1, _, _) = make_sync_manager::<S>(
        A::make_transport(),
        A::make_address(),
        handle1,
        P2pConfig::default(),
    )
    .await;
    let (mut mgr2, mut conn2, _, _) = make_sync_manager::<S>(
        A::make_transport(),
        A::make_address(),
        handle2,
        P2pConfig::default(),
    )
    .await;

    connect_services::<S>(&mut conn1, &mut conn2).await;
    assert_eq!(mgr1.register_peer(*conn2.peer_id()).await, Ok(()));

    // ensure that only a header request is received from the remote and
    // as the nodes are tracking the same chain, no further messages are exchanged
    let (res1, res2) = tokio::join!(
        process_header_request(&mut mgr2, &mgr2_handle),
        advance_mgr_state(&mut mgr1)
    );

    assert_eq!(res1, Ok(()));
    assert_eq!(res2, Ok(()));

    assert!(same_tip(&mgr1_handle, &mgr2_handle).await);
    assert_eq!(mgr1.state(), &SyncState::Done);

    mgr1.unregister_peer(*conn2.peer_id());
    assert_eq!(conn1.disconnect(*conn2.peer_id()).await, Ok(()));
    assert!(std::matches!(
        conn2.poll_next().await,
        Ok(ConnectivityEvent::ConnectionClosed { .. })
    ));
    assert!(std::matches!(
        conn1.poll_next().await,
        Ok(ConnectivityEvent::ConnectionClosed { .. })
    ));

    let parent_info = TestBlockInfo::from_tip(&mgr1_handle, &config).await;
    let blocks = p2p_test_utils::create_n_blocks(Arc::clone(&config), parent_info, 7);
    p2p_test_utils::import_blocks(&mgr2_handle, blocks.clone()).await;

    connect_services::<S>(&mut conn1, &mut conn2).await;
    assert_eq!(mgr1.register_peer(*conn2.peer_id()).await, Ok(()));

    let handle = tokio::spawn(async move {
        for _ in 0..9 {
            advance_mgr_state(&mut mgr1).await.unwrap();
        }

        mgr1
    });

    for _ in 0..9 {
        match mgr2.handle_mut().poll_next().await.unwrap() {
            SyncingEvent::Request {
                peer_id: _,
                request_id,
                request: Request::HeaderListRequest(request),
            } => {
                let headers = mgr2_handle
                    .call(move |this| this.get_headers(request.into_locator()))
                    .await
                    .unwrap()
                    .unwrap();
                mgr2.handle_mut()
                    .send_response(
                        request_id,
                        Response::HeaderListResponse(HeaderListResponse::new(headers)),
                    )
                    .await
                    .unwrap()
            }
            SyncingEvent::Request {
                peer_id: _,
                request_id,
                request: Request::BlockListRequest(request),
            } => {
                assert_eq!(request.block_ids().len(), 1);
                let id = request.block_ids()[0];
                let blocks = vec![mgr2_handle
                    .call(move |this| this.get_block(id))
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap()];
                mgr2.handle_mut()
                    .send_response(
                        request_id,
                        Response::BlockListResponse(BlockListResponse::new(blocks)),
                    )
                    .await
                    .unwrap();
            }
            SyncingEvent::Response {
                peer_id: _,
                request_id: _,
                response: Response::HeaderListResponse(_response),
            } => {}
            msg => panic!("invalid message received: {:?}", msg),
        }
    }

    let mut mgr1 = handle.await.unwrap();
    mgr1.update_state();

    assert!(same_tip(&mgr1_handle, &mgr2_handle).await);
    assert_eq!(mgr1.state(), &SyncState::Done);
}

// Check that the peer that ignores requests is disconnected.
async fn disconnect_unresponsive_peer<A, T>()
where
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
    T: NetworkingService + 'static + Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let config = Arc::new(common::chain::config::create_unit_test_config());
    let (chainstate1, chainstate2) = init_chainstate_2(Arc::clone(&config), 8).await;
    let p2p_config = P2pConfig {
        bind_address: "/ip6/::1/tcp/3031".to_owned().into(),
        ban_threshold: 100.into(),
        ban_duration: Default::default(),
        outbound_connection_timeout: 10.into(),
        mdns_config: MdnsConfig::Disabled.into(),
        node_type: NodeType::Full.into(),
        max_tip_age: Default::default(),
    };
    let (mut mgr1, mut conn1, _sync1, mut pm1) = make_sync_manager::<T>(
        A::make_transport(),
        A::make_address(),
        chainstate1,
        p2p_config,
    )
    .await;
    let (_mgr2, mut conn2, _sync2, _pm2) = make_sync_manager::<T>(
        A::make_transport(),
        A::make_address(),
        chainstate2,
        P2pConfig::default(),
    )
    .await;

    connect_services::<T>(&mut conn1, &mut conn2).await;
    let peer2_id = *conn2.peer_id();

    tokio::spawn(async move {
        mgr1.register_peer(peer2_id).await.unwrap();
        mgr1.run().await.unwrap();
    });

    match pm1.recv().await.unwrap() {
        PeerManagerEvent::Disconnect(peer_id, _) => assert_eq!(peer_id, peer2_id),
        e => panic!("Unexpected peer manager event: {e:?}"),
    }
}

async fn make_sync_manager<T>(
    transport: T::Transport,
    addr: T::Address,
    chainstate: subsystem::Handle<Box<dyn ChainstateInterface>>,
    p2p_config: P2pConfig,
) -> (
    BlockSyncManager<T>,
    T::ConnectivityHandle,
    mpsc::UnboundedSender<SyncControlEvent<T>>,
    mpsc::UnboundedReceiver<PeerManagerEvent<T>>,
)
where
    T: NetworkingService,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
    T::SyncingPeerRequestId: 'static,
    T::PeerId: 'static,
{
    let (tx_p2p_sync, rx_p2p_sync) = mpsc::unbounded_channel();
    let (tx_peer_manager, rx_peer_manager) = mpsc::unbounded_channel();

    let chain_config = Arc::new(common::chain::config::create_mainnet());
    let p2p_config = Arc::new(p2p_config);
    let (conn, sync) = T::start(
        transport,
        addr,
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
    )
    .await
    .unwrap();

    (
        BlockSyncManager::<T>::new(
            chain_config,
            p2p_config,
            sync,
            chainstate,
            rx_p2p_sync,
            tx_peer_manager,
        ),
        conn,
        tx_p2p_sync,
        rx_peer_manager,
    )
}

// initialize two blockchains which have the same longest chain that is `num_blocks` long
async fn init_chainstate_2(
    config: Arc<ChainConfig>,
    num_blocks: usize,
) -> (
    subsystem::Handle<Box<dyn ChainstateInterface>>,
    subsystem::Handle<Box<dyn ChainstateInterface>>,
) {
    let handle1 = p2p_test_utils::start_chainstate(Arc::clone(&config)).await;
    let handle2 = p2p_test_utils::start_chainstate(Arc::clone(&config)).await;
    let blocks = p2p_test_utils::create_n_blocks(
        Arc::clone(&config),
        TestBlockInfo::from_genesis(config.genesis_block()),
        num_blocks,
    );

    p2p_test_utils::import_blocks(&handle1, blocks.clone()).await;
    p2p_test_utils::import_blocks(&handle2, blocks).await;

    (handle1, handle2)
}

async fn init_chainstate_3(
    config: Arc<ChainConfig>,
    num_blocks: usize,
) -> (
    subsystem::Handle<Box<dyn ChainstateInterface>>,
    subsystem::Handle<Box<dyn ChainstateInterface>>,
    subsystem::Handle<Box<dyn ChainstateInterface>>,
) {
    let handle1 = p2p_test_utils::start_chainstate(Arc::clone(&config)).await;
    let handle2 = p2p_test_utils::start_chainstate(Arc::clone(&config)).await;
    let handle3 = p2p_test_utils::start_chainstate(Arc::clone(&config)).await;
    let blocks = p2p_test_utils::create_n_blocks(
        Arc::clone(&config),
        TestBlockInfo::from_genesis(config.genesis_block()),
        num_blocks,
    );

    p2p_test_utils::import_blocks(&handle1, blocks.clone()).await;
    p2p_test_utils::import_blocks(&handle2, blocks.clone()).await;
    p2p_test_utils::import_blocks(&handle3, blocks).await;

    (handle1, handle2, handle3)
}

async fn same_tip(
    handle1: &subsystem::Handle<Box<dyn ChainstateInterface>>,
    handle2: &subsystem::Handle<Box<dyn ChainstateInterface>>,
) -> bool {
    get_tip(handle1).await == get_tip(handle2).await
}

async fn get_tip(handle: &subsystem::Handle<Box<dyn ChainstateInterface>>) -> Id<GenBlock> {
    handle.call(move |this| this.get_best_block_id()).await.unwrap().unwrap()
}

async fn process_header_request<T>(
    mgr: &mut BlockSyncManager<T>,
    handle: &subsystem::Handle<Box<dyn ChainstateInterface>>,
) -> Result<(), P2pError>
where
    T: NetworkingService,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
    T::SyncingPeerRequestId: 'static,
    T::PeerId: 'static,
{
    match mgr.handle_mut().poll_next().await.unwrap() {
        SyncingEvent::Request {
            peer_id: _,
            request_id,
            request: Request::HeaderListRequest(request),
        } => {
            let headers = handle
                .call(move |this| this.get_headers(request.into_locator()))
                .await
                .unwrap()
                .unwrap();
            mgr.handle_mut()
                .send_response(
                    request_id,
                    Response::HeaderListResponse(HeaderListResponse::new(headers)),
                )
                .await
        }
        _ => panic!("invalid message"),
    }
}

async fn advance_mgr_state<T>(mgr: &mut BlockSyncManager<T>) -> Result<(), P2pError>
where
    T: NetworkingService,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
    T::SyncingPeerRequestId: 'static,
    T::PeerId: 'static,
{
    match mgr.handle_mut().poll_next().await.unwrap() {
        SyncingEvent::Request {
            peer_id,
            request_id,
            request,
        } => match request {
            Request::HeaderListRequest(request) => {
                mgr.process_header_request(peer_id, request_id, request.into_locator()).await?;
            }
            Request::BlockListRequest(request) => {
                mgr.process_block_request(peer_id, request_id, request.into_block_ids()).await?;
            }
        },
        SyncingEvent::Response {
            peer_id,
            request_id: _,
            response,
        } => match response {
            Response::HeaderListResponse(response) => {
                mgr.process_header_response(peer_id, response.into_headers()).await?;
            }
            Response::BlockListResponse(response) => {
                mgr.process_block_response(peer_id, response.into_blocks()).await?;
            }
        },
        SyncingEvent::Announcement {
            peer_id,
            message_id,
            announcement,
        } => {
            mgr.process_announcement(peer_id, message_id, announcement).await?;
        }
    }

    mgr.update_state();
    Ok(())
}
