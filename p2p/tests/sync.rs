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
#![cfg(not(loom))]
#![allow(unused)]

use common::chain::config;
use common::chain::ChainConfig;
use futures::FutureExt;
use logging::log;
use p2p::{
    error::{self, P2pError},
    event,
    message::{self, MessageType, SyncingMessage},
    net::{self, mock::MockService, FloodsubService, FloodsubTopic, NetworkService},
    sync::{mock_consensus, SyncManager, SyncState},
};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
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
    for _ in 0..blocks {
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
    remote: &[mock_consensus::BlockHeader],
) {
    get_message!(
        rx.recv().await.unwrap(),
        event::P2pEvent::GetUniqHeaders { headers, response },
        {
            let uniq = cons.get_uniq_headers(&headers);
            assert_eq!(&uniq, remote);
            if uniq.is_empty() {
                response.send(None);
            } else {
                response.send(Some(uniq));
            }
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

async fn peer_get_headers<T, F, Fut>(
    rx: &mut mpsc::Receiver<event::PeerEvent<T>>,
    cons: &mut mock_consensus::Consensus,
    f: F,
) where
    T: NetworkService + std::fmt::Debug,
    F: FnOnce(Vec<mock_consensus::BlockHeader>) -> Fut,
    Fut: futures::Future<Output = ()>,
{
    get_message!(
        rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::SyncEvent::GetHeaders { locator }),
        {
            f(cons.get_headers(&locator)).await;
        }
    );
}

async fn make_sync_manager<T>(
    addr: T::Address,
) -> (
    SyncManager<T>,
    mpsc::Sender<event::SyncControlEvent<T>>,
    mpsc::Sender<event::PeerSyncEvent<T>>,
    mpsc::Receiver<event::P2pEvent>,
)
where
    T: NetworkService + std::fmt::Debug,
    T::FloodsubHandle: FloodsubService<T>,
{
    let (tx_sync, rx_sync) = tokio::sync::mpsc::channel(16);
    let (tx_peer, rx_peer) = tokio::sync::mpsc::channel(16);
    let (tx_p2p, rx_p2p) = tokio::sync::mpsc::channel(16);
    let (tx_sf, rx_sf) = tokio::sync::mpsc::channel(16);
    let (tx_fs, rx_fs) = tokio::sync::mpsc::channel(16);

    (
        SyncManager::<T>::new(tx_sf, rx_fs, tx_p2p, rx_sync, rx_peer),
        tx_sync,
        tx_peer,
        rx_p2p,
    )
}

// verify that if local and remote nodes are in sync (they have the same mainchain)
// no blocks are exchanged after getheaders messages have been exchanged
#[tokio::test]
async fn local_and_remote_in_sync() {
    let addr: SocketAddr = test_utils::make_address("[::1]:");
    let (mut mgr, _, _, mut rx_p2p) = make_sync_manager::<MockService>(addr).await;
    let mut remote_cons = mock_consensus::Consensus::with_height(8);
    let ((peer_tx, mut peer_rx), peer_id) = (mpsc::channel(16), test_utils::get_random_mock_id());
    assert_eq!(mgr.state(), SyncState::Uninitialized);

    let mut local_cons = remote_cons.clone();
    let handle = tokio::spawn(async move {
        // verify that the first message that the consensus receives is the locator request
        get_locator(&mut rx_p2p, &mut local_cons).await;

        // verify that after getheaders has been sent (internally) and remote peer has responded
        // to it with their (possibly) new headers, getuniqheaders request is received and as local
        // and remote node are in sync, `get_uniq_headers()` returns an empty vector
        get_uniq_headers_and_verify(&mut rx_p2p, &mut local_cons, &[]).await;

        get_message!(
            rx_p2p.recv().await.unwrap(),
            event::P2pEvent::GetBestBlockHeader { response },
            {
                response.send(local_cons.get_best_block_header());
            }
        );

        local_cons
    });

    // add peer to the hashmap of known peers and send getheaders request to them
    assert_eq!(mgr.register_peer(peer_id, peer_tx).await, Ok(()));
    assert_eq!(mgr.advance_state().await, Ok(()));

    // verify that when the connection has been established,
    // the remote peer will receive getheaders request
    let all_headers = remote_cons.as_vec();

    peer_get_headers(&mut peer_rx, &mut remote_cons, |headers| async move {
        // verify that only the two most recent block headers are sent to local node
        assert_eq!((headers[0], headers[1]), (all_headers[1], all_headers[0]));

        assert_eq!(mgr.initialize_peer(peer_id, &headers).await, Ok(()));
        assert_eq!(mgr.advance_state().await, Ok(()));
        assert_eq!(mgr.state(), SyncState::Idle);
    })
    .await;

    let local_cons = handle.await.unwrap();
    assert_eq!(local_cons.mainchain, remote_cons.mainchain);
}

// local and remote nodes are in the same chain but remote is ahead 7 blocks
//
// this the remote node is synced first and as it's ahead of local node,
// no blocks are downloaded whereas loca node downloads the 7 new blocks from remote
#[tokio::test]
async fn remote_ahead_by_7_blocks() {
    let addr: SocketAddr = test_utils::make_address("[::1]:");
    let (mut mgr, _, _, mut rx_p2p) = make_sync_manager::<MockService>(addr).await;
    let mut remote_cons = mock_consensus::Consensus::with_height(8);
    let mut local_cons = remote_cons.clone();
    let mut new_block_hdrs = vec![];
    assert_eq!(mgr.state(), SyncState::Uninitialized);

    // add 7 more blocks to remote's chain
    for _ in 0..7 {
        let cur_id = remote_cons.mainchain.blkid;
        let block = mock_consensus::Block::new(Some(cur_id));
        new_block_hdrs.push(block.header);
        remote_cons.accept_block(block);
    }

    // verify that the chains are different
    assert_ne!(local_cons.mainchain, remote_cons.mainchain);

    let ((peer_tx, mut peer_rx), peer_id) = (mpsc::channel(16), test_utils::get_random_mock_id());

    let handle = tokio::spawn(async move {
        // verify that the first message that the consensus receives is the locator request
        get_locator(&mut rx_p2p, &mut local_cons).await;

        // verify that as the remote is ahead of local by 7 blocks, extracting the unique
        // headers from the header response results in 7 new headers and that the headers
        // belong to the 7 new blocks that were added to the remote chain
        get_uniq_headers_and_verify(&mut rx_p2p, &mut local_cons, &new_block_hdrs).await;

        // local syncmanager sent block request to remote and for each now block it receives,
        // it sends the blockindex a newblock event that tells it to accept the new block
        accept_n_blocks(&mut rx_p2p, &mut local_cons, 7).await;

        // return the updates blockindex after the tests have been run
        // so it can be compared against remote's blockindex
        local_cons
    });

    // add peer to the hashmap of known peers and send getheaders request to them
    assert_eq!(mgr.register_peer(peer_id, peer_tx).await, Ok(()));
    assert_eq!(mgr.advance_state().await, Ok(()));

    // verify that when the connection has been established,
    // the remote peer will receive getheaders request
    get_message!(
        peer_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::SyncEvent::GetHeaders { locator }),
        {
            assert_eq!(
                mgr.initialize_peer(peer_id, &remote_cons.get_headers(&locator)).await,
                Ok(())
            );
            assert_eq!(mgr.advance_state().await, Ok(()));
        }
    );

    // respond to getblocks request received from the local node
    for i in 0..7 {
        get_message!(
            peer_rx.recv().await.unwrap(),
            event::PeerEvent::Syncing(event::SyncEvent::GetBlocks { headers }),
            {
                let blocks =
                    remote_cons.get_blocks(&headers).into_iter().map(Arc::new).collect::<Vec<_>>();

                assert_eq!(mgr.process_block_response(peer_id, blocks).await, Ok(()));
                assert_eq!(mgr.advance_state().await, Ok(()));
            }
        );
    }

    let local_cons = handle.await.unwrap();
    assert_eq!(local_cons.mainchain, remote_cons.mainchain);
    assert_eq!(mgr.state(), SyncState::Idle);
}

// // local and remote nodes are in the same chain but local is ahead of remote by 12 blocks
#[tokio::test]
async fn local_ahead_by_12_blocks() {
    let addr: SocketAddr = test_utils::make_address("[::1]:");
    let (mut mgr, _, _, mut rx_p2p) = make_sync_manager::<MockService>(addr).await;
    let mut remote_cons = mock_consensus::Consensus::with_height(8);
    let mut local_cons = remote_cons.clone();
    let mut new_block_hdrs = vec![];
    assert_eq!(mgr.state(), SyncState::Uninitialized);

    // add 12 more blocks to local's chain
    for _ in 0..12 {
        let cur_id = local_cons.mainchain.blkid;
        let block = mock_consensus::Block::new(Some(cur_id));
        new_block_hdrs.push(block.header);
        local_cons.accept_block(block);
    }

    // verify that the chains are different
    assert_ne!(local_cons.mainchain, remote_cons.mainchain);

    let ((peer_tx, mut peer_rx), peer_id) = (mpsc::channel(16), test_utils::get_random_mock_id());

    let handle = tokio::spawn(async move {
        // verify that the first message that the consensus receives is the locator request
        get_locator(&mut rx_p2p, &mut local_cons).await;

        // as local is ahead of remote, getuniqheaders returns an empty vector
        get_uniq_headers_and_verify(&mut rx_p2p, &mut local_cons, &[]).await;

        get_message!(
            rx_p2p.recv().await.unwrap(),
            event::P2pEvent::GetBestBlockHeader { response },
            {
                response.send(local_cons.get_best_block_header());
            }
        );

        // verify that as the local node is ahead of remote by 12 blocks,
        // the header response contains at least 12 headers
        get_message!(
            rx_p2p.recv().await.unwrap(),
            event::P2pEvent::GetHeaders { locator, response },
            {
                let headers = local_cons.get_headers(&locator);
                assert!(headers.len() >= 12);
                response.send(headers);
            }
        );

        // verify that remote downloads the blocks it doesn't have and does a reorg
        get_blocks(&mut rx_p2p, &mut local_cons).await;

        local_cons
    });

    // add peer to the hashmap of known peers and send getheaders request to them
    assert_eq!(mgr.register_peer(peer_id, peer_tx).await, Ok(()));
    assert_eq!(mgr.advance_state().await, Ok(()));

    // verify that when the connection has been established,
    // the remote peer will receive getheaders request
    get_message!(
        peer_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::SyncEvent::GetHeaders { locator }),
        {
            assert_eq!(
                mgr.initialize_peer(peer_id, &remote_cons.get_headers(&locator),).await,
                Ok(())
            );
            assert_eq!(mgr.advance_state().await, Ok(()));
        }
    );

    let locator = remote_cons.get_locator();
    assert_eq!(mgr.process_header_request(peer_id, locator).await, Ok(()));
    assert_eq!(mgr.advance_state().await, Ok(()));

    // verify that after extracting the uniq headers from the response,
    // remote is left with 12 new block headers
    get_message!(
        peer_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::SyncEvent::Headers { headers }),
        {
            // based on the unique headers, request blocks from remote
            let uniq = remote_cons.get_uniq_headers(&headers);
            assert_eq!(uniq.len(), 12);
            assert_eq!(uniq, new_block_hdrs);
            assert_eq!(mgr.process_block_request(peer_id, &uniq,).await, Ok(()));
            assert_eq!(mgr.advance_state().await, Ok(()));
        }
    );

    // request the 12 missing blocks from remote
    get_message!(
        peer_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::SyncEvent::Blocks { blocks }),
        {
            assert_eq!(blocks.len(), 12);
            for block in blocks {
                remote_cons.accept_block(block);
            }
        }
    );

    let local_cons = handle.await.unwrap();
    assert_eq!(local_cons.mainchain, remote_cons.mainchain);
    assert_eq!(mgr.state(), SyncState::Idle);
}

// local and remote nodes are in different chains and remote has longer chain
// verify that local downloads all blocks are reorgs
#[tokio::test]
async fn remote_local_diff_chains_remote_higher() {
    let addr: SocketAddr = test_utils::make_address("[::1]:");
    let (mut mgr, _, _, mut rx_p2p) = make_sync_manager::<MockService>(addr).await;
    let mut remote_cons = mock_consensus::Consensus::with_height(8);
    let mut local_cons = remote_cons.clone();
    let mut new_remote_block_hdrs = vec![];
    let mut new_local_block_hdrs = vec![];
    assert_eq!(mgr.state(), SyncState::Uninitialized);

    // add 8 more blocks to remote's chain
    for _ in 0..8 {
        let cur_id = remote_cons.mainchain.blkid;
        let block = mock_consensus::Block::new(Some(cur_id));
        new_remote_block_hdrs.push(block.header);
        remote_cons.accept_block(block);
    }

    // add 5 more blocks to local's chain
    for _ in 0..5 {
        let cur_id = local_cons.mainchain.blkid;
        let block = mock_consensus::Block::new(Some(cur_id));
        new_local_block_hdrs.push(block.header);
        local_cons.accept_block(block);
    }

    // verify that the chains are different and make a copy of the remote chain
    let remote_orig_cons = remote_cons.clone();
    assert_ne!(local_cons.mainchain, remote_cons.mainchain);

    let ((peer_tx, mut peer_rx), peer_id) = (mpsc::channel(16), test_utils::get_random_mock_id());

    let handle = tokio::spawn(async move {
        // verify that the first message that the consensus receives is the locator request
        get_locator(&mut rx_p2p, &mut local_cons).await;

        // as remote is a different branch that has 8 new blocks since the common ancestor
        // `get_uniq_headers()` will return those headers from the entire response
        get_uniq_headers_and_verify(&mut rx_p2p, &mut local_cons, &new_remote_block_hdrs).await;

        // as the local node is in a different branch than remote that has 5 blocks
        // since the common ancestors, the response contains at least 5 headers
        get_message!(
            rx_p2p.recv().await.unwrap(),
            event::P2pEvent::GetHeaders { locator, response },
            {
                let headers = local_cons.get_headers(&locator);
                assert!(headers.len() >= 5);
                response.send(headers);
            }
        );

        // accept the 8 new blocks received from remote
        // (internally `accept_block()` des a reorg which is tested later in the test)
        accept_n_blocks(&mut rx_p2p, &mut local_cons, 8).await;

        // respond to block request received from remote
        get_blocks(&mut rx_p2p, &mut local_cons).await;

        local_cons
    });

    // add peer to the hashmap of known peers and send getheaders request to them
    assert_eq!(mgr.register_peer(peer_id, peer_tx).await, Ok(()));
    assert_eq!(mgr.advance_state().await, Ok(()));

    // verify that when the connection has been established,
    // the remote peer will receive getheaders request
    get_message!(
        peer_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::SyncEvent::GetHeaders { locator }),
        {
            assert_eq!(
                mgr.initialize_peer(peer_id, &remote_cons.get_headers(&locator)).await,
                Ok(())
            );
            assert_eq!(mgr.advance_state().await, Ok(()));
        }
    );

    let locator = remote_cons.get_locator();
    assert_eq!(mgr.process_header_request(peer_id, locator).await, Ok(()));
    assert_eq!(mgr.advance_state().await, Ok(()));

    // TODO: add comment on what happens here
    let mut dl_blocks = vec![];

    for i in 0..9 {
        match peer_rx.recv().await.unwrap() {
            event::PeerEvent::Syncing(event::SyncEvent::GetBlocks { headers }) => {
                let blocks =
                    remote_cons.get_blocks(&headers).into_iter().map(Arc::new).collect::<Vec<_>>();

                assert_eq!(mgr.process_block_response(peer_id, blocks).await, Ok(()));
                assert_eq!(mgr.advance_state().await, Ok(()));
            }
            event::PeerEvent::Syncing(event::SyncEvent::Headers { headers }) => {
                let uniq = remote_cons.get_uniq_headers(&headers);
                assert_eq!(uniq.len(), 5);
                assert_eq!(uniq, new_local_block_hdrs);
                dl_blocks = uniq;
            }
            e => panic!("invalid message received: {:#?}", e),
        }
    }

    assert_eq!(
        mgr.process_block_request(peer_id, &dl_blocks,).await,
        Ok(())
    );
    assert_eq!(mgr.advance_state().await, Ok(()));

    // verify that remote node receives the 5 blocks it requested
    get_message!(
        peer_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::SyncEvent::Blocks { blocks }),
        {
            assert_eq!(blocks.len(), 5);
            for block in blocks {
                remote_cons.accept_block(block);
            }
        }
    );

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
    assert_eq!(mgr.state(), SyncState::Idle);
}

// remote and local are in different branches and local has longer chain
#[tokio::test]
async fn remote_local_diff_chains_local_higher() {
    let addr: SocketAddr = test_utils::make_address("[::1]:");
    let (mut mgr, _, _, mut rx_p2p) = make_sync_manager::<MockService>(addr).await;
    let mut remote_cons = mock_consensus::Consensus::with_height(8);
    let mut local_cons = remote_cons.clone();
    let mut new_remote_block_hdrs = vec![];
    let mut new_local_block_hdrs = vec![];
    assert_eq!(mgr.state(), SyncState::Uninitialized);

    // add 3 more blocks to remote's chain
    for _ in 0..3 {
        let cur_id = remote_cons.mainchain.blkid;
        let block = mock_consensus::Block::new(Some(cur_id));
        new_remote_block_hdrs.push(block.header);
        remote_cons.accept_block(block);
    }

    // add 16 more blocks to local's chain
    for _ in 0..16 {
        let cur_id = local_cons.mainchain.blkid;
        let block = mock_consensus::Block::new(Some(cur_id));
        new_local_block_hdrs.push(block.header);
        local_cons.accept_block(block);
    }

    // verify that the chains are different and make a copy of the local chain
    let local_orig_cons = local_cons.clone();
    assert_ne!(local_cons.mainchain, remote_cons.mainchain);

    let ((peer_tx, mut peer_rx), peer_id) = (mpsc::channel(16), test_utils::get_random_mock_id());

    let handle = tokio::spawn(async move {
        // verify that the first message that the consensus receives is the locator request
        get_locator(&mut rx_p2p, &mut local_cons).await;

        // verify that the  uniq headers received from remote
        // are the ones they added before the test started
        get_uniq_headers_and_verify(&mut rx_p2p, &mut local_cons, &new_remote_block_hdrs).await;

        get_message!(
            rx_p2p.recv().await.unwrap(),
            event::P2pEvent::GetHeaders { locator, response },
            {
                let headers = local_cons.get_headers(&locator);
                assert!(headers.len() >= 16);
                response.send(headers);
            }
        );

        // accept the remote blocks to our chain but because the height of that
        // chhain is shorter than ours, no reorg happens which is tested later on
        accept_n_blocks(&mut rx_p2p, &mut local_cons, 3).await;
        get_blocks(&mut rx_p2p, &mut local_cons).await;

        local_cons
    });

    // add peer to the hashmap of known peers and send getheaders request to them
    assert_eq!(mgr.register_peer(peer_id, peer_tx).await, Ok(()));
    assert_eq!(mgr.advance_state().await, Ok(()));

    // verify that when the connection has been established,
    // the remote peer will receive getheaders request
    get_message!(
        peer_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::SyncEvent::GetHeaders { locator }),
        {
            assert_eq!(
                mgr.initialize_peer(peer_id, &remote_cons.get_headers(&locator),).await,
                Ok(())
            );
            assert_eq!(mgr.advance_state().await, Ok(()));
        }
    );

    let locator = remote_cons.get_locator();
    assert_eq!(mgr.process_header_request(peer_id, locator).await, Ok(()));
    assert_eq!(mgr.advance_state().await, Ok(()));

    let mut dl_blocks = vec![];
    for _ in 0..4 {
        match peer_rx.recv().await.unwrap() {
            event::PeerEvent::Syncing(event::SyncEvent::GetBlocks { headers }) => {
                let blocks =
                    remote_cons.get_blocks(&headers).into_iter().map(Arc::new).collect::<Vec<_>>();

                assert_eq!(mgr.process_block_response(peer_id, blocks).await, Ok(()));
                assert_eq!(mgr.advance_state().await, Ok(()));
            }
            event::PeerEvent::Syncing(event::SyncEvent::Headers { headers }) => {
                let uniq = remote_cons.get_uniq_headers(&headers);
                assert_eq!(uniq.len(), 16);
                assert_eq!(uniq, new_local_block_hdrs);
                dl_blocks = uniq;
            }
            e => panic!("invalid message received: {:#?}", e),
        }
    }

    assert_eq!(
        mgr.process_block_request(peer_id, &dl_blocks,).await,
        Ok(())
    );
    assert_eq!(mgr.advance_state().await, Ok(()));

    // accept the blocks to remote chain (a reorg is done as the chain is longer)
    get_message!(
        peer_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::SyncEvent::Blocks { blocks }),
        {
            assert_eq!(blocks.len(), 16);
            for block in blocks {
                remote_cons.accept_block(block);
            }
        }
    );

    // wait for the blockindex task to finish
    let local_cons = handle.await.unwrap();

    // verify that even though local downloaded blocks from
    // local node, it did not do a reorg
    assert_eq!(local_orig_cons.mainchain, local_cons.mainchain);
    assert_eq!(
        local_orig_cons.blks.store.len() + 3,
        local_cons.blks.store.len()
    );

    // verify also that local did a reorg as its chain was shorter
    assert_eq!(remote_cons.mainchain, local_cons.mainchain);
    assert_eq!(mgr.state(), SyncState::Idle);
}

// connect two remote nodes and as all three nodes are in different chains,
// local node downloads all blocks
#[tokio::test]
async fn two_remote_nodes_different_chains() {
    let addr: SocketAddr = test_utils::make_address("[::1]:");
    let (mut mgr, _, _, mut rx_p2p) = make_sync_manager::<MockService>(addr).await;
    let mut remote1_cons = mock_consensus::Consensus::with_height(8);
    let mut remote2_cons = remote1_cons.clone();
    let mut local_cons = remote1_cons.clone();
    let mut local_orig_cons = remote1_cons.clone();
    let mut new_remote1_block_hdrs = vec![];
    let mut new_remote2_block_hdrs = vec![];
    assert_eq!(mgr.state(), SyncState::Uninitialized);

    // add 8 more blocks to remote's chain
    for _ in 0..8 {
        let cur_id = remote1_cons.mainchain.blkid;
        let block = mock_consensus::Block::new(Some(cur_id));
        new_remote1_block_hdrs.push(block.header);
        remote1_cons.accept_block(block);
    }

    // add 5 more blocks to local's chain
    for _ in 0..5 {
        let cur_id = remote2_cons.mainchain.blkid;
        let block = mock_consensus::Block::new(Some(cur_id));
        new_remote2_block_hdrs.push(block.header);
        remote2_cons.accept_block(block);
    }

    let (peer1_tx, mut peer1_rx) = mpsc::channel(2);
    let peer1_id: SocketAddr = test_utils::make_address("[::1]:");

    let handle = tokio::spawn(async move {
        // verify that the first message that the consensus receives is the locator request
        get_locator(&mut rx_p2p, &mut local_cons).await;

        // as remote_1 is a different branch that has 8 new blocks since the common ancestor
        // `get_uniq_headers()` will return those headers from the entire response
        get_uniq_headers_and_verify(&mut rx_p2p, &mut local_cons, &new_remote1_block_hdrs).await;

        // accept the blocks from first remote node (reorg done)
        accept_n_blocks(&mut rx_p2p, &mut local_cons, 8).await;

        get_message!(
            rx_p2p.recv().await.unwrap(),
            event::P2pEvent::GetHeaders { locator, response },
            {
                response.send(local_cons.get_headers(&locator));
            }
        );
        // handler locator and header request for the second peer
        get_locator(&mut rx_p2p, &mut local_cons).await;
        get_uniq_headers_and_verify(&mut rx_p2p, &mut local_cons, &new_remote2_block_hdrs).await;

        // accept the blcoks from the second remote node (no reorg is done)
        accept_n_blocks(&mut rx_p2p, &mut local_cons, 5).await;

        local_cons
    });

    // add peer to the hashmap of known peers and send getheaders request to them
    assert_eq!(mgr.register_peer(peer1_id, peer1_tx).await, Ok(()));
    assert_eq!(mgr.advance_state().await, Ok(()));

    // verify that when the connection has been established,
    // the remote peer will receive getheaders request
    get_message!(
        peer1_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::SyncEvent::GetHeaders { locator }),
        {
            assert_eq!(
                mgr.initialize_peer(peer1_id, &remote1_cons.get_headers(&locator),).await,
                Ok(())
            );
            assert_eq!(mgr.advance_state().await, Ok(()));
        }
    );

    for _ in 0..8 {
        match peer1_rx.recv().await.unwrap() {
            event::PeerEvent::Syncing(event::SyncEvent::GetBlocks { headers }) => {
                let blocks =
                    remote1_cons.get_blocks(&headers).into_iter().map(Arc::new).collect::<Vec<_>>();

                assert_eq!(mgr.process_block_response(peer1_id, blocks,).await, Ok(()));
                assert_eq!(mgr.advance_state().await, Ok(()));
            }
            e => panic!("invalid message received: {:#?}", e),
        }
    }

    let locator = remote1_cons.get_locator();
    assert_eq!(mgr.process_header_request(peer1_id, locator,).await, Ok(()));
    assert_eq!(mgr.advance_state().await, Ok(()));

    get_message!(
        peer1_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::SyncEvent::Headers { headers }),
        {
            assert!(remote1_cons.get_uniq_headers(&headers).is_empty());
        }
    );

    let (peer2_tx, mut peer2_rx) = mpsc::channel(1);
    let peer2_id: SocketAddr = test_utils::make_address("[::1]:");

    // add peer to the hashmap of known peers and send getheaders request to them
    assert_eq!(mgr.register_peer(peer2_id, peer2_tx).await, Ok(()));
    assert_eq!(mgr.advance_state().await, Ok(()));

    // verify that when the connection has been established,
    // the remote peer will receive getheaders request
    get_message!(
        peer2_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::SyncEvent::GetHeaders { locator }),
        {
            assert_eq!(
                mgr.initialize_peer(peer2_id, &remote2_cons.get_headers(&locator),).await,
                Ok(())
            );
            assert_eq!(mgr.advance_state().await, Ok(()));
        }
    );

    for _ in 0..5 {
        get_message!(
            peer2_rx.recv().await.unwrap(),
            event::PeerEvent::Syncing(event::SyncEvent::GetBlocks { headers }),
            {
                let blocks =
                    remote2_cons.get_blocks(&headers).into_iter().map(Arc::new).collect::<Vec<_>>();

                assert_eq!(mgr.process_block_response(peer2_id, blocks,).await, Ok(()));
                assert_eq!(mgr.advance_state().await, Ok(()));
            }
        );
    }

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
    assert_eq!(mgr.state(), SyncState::Idle);
}

// nodes are in sync and remote node publishes a new block
// and the local state is updated accordingly
#[tokio::test]
async fn nodes_in_sync_remote_publishes_new_block() {
    let addr: SocketAddr = test_utils::make_address("[::1]:");
    let (mut mgr, _, _, mut rx_p2p) = make_sync_manager::<MockService>(addr).await;
    let mut remote_cons = mock_consensus::Consensus::with_height(16);
    let ((peer_tx, mut peer_rx), peer_id) = (mpsc::channel(1), test_utils::get_random_mock_id());
    assert_eq!(mgr.state(), SyncState::Uninitialized);

    let mut local_cons = remote_cons.clone();
    let handle = tokio::spawn(async move {
        get_locator(&mut rx_p2p, &mut local_cons).await;
        get_uniq_headers_and_verify(&mut rx_p2p, &mut local_cons, &[]).await;

        get_message!(
            rx_p2p.recv().await.unwrap(),
            event::P2pEvent::GetBestBlockHeader { response },
            {
                response.send(local_cons.get_best_block_header());
            }
        );

        get_message!(
            rx_p2p.recv().await.unwrap(),
            event::P2pEvent::GetHeaders { locator, response },
            {
                response.send(local_cons.get_headers(&locator));
            }
        );

        // accept the floodsub block
        accept_n_blocks(&mut rx_p2p, &mut local_cons, 1).await;

        local_cons
    });

    // add peer to the hashmap of known peers and send getheaders request to them
    mgr.register_peer(peer_id, peer_tx).await;
    assert_eq!(mgr.advance_state().await, Ok(()));

    // verify that when the connection has been established,
    // the remote peer will receive getheaders request
    get_message!(
        peer_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::SyncEvent::GetHeaders { locator }),
        {
            mgr.initialize_peer(peer_id, &remote_cons.get_headers(&locator)).await;
            assert_eq!(mgr.advance_state().await, Ok(()));
        }
    );

    // now remote peer sends getheaders request to local sync node and it should
    // get the same response
    mgr.process_header_request(peer_id, remote_cons.get_locator()).await;
    assert_eq!(mgr.advance_state().await, Ok(()));

    // after the possibly new headers have been received from remote, verify that they
    // aren't actually unique and that remote node doesn't have to download any new
    // blocks from the local node
    get_message!(
        peer_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::SyncEvent::Headers { headers }),
        {
            assert!(remote_cons.get_uniq_headers(&headers).is_empty());
        }
    );

    // add new block to remote's chain and advertise it over the floodsub
    let block = mock_consensus::Block::new(Some(remote_cons.mainchain.blkid));
    remote_cons.accept_block(block.clone());

    assert_eq!(mgr.process_block(peer_id, Arc::new(block)).await, Ok(()));
    assert_eq!(mgr.advance_state().await, Ok(()));

    // wait for the blockindex task to finish
    let local_cons = handle.await.unwrap();

    // verify that the remote and local chains are the same
    // after the block announcement
    assert_eq!(remote_cons.mainchain, local_cons.mainchain);
    assert_eq!(mgr.state(), SyncState::Idle);
}

// connect two remote nodes that are in sync and ahead of local
// verify that downloads blocks from both nodes
#[tokio::test]
async fn two_remote_nodes_same_chain() {
    let addr: SocketAddr = test_utils::make_address("[::1]:");
    let (mut mgr, _, _, mut rx_p2p) = make_sync_manager::<MockService>(addr).await;
    let mut remote_cons = mock_consensus::Consensus::with_height(8);
    let mut local_cons = remote_cons.clone();
    let mut local_orig_cons = remote_cons.clone();
    let mut new_remote_block_hdrs = vec![];
    assert_eq!(mgr.state(), SyncState::Uninitialized);

    // add 10 more blocks to the remotes' chain
    for _ in 0..10 {
        let cur_id = remote_cons.mainchain.blkid;
        let block = mock_consensus::Block::new(Some(cur_id));
        new_remote_block_hdrs.push(block.header);
        remote_cons.accept_block(block);
    }

    let ((peer1_tx, mut peer1_rx), peer1_id) = (mpsc::channel(1), test_utils::get_random_mock_id());
    let ((peer2_tx, mut peer2_rx), peer2_id) = (mpsc::channel(1), test_utils::get_random_mock_id());

    let handle = tokio::spawn(async move {
        get_locator(&mut rx_p2p, &mut local_cons).await;
        get_locator(&mut rx_p2p, &mut local_cons).await;
        let mut getuniqheaders_last = false;

        for i in 0..12 {
            match rx_p2p.recv().await.unwrap() {
                event::P2pEvent::GetUniqHeaders { headers, response } => {
                    getuniqheaders_last = i == 12;
                    let uniq = local_cons.get_uniq_headers(&headers);
                    assert_eq!(uniq, new_remote_block_hdrs);
                    response.send((!uniq.is_empty()).then(|| uniq));
                }
                event::P2pEvent::NewBlock { block, response } => {
                    local_cons.accept_block(block);
                    response.send(());
                }
                e => panic!("invalid message received: {:#?}", e),
            }
        }

        if getuniqheaders_last {
            match rx_p2p.recv().await.unwrap() {
                event::P2pEvent::GetBestBlockHeader { response } => {
                    response.send(local_cons.get_best_block_header());
                }
                _ => panic!("invalid message"),
            }
        }

        local_cons
    });

    // add both peers to the hashmap of known peers and send getheaders request to them
    for peer in vec![(peer1_id, peer1_tx), (peer2_id, peer2_tx)] {
        assert_eq!(mgr.register_peer(peer.0, peer.1,).await, Ok(()));
        assert_eq!(mgr.advance_state().await, Ok(()));
    }

    let (mut peer1_cnt, mut peer2_cnt) = (0, 0);
    for i in 0..12 {
        let (event, peer_id) = tokio::select! {
            event = peer1_rx.recv() => { peer1_cnt += 1; (event.unwrap(), peer1_id) },
            event = peer2_rx.recv() => { peer2_cnt += 1; (event.unwrap(), peer2_id) },
        };

        match event {
            event::PeerEvent::Syncing(event::SyncEvent::GetHeaders { locator }) => {
                assert_eq!(
                    mgr.initialize_peer(peer_id, &remote_cons.get_headers(&locator)).await,
                    Ok(())
                );
                assert_eq!(mgr.advance_state().await, Ok(()));
            }
            event::PeerEvent::Syncing(event::SyncEvent::GetBlocks { headers }) => {
                let blocks =
                    remote_cons.get_blocks(&headers).into_iter().map(Arc::new).collect::<Vec<_>>();

                assert_eq!(mgr.process_block_response(peer_id, blocks).await, Ok(()));
                assert_eq!(mgr.advance_state().await, Ok(()));
            }
            e => panic!("invalid message received: {:#?}", e),
        }
    }
    assert_eq!(mgr.advance_state().await, Ok(()));

    // wait for the blockindex task to finish
    let local_cons = handle.await.unwrap();

    // verify also that local did a reorg as its chain was shorter
    assert_ne!(local_orig_cons.mainchain, local_cons.mainchain);
    assert_eq!(remote_cons.mainchain, local_cons.mainchain);
    assert_eq!(
        local_orig_cons.blks.store.len() + 10,
        local_cons.blks.store.len()
    );

    // verify that both peers contributed to block requests
    assert_ne!(peer1_cnt, 0);
    assert_ne!(peer2_cnt, 0);
    assert_eq!(mgr.state(), SyncState::Idle);
}

// connect two remote nodes that are in sync and ahead of local
// verify that downloads blocks from both nodes
//
// then local "loses" the connection for a moment and misses two blocks
// that are coming from the floodsub. It buffers the "orphan" block,
// syncs up with the remote nodes and then adds the block to its chain
#[tokio::test]
async fn two_remote_nodes_local_loses_connection() {
    let addr: SocketAddr = test_utils::make_address("[::1]:");
    let (mut mgr, _, _, mut rx_p2p) = make_sync_manager::<MockService>(addr).await;
    let mut remote_cons = mock_consensus::Consensus::with_height(8);
    let mut local_cons = remote_cons.clone();
    let mut local_orig_cons = remote_cons.clone();
    let mut new_remote_block_hdrs = vec![];
    assert_eq!(mgr.state(), SyncState::Uninitialized);

    // add 10 more blocks to the remotes' chain
    for _ in 0..10 {
        let cur_id = remote_cons.mainchain.blkid;
        let block = mock_consensus::Block::new(Some(cur_id));
        new_remote_block_hdrs.push(block.header);
        remote_cons.accept_block(block);
    }

    let ((peer1_tx, mut peer1_rx), peer1_id) = (mpsc::channel(1), test_utils::get_random_mock_id());
    let ((peer2_tx, mut peer2_rx), peer2_id) = (mpsc::channel(1), test_utils::get_random_mock_id());
    let ((peer3_tx, mut peer3_rx), peer3_id) = (mpsc::channel(1), test_utils::get_random_mock_id());

    let handle = tokio::spawn(async move {
        get_locator(&mut rx_p2p, &mut local_cons).await;
        get_locator(&mut rx_p2p, &mut local_cons).await;
        let mut getuniqheaders_last = false;

        for i in 0..12 {
            match rx_p2p.recv().await.unwrap() {
                event::P2pEvent::GetUniqHeaders { headers, response } => {
                    getuniqheaders_last = i == 12;
                    let uniq = local_cons.get_uniq_headers(&headers);
                    assert_eq!(uniq, new_remote_block_hdrs);
                    response.send((!uniq.is_empty()).then(|| uniq));
                }
                event::P2pEvent::NewBlock { block, response } => {
                    local_cons.accept_block(block);
                    response.send(());
                }
                e => panic!("invalid message received: {:#?}", e),
            }
        }

        if getuniqheaders_last {
            match rx_p2p.recv().await.unwrap() {
                event::P2pEvent::GetBestBlockHeader { response } => {
                    response.send(local_cons.get_best_block_header());
                }
                _ => panic!("invalid message"),
            }
        }

        // after internet connection was lost, two new nodes connected
        get_locator(&mut rx_p2p, &mut local_cons).await;
        get_locator(&mut rx_p2p, &mut local_cons).await;
        getuniqheaders_last = false;

        for i in 0..5 {
            match rx_p2p.recv().await.unwrap() {
                event::P2pEvent::GetUniqHeaders { headers, response } => {
                    getuniqheaders_last = i == 4;
                    let uniq = local_cons.get_uniq_headers(&headers);
                    response.send((!uniq.is_empty()).then(|| uniq));
                }
                event::P2pEvent::NewBlock { block, response } => {
                    local_cons.accept_block(block);
                    response.send(());
                }
                e => panic!("invalid message received: {:#?}", e),
            }
        }

        if getuniqheaders_last {
            match rx_p2p.recv().await.unwrap() {
                event::P2pEvent::GetBestBlockHeader { response } => {
                    response.send(local_cons.get_best_block_header());
                }
                _ => panic!("invalid message"),
            }
        }

        local_cons
    });

    // add both peers to the hashmap of known peers and send getheaders request to them
    for peer in vec![(peer1_id, peer1_tx.clone()), (peer2_id, peer2_tx)] {
        assert_eq!(mgr.register_peer(peer.0, peer.1).await, Ok(()));
        assert_eq!(mgr.advance_state().await, Ok(()));
    }

    let (mut peer1_cnt, mut peer2_cnt) = (0, 0);
    for i in 0..12 {
        let (event, peer_id) = tokio::select! {
            event = peer1_rx.recv() => { peer1_cnt += 1; (event.unwrap(), peer1_id) },
            event = peer2_rx.recv() => { peer2_cnt += 1; (event.unwrap(), peer2_id) },
        };

        match event {
            event::PeerEvent::Syncing(event::SyncEvent::GetHeaders { locator }) => {
                assert_eq!(
                    mgr.initialize_peer(peer_id, &remote_cons.get_headers(&locator)).await,
                    Ok(())
                );
                assert_eq!(mgr.advance_state().await, Ok(()));
            }
            event::PeerEvent::Syncing(event::SyncEvent::GetBlocks { headers }) => {
                let blocks =
                    remote_cons.get_blocks(&headers).into_iter().map(Arc::new).collect::<Vec<_>>();

                assert_eq!(mgr.process_block_response(peer_id, blocks).await, Ok(()));
                assert_eq!(mgr.advance_state().await, Ok(()));
            }
            e => panic!("invalid message received: {:#?}", e),
        }
    }

    // verify that both peers contributed to block requests
    assert_ne!(peer1_cnt, 0);
    assert_ne!(peer2_cnt, 0);

    // disconnected the peers
    assert_eq!(mgr.unregister_peer(peer1_id).await, Ok(()));
    assert_eq!(mgr.advance_state().await, Ok(()));

    assert_eq!(mgr.unregister_peer(peer2_id).await, Ok(()));
    assert_eq!(mgr.advance_state().await, Ok(()));

    // local node doesn't receive the next 3 blocks
    let block = (0..3)
        .map(|_| {
            let cur_id = remote_cons.mainchain.blkid;
            let block = mock_consensus::Block::new(Some(cur_id));
            remote_cons.accept_block(block.clone());
            block
        })
        .last();

    // then connect one new peer and one old peer
    for peer in vec![(peer1_id, peer1_tx), (peer3_id, peer3_tx)] {
        assert_eq!(mgr.register_peer(peer.0, peer.1).await, Ok(()));
        assert_eq!(mgr.advance_state().await, Ok(()));
    }

    for i in 0..5 {
        let (event, peer_id) = tokio::select! {
            event = peer1_rx.recv() => { (event.unwrap(), peer1_id) },
            event = peer3_rx.recv() => { (event.unwrap(), peer3_id) },
        };

        match event {
            event::PeerEvent::Syncing(event::SyncEvent::GetHeaders { locator }) => {
                assert_eq!(
                    mgr.initialize_peer(peer_id, &remote_cons.get_headers(&locator)).await,
                    Ok(())
                );
                assert_eq!(mgr.advance_state().await, Ok(()));
            }
            event::PeerEvent::Syncing(event::SyncEvent::GetBlocks { headers }) => {
                let blocks =
                    remote_cons.get_blocks(&headers).into_iter().map(Arc::new).collect::<Vec<_>>();

                assert_eq!(mgr.process_block_response(peer_id, blocks).await, Ok(()));
                assert_eq!(mgr.advance_state().await, Ok(()));
            }
            e => panic!("invalid message received: {:#?}", e),
        }
    }

    // wait for the blockindex task to finish
    let local_cons = handle.await.unwrap();

    // verify also that local did a reorg as its chain was shorter
    assert_ne!(local_orig_cons.mainchain, local_cons.mainchain);
    assert_eq!(remote_cons.mainchain, local_cons.mainchain);
    assert_eq!(
        local_orig_cons.blks.store.len() + 13,
        local_cons.blks.store.len()
    );
    assert_eq!(mgr.state(), SyncState::Idle);
}
