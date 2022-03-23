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
    net::{self, mock::MockService, FloodsubService, NetworkService},
    sync::{mock_consensus, SyncManager},
};
use std::net::SocketAddr;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{mpsc, oneshot};

macro_rules! get_message {
    ($expression:expr, $($pattern:pat_param)|+, $ret:expr) => {
        match $expression {
            $($pattern)|+ => $ret,
            _ => panic!("invalid message received")
        }
    }
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
    T: NetworkService,
    T::FloodsubHandle: FloodsubService<T>,
{
    let config = Arc::new(config::create_mainnet());
    let (_, flood) = T::start(addr, &[], &[]).await.unwrap();
    let (tx_sync, rx_sync) = tokio::sync::mpsc::channel(16);
    let (tx_peer, rx_peer) = tokio::sync::mpsc::channel(16);
    let (tx_p2p, rx_p2p) = tokio::sync::mpsc::channel(16);

    (
        SyncManager::<T>::new(Arc::clone(&config), flood, tx_p2p, rx_sync, rx_peer),
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

    let (peer_tx, mut peer_rx) = mpsc::channel(1);
    let peer_id: SocketAddr = test_utils::make_address("[::1]:");

    let mut local_cons = remote_cons.clone();
    let handle = tokio::spawn(async move {
        // verify that the first message that the consensus receives is the locator request
        get_message!(
            rx_p2p.recv().await.unwrap(),
            event::P2pEvent::GetLocator { response },
            {
                response.send(local_cons.get_locator());
            }
        );

        // verify that after getheaders has been sent (internally) and remote peer has responded
        // to it with their (possibly) new headers, getuniqheaders request is received and as local
        // and remote node are in sync, `get_uniq_headers()` returns an empty vector
        get_message!(
            rx_p2p.recv().await.unwrap(),
            event::P2pEvent::GetUniqHeaders { headers, response },
            {
                let uniq = local_cons.get_uniq_headers(&headers);
                assert!(uniq.is_empty());
                response.send(uniq);
            }
        );

        // verify that after local node has sent its header request, the remote node sends its own headers
        // request, process is appropriately. In practice these could come in either order
        get_message!(
            rx_p2p.recv().await.unwrap(),
            event::P2pEvent::GetHeaders { locator, response },
            {
                let headers = local_cons.get_headers(&locator);
                let all_headers = local_cons.as_vec();

                // verify that only the two most recent block headers are sent to remote node
                assert_eq!((headers[0], headers[1]), (all_headers[1], all_headers[0]));

                response.send(headers);
            }
        );
    });

    // add peer to the hashmap of known peers and send getheaders request to them
    assert_eq!(
        mgr.on_sync_event(event::SyncControlEvent::Connected {
            peer_id,
            tx: peer_tx
        })
        .await,
        Ok(())
    );

    // verify that when the connection has been established,
    // the remote peer will receive getheaders request
    get_message!(
        peer_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::PeerSyncEvent::GetHeaders {
            peer_id: _,
            locator
        }),
        {
            let headers = remote_cons.get_headers(&locator);
            let all_headers = remote_cons.as_vec();

            // verify that only the two most recent block headers are sent to local node
            assert_eq!((headers[0], headers[1]), (all_headers[1], all_headers[0]),);

            assert_eq!(
                mgr.on_peer_event(event::PeerSyncEvent::Headers {
                    peer_id: Some(peer_id),
                    headers,
                })
                .await,
                Ok(())
            );
        }
    );

    // now remote peer sends getheaders request to local sync node and it should
    // get the same response
    let locator = remote_cons.get_locator();

    assert_eq!(
        mgr.on_peer_event(event::PeerSyncEvent::GetHeaders {
            peer_id: Some(peer_id),
            locator,
        })
        .await,
        Ok(())
    );

    // after the possibly new headers have been received from remote, verify that they
    // aren't actually unique and that remote node doesn't have to download any new
    // blocks from the local node
    get_message!(
        peer_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::PeerSyncEvent::Headers {
            peer_id: _,
            headers
        }),
        {
            assert!(remote_cons.get_uniq_headers(&headers).is_empty());
        }
    );
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

    // add 7 more blocks to remote's chain
    for _ in 0..7 {
        let cur_id = remote_cons.mainchain.blkid;
        let block = mock_consensus::Block::new(Some(cur_id));
        new_block_hdrs.push(block.header);
        remote_cons.accept_block(block);
    }

    // verify that the chains are different
    assert_ne!(local_cons.mainchain, remote_cons.mainchain);

    let (peer_tx, mut peer_rx) = mpsc::channel(1);
    let peer_id: SocketAddr = test_utils::make_address("[::1]:");

    let handle = tokio::spawn(async move {
        // verify that the first message that the consensus receives is the locator request
        get_message!(
            rx_p2p.recv().await.unwrap(),
            event::P2pEvent::GetLocator { response },
            {
                response.send(local_cons.get_locator());
            }
        );

        // verify that as the remote is ahead of local by 7 blocks, extracting the unique
        // headers from the header response results in 7 new headers and that the headers
        // belong to the 7 new blocks that were added to the remote chain
        get_message!(
            rx_p2p.recv().await.unwrap(),
            event::P2pEvent::GetUniqHeaders { headers, response },
            {
                let uniq = local_cons.get_uniq_headers(&headers);
                assert_eq!(uniq.len(), 7);
                assert_eq!(uniq, new_block_hdrs);
                response.send(uniq);
            }
        );

        // local syncmanager sent block request to remote and for each now block it receives,
        // it sends the blockindex a newblock event that tells it to accept the new block
        for _ in 0..7 {
            get_message!(
                rx_p2p.recv().await.unwrap(),
                event::P2pEvent::NewBlock { block, response },
                {
                    let uniq = local_cons.accept_block(block);
                    response.send(());
                }
            );
        }

        // return the updates blockindex after the tests have been run
        // so it can be compared against remote's blockindex
        local_cons
    });

    // add peer to the hashmap of known peers and send getheaders request to them
    assert_eq!(
        mgr.on_sync_event(event::SyncControlEvent::Connected {
            peer_id,
            tx: peer_tx
        })
        .await,
        Ok(())
    );

    // verify that when the connection has been established,
    // the remote peer will receive getheaders request
    get_message!(
        peer_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::PeerSyncEvent::GetHeaders {
            peer_id: _,
            locator
        }),
        {
            assert_eq!(
                mgr.on_peer_event(event::PeerSyncEvent::Headers {
                    peer_id: Some(peer_id),
                    headers: remote_cons.get_headers(&locator),
                })
                .await,
                Ok(())
            );
        }
    );

    // respond to getblocks request received from the local node
    get_message!(
        peer_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::PeerSyncEvent::GetBlocks {
            peer_id: _,
            headers
        }),
        {
            assert_eq!(
                mgr.on_peer_event(event::PeerSyncEvent::Blocks {
                    peer_id: Some(peer_id),
                    blocks: remote_cons.get_blocks(&headers),
                })
                .await,
                Ok(())
            );
        }
    );

    let local_cons = handle.await.unwrap();
    assert_eq!(local_cons.mainchain, remote_cons.mainchain);
}

// local and remote nodes are in the same chain but local is ahead of remote by 12 blocks
#[tokio::test]
async fn local_ahead_by_12_blocks() {
    let addr: SocketAddr = test_utils::make_address("[::1]:");
    let (mut mgr, _, _, mut rx_p2p) = make_sync_manager::<MockService>(addr).await;
    let mut remote_cons = mock_consensus::Consensus::with_height(8);
    let mut local_cons = remote_cons.clone();
    let mut new_block_hdrs = vec![];

    // add 12 more blocks to local's chain
    for _ in 0..12 {
        let cur_id = local_cons.mainchain.blkid;
        let block = mock_consensus::Block::new(Some(cur_id));
        new_block_hdrs.push(block.header);
        local_cons.accept_block(block);
    }

    // verify that the chains are different
    assert_ne!(local_cons.mainchain, remote_cons.mainchain);

    let (peer_tx, mut peer_rx) = mpsc::channel(1);
    let peer_id: SocketAddr = test_utils::make_address("[::1]:");

    let handle = tokio::spawn(async move {
        // verify that the first message that the consensus receives is the locator request
        get_message!(
            rx_p2p.recv().await.unwrap(),
            event::P2pEvent::GetLocator { response },
            {
                response.send(local_cons.get_locator());
            }
        );

        // as local is ahead of remote, getuniqheaders returns an empty vector
        get_message!(
            rx_p2p.recv().await.unwrap(),
            event::P2pEvent::GetUniqHeaders { headers, response },
            {
                let uniq = local_cons.get_uniq_headers(&headers);
                assert!(uniq.is_empty());
                response.send(uniq);
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
        get_message!(
            rx_p2p.recv().await.unwrap(),
            event::P2pEvent::GetBlocks { headers, response },
            {
                response.send(local_cons.get_blocks(&headers));
            }
        );

        local_cons
    });

    // add peer to the hashmap of known peers and send getheaders request to them
    assert_eq!(
        mgr.on_sync_event(event::SyncControlEvent::Connected {
            peer_id,
            tx: peer_tx
        })
        .await,
        Ok(())
    );

    // verify that when the connection has been established,
    // the remote peer will receive getheaders request
    get_message!(
        peer_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::PeerSyncEvent::GetHeaders {
            peer_id: _,
            locator
        }),
        {
            assert_eq!(
                mgr.on_peer_event(event::PeerSyncEvent::Headers {
                    peer_id: Some(peer_id),
                    headers: remote_cons.get_headers(&locator),
                })
                .await,
                Ok(())
            );
        }
    );

    let locator = remote_cons.get_locator();
    assert_eq!(
        mgr.on_peer_event(event::PeerSyncEvent::GetHeaders {
            peer_id: Some(peer_id),
            locator,
        })
        .await,
        Ok(())
    );

    // verify that after extracting the uniq headers from the response,
    // remote is left with 12 new block headers
    get_message!(
        peer_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::PeerSyncEvent::Headers {
            peer_id: _,
            headers
        }),
        {
            // based on the unique headers, request blocks from remote
            let uniq = remote_cons.get_uniq_headers(&headers);
            assert_eq!(uniq.len(), 12);
            assert_eq!(uniq, new_block_hdrs);
            assert_eq!(
                mgr.on_peer_event(event::PeerSyncEvent::GetBlocks {
                    peer_id: Some(peer_id),
                    headers: uniq,
                })
                .await,
                Ok(())
            );
        }
    );

    // request the 12 missing blocks from remote
    get_message!(
        peer_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::PeerSyncEvent::Blocks { peer_id: _, blocks }),
        {
            assert_eq!(blocks.len(), 12);
            for block in blocks {
                remote_cons.accept_block(block);
            }
        }
    );

    let local_cons = handle.await.unwrap();
    assert_eq!(local_cons.mainchain, remote_cons.mainchain);
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

    let (peer_tx, mut peer_rx) = mpsc::channel(3);
    let peer_id: SocketAddr = test_utils::make_address("[::1]:");

    let handle = tokio::spawn(async move {
        // verify that the first message that the consensus receives is the locator request
        get_message!(
            rx_p2p.recv().await.unwrap(),
            event::P2pEvent::GetLocator { response },
            {
                response.send(local_cons.get_locator());
            }
        );

        // as remote is a different branch that has 8 new blocks since the common ancestor
        // `get_uniq_headers()` will return those headers from the entire response
        get_message!(
            rx_p2p.recv().await.unwrap(),
            event::P2pEvent::GetUniqHeaders { headers, response },
            {
                let uniq = local_cons.get_uniq_headers(&headers);
                assert_eq!(uniq.len(), 8);
                assert_eq!(uniq, new_remote_block_hdrs);
                response.send(uniq);
            }
        );

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
        for _ in 0..8 {
            get_message!(
                rx_p2p.recv().await.unwrap(),
                event::P2pEvent::NewBlock { block, response },
                {
                    let uniq = local_cons.accept_block(block);
                    response.send(());
                }
            );
        }

        // respond to block request received from remote
        get_message!(
            rx_p2p.recv().await.unwrap(),
            event::P2pEvent::GetBlocks { headers, response },
            {
                response.send(local_cons.get_blocks(&headers));
            }
        );

        local_cons
    });

    // add peer to the hashmap of known peers and send getheaders request to them
    assert_eq!(
        mgr.on_sync_event(event::SyncControlEvent::Connected {
            peer_id,
            tx: peer_tx
        })
        .await,
        Ok(())
    );

    // verify that when the connection has been established,
    // the remote peer will receive getheaders request
    get_message!(
        peer_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::PeerSyncEvent::GetHeaders {
            peer_id: _,
            locator
        }),
        {
            assert_eq!(
                mgr.on_peer_event(event::PeerSyncEvent::Headers {
                    peer_id: Some(peer_id),
                    headers: remote_cons.get_headers(&locator),
                })
                .await,
                Ok(())
            );
        }
    );

    let locator = remote_cons.get_locator();
    assert_eq!(
        mgr.on_peer_event(event::PeerSyncEvent::GetHeaders {
            peer_id: Some(peer_id),
            locator,
        })
        .await,
        Ok(())
    );

    get_message!(
        peer_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::PeerSyncEvent::GetBlocks {
            peer_id: _,
            headers
        }),
        {
            assert_eq!(
                mgr.on_peer_event(event::PeerSyncEvent::Blocks {
                    peer_id: Some(peer_id),
                    blocks: remote_cons.get_blocks(&headers),
                })
                .await,
                Ok(())
            );
        }
    );

    // verify that after extracting the uniq headers from the response,
    // remote is left with 5 new block headers
    get_message!(
        peer_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::PeerSyncEvent::Headers {
            peer_id: _,
            headers
        }),
        {
            let uniq = remote_cons.get_uniq_headers(&headers);
            assert_eq!(uniq.len(), 5);
            assert_eq!(uniq, new_local_block_hdrs);
            assert_eq!(
                mgr.on_peer_event(event::PeerSyncEvent::GetBlocks {
                    peer_id: Some(peer_id),
                    headers: uniq,
                })
                .await,
                Ok(())
            );
        }
    );

    // verify that remote node receives the 5 blocks it requested
    get_message!(
        peer_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::PeerSyncEvent::Blocks { peer_id: _, blocks }),
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

    let (peer_tx, mut peer_rx) = mpsc::channel(2);
    let peer_id: SocketAddr = test_utils::make_address("[::1]:");

    let handle = tokio::spawn(async move {
        // verify that the first message that the consensus receives is the locator request
        get_message!(
            rx_p2p.recv().await.unwrap(),
            event::P2pEvent::GetLocator { response },
            {
                response.send(local_cons.get_locator());
            }
        );

        get_message!(
            rx_p2p.recv().await.unwrap(),
            event::P2pEvent::GetUniqHeaders { headers, response },
            {
                let uniq = local_cons.get_uniq_headers(&headers);
                assert_eq!(uniq.len(), 3);
                assert_eq!(uniq, new_remote_block_hdrs);
                response.send(uniq);
            }
        );

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
        for _ in 0..3 {
            get_message!(
                rx_p2p.recv().await.unwrap(),
                event::P2pEvent::NewBlock { block, response },
                {
                    let uniq = local_cons.accept_block(block);
                    response.send(());
                }
            );
        }

        get_message!(
            rx_p2p.recv().await.unwrap(),
            event::P2pEvent::GetBlocks { headers, response },
            {
                response.send(local_cons.get_blocks(&headers));
            }
        );

        local_cons
    });

    // add peer to the hashmap of known peers and send getheaders request to them
    assert_eq!(
        mgr.on_sync_event(event::SyncControlEvent::Connected {
            peer_id,
            tx: peer_tx
        })
        .await,
        Ok(())
    );

    // verify that when the connection has been established,
    // the remote peer will receive getheaders request
    get_message!(
        peer_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::PeerSyncEvent::GetHeaders {
            peer_id: _,
            locator
        }),
        {
            assert_eq!(
                mgr.on_peer_event(event::PeerSyncEvent::Headers {
                    peer_id: Some(peer_id),
                    headers: remote_cons.get_headers(&locator),
                })
                .await,
                Ok(())
            );
        }
    );

    let locator = remote_cons.get_locator();
    assert_eq!(
        mgr.on_peer_event(event::PeerSyncEvent::GetHeaders {
            peer_id: Some(peer_id),
            locator,
        })
        .await,
        Ok(())
    );

    get_message!(
        peer_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::PeerSyncEvent::GetBlocks {
            peer_id: _,
            headers
        }),
        {
            assert_eq!(
                mgr.on_peer_event(event::PeerSyncEvent::Blocks {
                    peer_id: Some(peer_id),
                    blocks: remote_cons.get_blocks(&headers),
                })
                .await,
                Ok(())
            );
        }
    );

    // verify that remote node is behind local node by 16 blocks
    // and send a block request to fetch those new blocks
    get_message!(
        peer_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::PeerSyncEvent::Headers {
            peer_id: _,
            headers
        }),
        {
            let uniq = remote_cons.get_uniq_headers(&headers);
            assert_eq!(uniq.len(), 16);
            assert_eq!(uniq, new_local_block_hdrs);
            assert_eq!(
                mgr.on_peer_event(event::PeerSyncEvent::GetBlocks {
                    peer_id: Some(peer_id),
                    headers: uniq,
                })
                .await,
                Ok(())
            );
        }
    );

    // accept the blocks to remote chain (a reorg is done as the chain is longer)
    get_message!(
        peer_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::PeerSyncEvent::Blocks { peer_id: _, blocks }),
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
        get_message!(
            rx_p2p.recv().await.unwrap(),
            event::P2pEvent::GetLocator { response },
            {
                response.send(local_cons.get_locator());
            }
        );

        // as remote_1 is a different branch that has 8 new blocks since the common ancestor
        // `get_uniq_headers()` will return those headers from the entire response
        get_message!(
            rx_p2p.recv().await.unwrap(),
            event::P2pEvent::GetUniqHeaders { headers, response },
            {
                let uniq = local_cons.get_uniq_headers(&headers);
                assert_eq!(uniq.len(), 8);
                assert_eq!(uniq, new_remote1_block_hdrs);
                response.send(uniq);
            }
        );

        get_message!(
            rx_p2p.recv().await.unwrap(),
            event::P2pEvent::GetHeaders { locator, response },
            {
                let headers = local_cons.get_headers(&locator);
                response.send(headers);
            }
        );

        // accept the blocks from first remote node (reorg done)
        for _ in 0..8 {
            get_message!(
                rx_p2p.recv().await.unwrap(),
                event::P2pEvent::NewBlock { block, response },
                {
                    let uniq = local_cons.accept_block(block);
                    response.send(());
                }
            );
        }

        get_message!(
            rx_p2p.recv().await.unwrap(),
            event::P2pEvent::GetLocator { response },
            {
                response.send(local_cons.get_locator());
            }
        );

        get_message!(
            rx_p2p.recv().await.unwrap(),
            event::P2pEvent::GetUniqHeaders { headers, response },
            {
                let uniq = local_cons.get_uniq_headers(&headers);
                assert_eq!(uniq.len(), 5);
                assert_eq!(uniq, new_remote2_block_hdrs);
                response.send(uniq);
            }
        );

        // accept the blcoks from the second remote node (no reorg is done)
        for _ in 0..5 {
            get_message!(
                rx_p2p.recv().await.unwrap(),
                event::P2pEvent::NewBlock { block, response },
                {
                    let uniq = local_cons.accept_block(block);
                    response.send(());
                }
            );
        }

        local_cons
    });

    // add peer to the hashmap of known peers and send getheaders request to them
    assert_eq!(
        mgr.on_sync_event(event::SyncControlEvent::Connected {
            peer_id: peer1_id,
            tx: peer1_tx
        })
        .await,
        Ok(())
    );

    // verify that when the connection has been established,
    // the remote peer will receive getheaders request
    get_message!(
        peer1_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::PeerSyncEvent::GetHeaders {
            peer_id: _,
            locator
        }),
        {
            assert_eq!(
                mgr.on_peer_event(event::PeerSyncEvent::Headers {
                    peer_id: Some(peer1_id),
                    headers: remote1_cons.get_headers(&locator),
                })
                .await,
                Ok(())
            );
        }
    );

    let locator = remote1_cons.get_locator();
    assert_eq!(
        mgr.on_peer_event(event::PeerSyncEvent::GetHeaders {
            peer_id: Some(peer1_id),
            locator,
        })
        .await,
        Ok(())
    );

    get_message!(
        peer1_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::PeerSyncEvent::GetBlocks {
            peer_id: _,
            headers
        }),
        {
            assert_eq!(headers.len(), 8);
            assert_eq!(
                mgr.on_peer_event(event::PeerSyncEvent::Blocks {
                    peer_id: Some(peer1_id),
                    blocks: remote1_cons.get_blocks(&headers),
                })
                .await,
                Ok(())
            );
        }
    );

    let (peer2_tx, mut peer2_rx) = mpsc::channel(1);
    let peer2_id: SocketAddr = test_utils::make_address("[::1]:");

    // add peer to the hashmap of known peers and send getheaders request to them
    assert_eq!(
        mgr.on_sync_event(event::SyncControlEvent::Connected {
            peer_id: peer2_id,
            tx: peer2_tx
        })
        .await,
        Ok(())
    );

    // verify that when the connection has been established,
    // the remote peer will receive getheaders request
    get_message!(
        peer2_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::PeerSyncEvent::GetHeaders {
            peer_id: _,
            locator
        }),
        {
            assert_eq!(
                mgr.on_peer_event(event::PeerSyncEvent::Headers {
                    peer_id: Some(peer2_id),
                    headers: remote2_cons.get_headers(&locator),
                })
                .await,
                Ok(())
            );
        }
    );

    get_message!(
        peer2_rx.recv().await.unwrap(),
        event::PeerEvent::Syncing(event::PeerSyncEvent::GetBlocks {
            peer_id: _,
            headers
        }),
        {
            assert_eq!(headers.len(), 5);
            assert_eq!(
                mgr.on_peer_event(event::PeerSyncEvent::Blocks {
                    peer_id: Some(peer2_id),
                    blocks: remote2_cons.get_blocks(&headers),
                })
                .await,
                Ok(())
            );
        }
    );

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
}
