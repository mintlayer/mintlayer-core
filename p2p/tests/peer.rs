// Copyright (c) 2021-2022 RBB S.r.l
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

use common::chain::config;
use libp2p::Multiaddr;
use p2p::net::{
    self, libp2p::Libp2pService, mock::MockService, ConnectivityService, NetworkService,
};
use p2p::peer::{Peer, PeerRole};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;

// connect two mock service peers together
#[tokio::test]
async fn test_peer_new_mock() {
    let config = Arc::new(config::create_mainnet());
    let addr: SocketAddr = test_utils::make_address("[::1]:");
    let (mut server, _) = MockService::start(addr, &[], &[]).await.unwrap();
    let peer_fut = TcpStream::connect(addr);

    let (server_res, peer_res) = tokio::join!(server.poll_next(), peer_fut);
    assert!(server_res.is_ok());
    assert!(peer_res.is_ok());

    let server_res: net::ConnectivityEvent<MockService> = server_res.unwrap();
    let server_res = match server_res {
        net::ConnectivityEvent::IncomingConnection { peer_id: _, socket } => socket,
        _ => panic!("invalid event received, expected incoming connection"),
    };

    let (peer_tx, _peer_rx) = tokio::sync::mpsc::channel(1);
    let (sync_tx, _sync_rx) = tokio::sync::mpsc::channel(1);
    let (_tx, rx) = tokio::sync::mpsc::channel(1);
    let _ = Peer::<MockService>::new(
        addr,
        PeerRole::Outbound,
        Arc::clone(&config),
        server_res,
        peer_tx,
        sync_tx,
        rx,
    );
}

// connect two libp2p service peers together
#[tokio::test]
async fn test_peer_new_libp2p() {
    let config = Arc::new(config::create_mainnet());
    let addr1: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
    let (mut server1, _) = Libp2pService::start(addr1.clone(), &[], &[]).await.unwrap();

    let conn_addr = server1.local_addr().clone();
    let addr2: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
    let (mut server2, _) = Libp2pService::start(addr2, &[], &[]).await.unwrap();

    let (server1_res, server2_res) = tokio::join!(server1.poll_next(), server2.connect(conn_addr));
    assert!(server1_res.is_ok());
    assert!(server2_res.is_ok());

    let server1_res: net::ConnectivityEvent<Libp2pService> = server1_res.unwrap();
    let (id, socket) = match server1_res {
        net::ConnectivityEvent::IncomingConnection { peer_id, socket } => (peer_id, socket),
        _ => panic!("invalid event received, expected incoming connection"),
    };

    let (peer_tx, _peer_rx) = tokio::sync::mpsc::channel(1);
    let (sync_tx, _sync_rx) = tokio::sync::mpsc::channel(1);
    let (_tx, rx) = tokio::sync::mpsc::channel(1);
    let _ = Peer::<Libp2pService>::new(
        id,
        PeerRole::Outbound,
        Arc::clone(&config),
        socket,
        peer_tx,
        sync_tx,
        rx,
    );
}
