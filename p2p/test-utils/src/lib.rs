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

use common::chain::ChainConfig;
use libp2p::Multiaddr;
use p2p::{
    net::{
        libp2p::Libp2pService,
        mock::{MockService, MockSocket},
        ConnectivityEvent, ConnectivityService, NetworkService,
    },
    peer::*,
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::net::{TcpListener, TcpStream};

pub async fn get_tcp_socket() -> TcpStream {
    let port: u16 = portpicker::pick_unused_port().expect("No ports free");
    let addr: SocketAddr = format!("[::1]:{}", port).parse().unwrap();
    let server = TcpListener::bind(addr).await.unwrap();

    tokio::spawn(async move {
        loop {
            let _ = server.accept().await.unwrap();
        }
    });

    TcpStream::connect(addr).await.unwrap()
}

/// Allocate a port and create a socket address for given NetworkService
pub fn make_address<T>(addr: &str) -> T
where
    T: std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Debug,
{
    let port: u16 = portpicker::pick_unused_port().expect("No ports free");
    format!("{}{}", addr, port).parse().unwrap()
}

pub fn get_mock_id() -> <MockService as NetworkService>::PeerId {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8888)
}

// create two mock peers that are connected to each other
pub async fn create_two_mock_peers(
    config: Arc<ChainConfig>,
) -> (Peer<MockService>, Peer<MockService>) {
    let addr: SocketAddr = make_address("[::1]:");
    let (mut server, _) = MockService::start(addr, &[], &[], std::time::Duration::from_secs(10)).await.unwrap();
    let peer_fut = TcpStream::connect(addr);

    let (remote_res, local_res) = tokio::join!(server.poll_next(), peer_fut);
    let remote_res: ConnectivityEvent<MockService> = remote_res.unwrap();
    let remote_res = match remote_res {
        ConnectivityEvent::IncomingConnection { peer_id: _, socket } => socket,
        _ => panic!("invalid event received, expected incoming connection"),
    };
    let local_res = local_res.unwrap();

    let (peer_tx, mut peer_rx) = tokio::sync::mpsc::channel(1);
    let (sync_tx, mut sync_rx) = tokio::sync::mpsc::channel(1);
    let (_tx, rx) = tokio::sync::mpsc::channel(1);
    let (_tx2, rx2) = tokio::sync::mpsc::channel(1);

    // spawn dummy task that listens to the peer RX channel and
    // acts as though a P2P object was listening to events from the peer
    tokio::spawn(async move {
        loop {
            let (_, _) = tokio::join!(peer_rx.recv(), sync_rx.recv());
        }
    });

    let local = Peer::<MockService>::new(
        addr,
        PeerRole::Outbound,
        config.clone(),
        remote_res,
        peer_tx.clone(),
        sync_tx.clone(),
        rx,
    );

    let remote = Peer::<MockService>::new(
        local_res.local_addr().unwrap(),
        PeerRole::Inbound,
        config.clone(),
        MockSocket::new(local_res),
        peer_tx,
        sync_tx,
        rx2,
    );

    (local, remote)
}

// create two libp2p peers that are connected to each other
pub async fn create_two_libp2p_peers(
    config: Arc<ChainConfig>,
) -> (Peer<Libp2pService>, Peer<Libp2pService>) {
    let addr1: Multiaddr = make_address("/ip6/::1/tcp/");
    let (mut server1, _) = Libp2pService::start(addr1, &[], &[], std::time::Duration::from_secs(10)).await.unwrap();

    let addr2: Multiaddr = make_address("/ip6/::1/tcp/");
    let (mut server2, _) = Libp2pService::start(addr2, &[], &[], std::time::Duration::from_secs(10)).await.unwrap();

    let server1_conn_fut = server1.connect(server2.local_addr().clone());

    let (local_res, remote_res) = tokio::join!(server1_conn_fut, server2.poll_next());
    let remote_res: ConnectivityEvent<Libp2pService> = remote_res.unwrap();
    let (id, remote_res) = match remote_res {
        ConnectivityEvent::IncomingConnection { peer_id, socket } => (peer_id, socket),
        _ => panic!("invalid event received, expected incoming connection"),
    };
    let local_res = local_res.unwrap();

    let (peer_tx, mut peer_rx) = tokio::sync::mpsc::channel(1);
    let (sync_tx, mut sync_rx) = tokio::sync::mpsc::channel(1);
    let (_tx, rx) = tokio::sync::mpsc::channel(1);
    let (_tx2, rx2) = tokio::sync::mpsc::channel(1);

    // spawn dummy task that listens to the peer RX channel and
    // acts as though a P2P object was listening to events from the peer
    tokio::spawn(async move {
        loop {
            let (_, _) = tokio::join!(peer_rx.recv(), sync_rx.recv());
        }
    });

    let local = Peer::<Libp2pService>::new(
        id,
        PeerRole::Outbound,
        config.clone(),
        remote_res,
        peer_tx.clone(),
        sync_tx.clone(),
        rx,
    );

    let remote = Peer::<Libp2pService>::new(
        local_res.0,
        PeerRole::Inbound,
        config.clone(),
        local_res.1,
        peer_tx,
        sync_tx,
        rx2,
    );

    (local, remote)
}
