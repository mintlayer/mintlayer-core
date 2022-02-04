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

use common::chain::ChainConfig;
use p2p::{
    net::{
        mock::{MockService, MockSocket},
        Event, NetworkService,
    },
    peer::*,
};
use std::{net::SocketAddr, sync::Arc};
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

// create two mock peers that are connected to each other
pub async fn create_two_mock_peers(
    config: Arc<ChainConfig>,
) -> (Peer<MockService>, Peer<MockService>) {
    let addr: SocketAddr = make_address("[::1]:");
    let mut server = MockService::new(addr, &[], &[]).await.unwrap();
    let peer_fut = TcpStream::connect(addr);

    let (remote_res, local_res) = tokio::join!(server.poll_next(), peer_fut);
    let remote_res: Event<MockService> = remote_res.unwrap();
    let remote_res = match remote_res {
        Event::IncomingConnection(remote_res) => remote_res,
        _ => panic!("invalid event received, expected incoming connection"),
    };
    let local_res = local_res.unwrap();

    let (peer_tx, mut peer_rx) = tokio::sync::mpsc::channel(1);
    let (_tx, rx) = tokio::sync::mpsc::channel(1);
    let (_tx2, rx2) = tokio::sync::mpsc::channel(1);

    // spawn dummy task that listens to the peer RX channel and
    // acts as though a P2P object was listening to events from the peer
    tokio::spawn(async move {
        loop {
            let _ = peer_rx.recv().await;
        }
    });

    let local = Peer::<MockService>::new(
        1,
        PeerRole::Outbound,
        config.clone(),
        remote_res,
        peer_tx.clone(),
        rx,
    );

    let remote = Peer::<MockService>::new(
        2,
        PeerRole::Inbound,
        config.clone(),
        MockSocket::new(local_res),
        peer_tx,
        rx2,
    );

    (local, remote)
}
