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
#![allow(unused, clippy::unwrap_used)]

use common::chain::ChainConfig;
use libp2p::Multiaddr;
use p2p::net::{
    libp2p::Libp2pService, mock::MockService, ConnectivityEvent, ConnectivityService,
    NetworkingService,
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

/// Allocate a port and create a socket address for given NetworkingService
pub fn make_address<T>(addr: &str) -> T
where
    T: std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Debug,
{
    let port: u16 = portpicker::pick_unused_port().expect("No ports free");
    format!("{}{}", addr, port).parse().unwrap()
}

pub fn get_mock_id() -> <MockService as NetworkingService>::PeerId {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8888)
}
