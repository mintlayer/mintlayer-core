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
#![allow(clippy::mutex_atomic)]
use lazy_static::lazy_static;
use std::net::TcpListener;
use std::sync::Mutex;

/// TCP server address for testing mock service connectivity
pub const TCP_SERVER: &str = "[::1]:7999";

lazy_static! {
    static ref TCP_RUNNING: Mutex<bool> = Default::default();
}

/// Spawn a TCP server if it's not already running
///
/// The server is not used for any communication but
/// only for creating a connected socket for P2P/Peer
pub fn start_tcp_server() {
    let mut running = TCP_RUNNING.lock().unwrap();
    if !(*running) {
        let server = TcpListener::bind(TCP_SERVER).unwrap();

        std::thread::spawn(move || loop {
            let (_, _) = server.accept().unwrap();
        });

        *running = true;
    }
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
