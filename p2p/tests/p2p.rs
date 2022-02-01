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

use common::{chain::config, sync::Arc};
use libp2p::Multiaddr;
use p2p::{net::libp2p::Libp2pService, net::mock::MockService, P2P};
use std::net::SocketAddr;

// create new p2p object with mock service
#[tokio::test]
async fn test_p2p_new_mock() {
    let config = Arc::new(config::create_mainnet());
    let addr: SocketAddr = test_utils::make_address("[::1]:");
    let res = P2P::<MockService>::new(256, 32, addr, Arc::clone(&config)).await;
    assert!(res.is_ok());

    // try to create new P2P object to the same address, should fail
    let res = P2P::<MockService>::new(256, 32, addr, Arc::clone(&config)).await;
    assert!(res.is_err());

    // try to create new P2P object to different address, should succeed
    let addr: SocketAddr = test_utils::make_address("127.0.0.1:");
    let res = P2P::<MockService>::new(256, 32, addr, Arc::clone(&config)).await;
    assert!(res.is_ok());
}

// create new p2p object with libp2p service
#[ignore]
#[tokio::test]
async fn test_p2p_new_libp2p() {
    let config = Arc::new(config::create_mainnet());
    let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
    let res = P2P::<Libp2pService>::new(256, 32, addr.clone(), Arc::clone(&config)).await;
    assert!(res.is_ok());

    // try to create new P2P object to the same address, should fail
    let res = P2P::<Libp2pService>::new(256, 32, addr, Arc::clone(&config)).await;
    assert!(res.is_err());

    // try to create new P2P object to different address, should succeed
    let addr: Multiaddr = test_utils::make_address("/ip4/127.0.0.1/tcp/");
    let res = P2P::<Libp2pService>::new(256, 32, addr, Arc::clone(&config)).await;
    assert!(res.is_ok());
}
