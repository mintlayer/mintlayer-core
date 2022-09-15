// Copyright (c) 2022 RBB S.r.l
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

use super::*;
use crate::{
    error::{P2pError, PeerError},
    net::libp2p::tests::message_types::SyncRequest,
    net::libp2p::types,
};
use futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use p2p_test_utils::{MakeP2pAddress, MakeTestAddress};
use tokio::sync::oneshot;

// try to send request to an uknown peer and verify that the request is not rejected
#[tokio::test]
async fn request_sent_directly_but_peer_not_part_of_swarm() {
    let (mut backend, _cmd, _conn_rx, _gossip_rx, _sync_rx) = make_libp2p(
        common::chain::config::create_mainnet(),
        Arc::new(Default::default()),
        MakeP2pAddress::make_address(),
        &[],
    )
    .await;

    backend
        .swarm
        .behaviour_mut()
        .sync
        .send_request(&PeerId::random(), SyncRequest::new(vec![0u8; 128]));
    assert!(std::matches!(
        backend.swarm.select_next_some().await,
        SwarmEvent::NewListenAddr { .. }
    ));
}

// try to send request to peer that is not part of our swarm and verify
// that the request is rejected by the backend
#[tokio::test]
async fn request_sent_but_peer_not_part_of_swarm() {
    let (mut backend, _cmd, _conn_rx, _gossip_rx, _sync_rx) = make_libp2p(
        common::chain::config::create_mainnet(),
        Arc::new(Default::default()),
        MakeP2pAddress::make_address(),
        &[],
    )
    .await;

    tokio::spawn(async move { backend.run().await });

    let (tx, rx) = oneshot::channel();
    _cmd.send(types::Command::SendRequest {
        peer_id: PeerId::random(),
        request: Box::new(SyncRequest::new(vec![0u8; 128])),
        response: tx,
    })
    .unwrap();

    assert_eq!(
        rx.await.unwrap(),
        Err(P2pError::PeerError(PeerError::PeerDoesntExist))
    );
}
