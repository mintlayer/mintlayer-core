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
use crate::net::libp2p::behaviour;
use crate::testing_utils::{TestTransport, TestTransportLibp2p};
use libp2p::ping;
use std::time::Duration;

#[tokio::test]
async fn test_identify_not_supported() {
    let config = common::chain::config::create_mainnet();
    let (mut backend1, _cmd1, _conn1, _sync1) = make_libp2p(
        config.clone(),
        Default::default(),
        TestTransportLibp2p::make_address(),
        &[],
    )
    .await;

    let (transport, peer_id, _id_keys) = make_transport_and_keys();
    let mut swarm = SwarmBuilder::new(
        transport,
        make_ping(
            Some(Duration::from_secs(2)),
            Some(Duration::from_secs(2)),
            Some(3),
        ),
        peer_id,
    )
    .executor(Box::new(|fut| {
        tokio::spawn(fut);
    }))
    .build();

    connect_swarms::<behaviour::Libp2pBehaviour, ping::Behaviour>(&mut backend1.swarm, &mut swarm)
        .await;

    loop {
        tokio::select! {
            event = backend1.swarm.select_next_some() =>
                if let SwarmEvent::ConnectionClosed { .. } = event { break },
            _event = swarm.select_next_some() => {},
        }
    }
}
