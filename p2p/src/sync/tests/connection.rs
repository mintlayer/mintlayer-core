// Copyright (c) 2022 RBB S.r.l
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
use super::*;

// handle peer connection event
#[tokio::test]
async fn test_peer_connected() {
    let (mut mgr, _conn, _sync, _pubsub, _swarm) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;

    assert_eq!(
        mgr.on_control_event(event::SyncControlEvent::Connected(PeerId::random())).await,
        Ok(())
    );
    assert_eq!(mgr.peers.len(), 1);
}

// handle peer disconnection event
#[tokio::test]
async fn test_peer_disconnected() {
    let (mut mgr, _conn, _sync, _pubsub, _swarm) =
        make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;

    // send Connected event to SyncManager
    let peer_id = PeerId::random();

    assert_eq!(
        mgr.on_control_event(event::SyncControlEvent::Connected(peer_id)).await,
        Ok(())
    );
    assert_eq!(mgr.peers.len(), 1);

    // no peer with this id exist, nothing happens
    assert_eq!(
        mgr.on_control_event(event::SyncControlEvent::Disconnected(PeerId::random()))
            .await,
        Ok(())
    );
    assert_eq!(mgr.peers.len(), 1);

    assert_eq!(
        mgr.on_control_event(event::SyncControlEvent::Disconnected(peer_id)).await,
        Ok(())
    );
    assert!(mgr.peers.is_empty());
}
