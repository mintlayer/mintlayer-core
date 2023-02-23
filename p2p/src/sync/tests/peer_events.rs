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

use crate::{
    error::PeerError, sync::tests::helpers::SyncManagerHandle, types::peer_id::PeerId, P2pError,
};

// Check that the header list request is sent to a newly connected peer.
#[tokio::test]
async fn connect_peer() {
    let mut handle = SyncManagerHandle::start().await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;
}

// Check that the attempt to connect the peer twice results in an error.
#[tokio::test]
async fn connect_peer_twice() {
    let mut handle = SyncManagerHandle::start().await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    handle.try_connect_peer(peer);
    assert_eq!(
        P2pError::PeerError(PeerError::PeerAlreadyExists),
        handle.error().await
    );
}

// Disconnecting an unknown or nonexistent peer isn't an error.
#[tokio::test]
async fn disconnect_nonexistent_peer() {
    let mut handle = SyncManagerHandle::start().await;

    let peer = PeerId::new();
    handle.disconnect_peer(peer);
    handle.assert_no_error().await;
}

#[tokio::test]
async fn disconnect_peer() {
    let mut handle = SyncManagerHandle::start().await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;
    handle.disconnect_peer(peer);
    handle.assert_no_error().await;
}
