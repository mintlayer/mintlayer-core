// Copyright (c) 2021 RBB S.r.l
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
use crate::message;
use crate::peer::PeerId;
use parity_scale_codec::{Decode, Encode};

#[derive(Debug, Encode, Decode)]
pub enum Event {
    Hello,
}

#[allow(unused)]
pub struct PeerEvent {
    peer_id: PeerId,
    event: PeerEventType,
}

/// P2P uses these events to communicate with Peer
#[allow(unused)]
pub enum PeerEventType {
    /// Remote peer disconnected
    Disconnected,
    /// Inbound or outbound message
    Message(message::Message),
}
