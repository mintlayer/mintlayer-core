// Copyright (c) 2023 RBB S.r.l
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

use p2p_types::PeerId;
use test_utils::assert_matches_return_val;

use crate::{
    message::PeerManagerMessage,
    net::default_backend::types::{CategorizedMessage, Command},
};

pub fn cmd_to_peer_man_msg(cmd: Command) -> (PeerId, PeerManagerMessage) {
    let (peer_id, msg) = assert_matches_return_val!(
        cmd,
        Command::SendMessage { peer_id, message },
        (peer_id, message)
    );

    let msg = msg.categorize();
    let msg = assert_matches_return_val!(msg, CategorizedMessage::PeerManagerMessage(msg), msg);
    (peer_id, msg)
}
