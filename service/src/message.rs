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
use rand::Rng;
use common::primitives::H256;
use common::chain::block::BlockHeader;

pub enum System {
    P2p,
    Rpc,
    Consensus,
    ChainInfo,
    Mempool,
}

pub enum MessageType {
    GetHeaders(H256, usize),
    Headers(Vec<BlockHeader>),
}

pub struct Message {
    /// Unique ID of the message, used to link requests with responses
    id: u128,

    /// System where the message originated from
    src: System,

    /// System where the message is destined to go
    dst: System,

    /// Request or response
    /// If `msg` is None, the requested resource was not found
    msg: Option<MessageType>,
}

impl Message {
    pub fn new(src: System, dst: System, msg: Option<MessageType>) -> Self {
        Self {
            id: rand::thread_rng().gen(),
            src,
            dst,
            msg,
        }
    }
}
