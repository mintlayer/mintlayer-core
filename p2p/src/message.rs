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
use parity_scale_codec::{Decode, Encode};
use util::Message;

const MINTLAYER_MAGIC_NUM: u32 = 0x11223344;
#[allow(unused)]
const MINTLAYER_MAINNET_ID: u32 = 0xaabbccdd;
#[allow(unused)]
const MINTLAYER_TESTNET_ID: u32 = 0xeeff1122;

#[derive(Debug, Encode, Decode, PartialEq)]
pub enum MessageType {
    Hello,
    HelloAck,
}

#[derive(Debug, Encode, Decode)]
pub struct Message {
    /// Magic number identifying Mintlayer P2P messages
    magic: u32,
    /// Type of the message carried in `payload`
    msg_type: MessageType,
    /// Size of the message
    size: u32,
    /// SCALE-encoded message
    payload: Vec<u8>,
}

#[derive(Debug, Encode, Decode, Message)]
pub struct Hello {
    /// Version of the software
    version: u32,
    /// Network ID
    network: u32,
    /// Services provided by the node
    services: u32,
    /// Unix timestamp
    timestamp: u64,
}

#[derive(Debug, Encode, Decode, Message)]
pub struct HelloAck {
    /// Version of the software
    version: u32,
    /// Network ID
    network: u32,
    /// Services provided by the node
    services: u32,
    /// Unix timestamp
    timestamp: u64,
}
