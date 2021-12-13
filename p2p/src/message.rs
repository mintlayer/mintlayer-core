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

#[allow(unused)]
const MINTLAYER_MAGIC_NUM: u32 = 0x11223344;
#[allow(unused)]
const MINTLAYER_MAINNET_ID: u32 = 0xaabbccdd;
#[allow(unused)]
const MINTLAYER_TESTNET_ID: u32 = 0xeeff1122;

#[derive(Debug, Encode, Decode)]
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

#[derive(Debug, Encode, Decode)]
pub struct Hello {
    version: u32,
    network: u32,
    services: u32,
    timestamp: u64,
}

#[derive(Debug, Encode, Decode)]
pub struct HelloAck {
    version: u32,
    network: u32,
    services: u32,
    timestamp: u64,
}
