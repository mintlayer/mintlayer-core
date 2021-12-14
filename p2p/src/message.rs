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
use common::chain::config::{ChainType, MAGIC_BYTES};
use parity_scale_codec::{Decode, Encode};
use util::Message;

#[derive(Debug, Encode, Decode, PartialEq, Clone)]
pub enum MessageType {
    Hello,
    HelloAck,
}

#[derive(Debug, Encode, Decode, Clone)]
pub struct Message {
    /// Magic number identifying Mintlayer P2P messages
    magic: [u8; 4],
    /// Type of the message carried in `payload`
    msg_type: MessageType,
    /// Size of the message
    size: u32,
    /// SCALE-encoded message
    payload: Vec<u8>,
}

#[derive(Debug, Encode, Decode, PartialEq, Clone, Message)]
pub struct Hello {
    /// Version of the software
    version: u32,
    /// Network ID
    network: ChainType,
    /// Services provided by the node
    services: u32,
    /// Unix timestamp
    timestamp: u64,
}

#[derive(Debug, Encode, Decode, PartialEq, Clone, Message)]
pub struct HelloAck {
    /// Version of the software
    version: u32,
    /// Network ID
    network: ChainType,
    /// Services provided by the node
    services: u32,
    /// Unix timestamp
    timestamp: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::P2pError;
    use std::time::SystemTime;

    #[test]
    fn hello_test() {
        let version = 215; // v2.1.5
        let services = 0;
        let timestamp: u64 =
            SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();

        let hello = Hello::new(version, ChainType::Mainnet, services, timestamp);
        let msg: Message = hello.clone().into();

        // Hello message cannot be converted to HelloAck message
        // even if the representation of the messages is exactly the same
        assert_eq!(
            HelloAck::try_from(msg.clone()),
            Err(P2pError::DecodeFailure("Invalid message type".to_string()))
        );
        assert_eq!(Hello::try_from(msg.clone()), Ok(hello));
        assert_eq!(msg.msg_type as u8, 0);
    }

    #[test]
    fn hello_ack_test() {
        let version = 215; // v2.1.5
        let services = 0;
        let timestamp: u64 =
            SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();

        let hello_ack = HelloAck::new(version, ChainType::Mainnet, services, timestamp);
        let msg: Message = hello_ack.clone().into();

        // Hello message cannot be converted to HelloAck message
        // even if the representation of the messages is exactly the same
        assert_eq!(
            Hello::try_from(msg.clone()),
            Err(P2pError::DecodeFailure("Invalid message type".to_string()))
        );
        assert_eq!(HelloAck::try_from(msg.clone()), Ok(hello_ack));
        assert_eq!(msg.msg_type as u8, 1);
    }
}
