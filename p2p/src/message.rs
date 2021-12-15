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

#[derive(Debug, Encode, Decode, Copy, Clone, PartialEq, Eq)]
#[allow(unused)]
pub enum MessageType {
    Hello {
        /// Software version of local node
        version: u32,
        /// Services that the local node supports
        services: u32,
        /// Unix timestamp
        timestamp: u64,
    },
    HelloAck {
        /// Software version of local node
        version: u32,
        /// Services that the local node supports
        services: u32,
        /// Unix timestamp
        timestamp: u64,
    },
}

#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
#[allow(unused)]
pub struct Message {
    /// Magic number identifying mainnet, testnet
    pub magic: [u8; 4],
    /// Message (Hello, GetHeaders)
    pub msg: MessageType,
}

#[cfg(test)]
mod tests {
    use super::*;
    // use crate::error;
    use common::chain::config;
    use std::time::SystemTime;

    #[test]
    fn hello_test() {
        let config = config::create_mainnet();
        let serv = 0u32;
        let ts: u64 = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();

        let msg = Message {
            magic: *config.magic_bytes(),
            msg: MessageType::Hello {
                version: 1,
                services: serv,
                timestamp: ts,
            },
        };
        assert_eq!(&msg.magic, config.magic_bytes());

        match msg.msg {
            MessageType::Hello {
                version,
                services,
                timestamp,
            } => {
                assert_eq!(version, 1);
                assert_eq!(services, serv);
                assert_eq!(timestamp, ts);
            }
            _ => panic!("invalid message type"),
        }

        let encoded = msg.encode();
        let message: Message = Decode::decode(&mut &encoded[..]).unwrap();

        match message.msg {
            MessageType::Hello {
                version,
                services,
                timestamp,
            } => {
                assert_eq!(version, 1);
                assert_eq!(services, serv);
                assert_eq!(timestamp, ts);
            }
            _ => panic!("invalid message type"),
        }
    }

    #[test]
    fn hello_ack_test() {
        let config = config::create_mainnet();
        let serv = 0u32;
        let ts: u64 = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();

        let msg = Message {
            magic: *config.magic_bytes(),
            msg: MessageType::HelloAck {
                version: 1,
                services: serv,
                timestamp: ts,
            },
        };
        assert_eq!(&msg.magic, config.magic_bytes());

        match msg.msg {
            MessageType::HelloAck {
                version,
                services,
                timestamp,
            } => {
                assert_eq!(version, 1);
                assert_eq!(services, serv);
                assert_eq!(timestamp, ts);
            }
            _ => panic!("invalid message type"),
        }

        let encoded = msg.encode();
        let message: Message = Decode::decode(&mut &encoded[..]).unwrap();

        match message.msg {
            MessageType::HelloAck {
                version,
                services,
                timestamp,
            } => {
                assert_eq!(version, 1);
                assert_eq!(services, serv);
                assert_eq!(timestamp, ts);
            }
            _ => panic!("invalid message type"),
        }
    }
}
