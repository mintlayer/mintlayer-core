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
use common::primitives::version::SemVer;
use serialization::{Decode, Encode};

#[derive(Debug, Encode, Decode, Copy, Clone, PartialEq, Eq)]
#[allow(unused)]
pub enum HandshakeMessage {
    Hello {
        /// Software version of local node
        version: SemVer,
        /// Services that the local node supports
        services: u32,
        /// Unix timestamp
        timestamp: i64,
    },
    HelloAck {
        /// Software version of local node
        version: SemVer,
        /// Services that the local node supports
        services: u32,
        /// Unix timestamp
        timestamp: i64,
    },
}

#[derive(Debug, Encode, Decode, Copy, Clone, PartialEq, Eq)]
pub enum ConnectivityMessage {
    Ping { nonce: u64 },
    Pong { nonce: u64 },
}

#[derive(Debug, Encode, Decode, Copy, Clone, PartialEq, Eq)]
#[allow(unused)]
pub enum MessageType {
    Handshake(HandshakeMessage),
    Connectivity(ConnectivityMessage),
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
    use common::chain::config;
    use common::primitives::time;

    #[test]
    fn hello_test() {
        let config = config::create_mainnet();
        let serv = 0u32;
        let ts = time::get();

        let msg = Message {
            magic: *config.magic_bytes(),
            msg: MessageType::Handshake(HandshakeMessage::Hello {
                version: SemVer::new(0, 1, 0),
                services: serv,
                timestamp: ts,
            }),
        };
        assert_eq!(&msg.magic, config.magic_bytes());

        match msg.msg {
            MessageType::Handshake(HandshakeMessage::Hello {
                version,
                services,
                timestamp,
            }) => {
                assert_eq!(version, SemVer::new(0, 1, 0));
                assert_eq!(services, serv);
                assert_eq!(timestamp, ts);
            }
            _ => panic!("invalid message type"),
        }

        let encoded = msg.encode();
        let message: Message = Decode::decode(&mut &encoded[..]).unwrap();

        match message.msg {
            MessageType::Handshake(HandshakeMessage::Hello {
                version,
                services,
                timestamp,
            }) => {
                assert_eq!(version, SemVer::new(0, 1, 0));
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
        let ts = time::get();

        let msg = Message {
            magic: *config.magic_bytes(),
            msg: MessageType::Handshake(HandshakeMessage::HelloAck {
                version: SemVer::new(0, 1, 0),
                services: serv,
                timestamp: ts,
            }),
        };
        assert_eq!(&msg.magic, config.magic_bytes());

        match msg.msg {
            MessageType::Handshake(HandshakeMessage::HelloAck {
                version,
                services,
                timestamp,
            }) => {
                assert_eq!(version, SemVer::new(0, 1, 0));
                assert_eq!(services, serv);
                assert_eq!(timestamp, ts);
            }
            _ => panic!("invalid message type"),
        }

        let encoded = msg.encode();
        let message: Message = Decode::decode(&mut &encoded[..]).unwrap();

        match message.msg {
            MessageType::Handshake(HandshakeMessage::HelloAck {
                version,
                services,
                timestamp,
            }) => {
                assert_eq!(version, SemVer::new(0, 1, 0));
                assert_eq!(services, serv);
                assert_eq!(timestamp, ts);
            }
            _ => panic!("invalid message type"),
        }
    }
}
