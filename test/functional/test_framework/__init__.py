#  Copyright (c) 2022 RBB S.r.l
#  opensource@mintlayer.org
#  SPDX-License-Identifier: MIT
#  Licensed under the MIT License;
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import scalecodec

def init_p2p_types():
    custom_types = {
        "types": {
            "SemVer": {
                "type": "struct",
                "type_mapping": [
                    ["major", "u8"],
                    ["minor", "u8"],
                    ["patch", "u16"],
                ]
            },

            "PubSubTopic": {
                "type": "enum",
                "type_mapping": [
                    ["Transactions", "Null"],
                    ["Blocks", "Null"],
                    ["PeerAddresses", "Null"],
                ]
            },

            "PeerAddressIp4": {
                "type": "struct",
                "type_mapping": [
                    ["ip", "[u8; 4]"],
                    ["port", "u16"],
                ]
            },

            "PeerAddressIp6": {
                "type": "struct",
                "type_mapping": [
                    ["ip", "[u8; 16]"],
                    ["port", "u16"],
                ]
            },

            "PeerAddress": {
                "type": "enum",
                "type_mapping": [
                    ["Ip4", "PeerAddressIp4"],
                    ["Ip6", "PeerAddressIp6"],
                ]
            },

            "HandshakeHello": {
                "type": "struct",
                "type_mapping": [
                    ["version", "SemVer"],
                    ["network", "[u8; 4]"],
                    ["subscriptions", "BTreeSet<PubSubTopic>"],
                    ["receiver_address", "Option<PeerAddress>"],
                    ["handshake_nonce", "u64"],
                ]
            },

            "HandshakeHelloAck": {
                "type": "struct",
                "type_mapping": [
                    ["version", "SemVer"],
                    ["network", "[u8; 4]"],
                    ["subscriptions", "BTreeSet<PubSubTopic>"],
                    ["receiver_address", "Option<PeerAddress>"],
                ]
            },

            "HandshakeMessage": {
                "type": "enum",
                "type_mapping": [
                    ["Hello", "HandshakeHello"],
                    ["HelloAck", "HandshakeHelloAck"],
                ]
            },

            "PingMessage": {
                "type": "struct",
                "type_mapping": [
                    ["nonce", "u64"],
                ]
            },

            # TODO: Implement
            "BlockHeader": {
                "type": "struct",
            },

            "Announcement": {
                "type": "enum",
                "type_mapping": [
                    ["block", "BlockHeader"],
                ]
            },

            "Id": "[u8; 32]",

            "HeaderListRequest": "Vec<Id>",

            "Message": {
                "type": "enum",
                "type_mapping": [
                    ["handshake", "HandshakeMessage"],
                    ["ping_request", "PingMessage"],
                    ["ping_response", "PingMessage"],
                    ["announcement", "Announcement"],
                    ["header_list_request", "HeaderListRequest"],
                ]
            }
        }
    }

    scalecodec.base.RuntimeConfiguration().update_type_registry(custom_types)

init_p2p_types()
