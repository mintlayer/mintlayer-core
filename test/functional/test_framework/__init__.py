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

def init_mintlayer_types():
    custom_types = {
        "types": {
            "Amount": "Compact<u128>",

            "H256": "[u8; 32]",

            "BlockHeight": "Compact<u64>",

            "OutputValue": {
                "type": "enum",
                "type_mapping": [
                    ["Coin", "Amount"],
                    ["TokenV0", ""], # deprecated
                    ["TokenV1", "(TokenId, Amount)"],
                ]
            },

            "Destination": {
                "type": "enum",
                "type_mapping": [
                    ["AnyoneCanSpend", "()"],
                    ["Address", "(PublicKeyHash)"],
                    ["PublicKey", "PublicKey"],
                    ["ScriptHash", "ScriptId"],
                    ["ClassicMultiSig", "(PublicKeyHash)"],
                ],
            },

            "PublicKeyHash": "[u8; 20]",

            "PublicKey": {
                "type": "struct",
                "type_mapping": [
                    ["key", "PublicKeyHolder"],
                ],
            },

            "PublicKeyHolder": {
                "type": "enum",
                "type_mapping": [
                    ["Secp256k1Schnorr", "(Secp256k1PublicKey)"],
                ],
            },

            "Secp256k1PublicKey": {
                "type": "struct",
                "type_mapping": [
                    ["pubkey_data", "[u8; 33]"],
                ],
            },

            "TxOutput": {
                "type": "enum",
                "type_mapping": [
                    ["Transfer", "(OutputValue, Destination)"],
                    ["LockThenTransfer", "(OutputValue, Destination, OutputTimeLock)"],
                    ["Burn", "(OutputValue)"],
                    ["CreateStakePool", "(PoolId, StakePoolData)"],
                    ["ProduceBlockFromStake", "(Destination, PoolId)"],
                    ["CreateDelegationId", "(Destination, PoolId)"],
                    ["DelegateStaking", "(Amount, DelegationId)"],
                    ["IssueFungibleToken", ""], # TODO
                    ["IssueNft", ""], # TODO
                    ["DataDeposit", "Vec<u8>"],
                    ["Htlc", "(OutputValue, HashedTimelockContract)"],
                ]
            },

            "HashedTimelockContract": {
                "type": "struct",
                "type_mapping": [
                    ["secret_hash", "[u8; 20]"],
                    ["spend_key", "Destination"],
                    ["refund_timelock", "OutputTimeLock"],
                    ["refund_key", "Destination"],
                ],
            },

            "OutputTimeLock": {
                "type": "enum",
                "type_mapping": [
                    ["UntilHeight", "(BlockHeight)"],
                    ["UntilTime", "(BlockTimestamp)"],
                    ["ForBlockCount", "Compact<u64>"],
                    ["ForSeconds", "Compat<u64>"],
                ],
            },

            "PoolId": "H256",
            "DelegationId": "H256",
            "TokenId": "H256",

            "StakePoolData": {
                "type": "struct",
                "type_mapping": [
                    ["value", "Amount"],
                    ["staker", "Destination"],
                    ["vrf_public_key", "VRFPublicKey"],
                    ["decommission_key", "Destination"],
                    ["margin_ratio_per_thousand", "u16"],
                    ["cost_per_block", "Amount"]
                ],
            },

            "VRFPublicKey": {
                "type": "struct",
                "type_mapping": [
                    ["key", "VRFPublicKeyHolder"],
                ],
            },

            "VRFPublicKeyHolder": {
                "type": "enum",
                "type_mapping": [
                    ["Schnorrkel", "(SchnorrkelPublicKey)"],
                ]
            },

            "SchnorrkelPublicKey": {
                "type": "struct",
                "type_mapping": [
                    ["key", "[u8; 32]"],
                ],
            },

            "OutPointSourceId": {
                "type": "enum",
                "type_mapping": [
                    ["Transaction", "H256"],
                    ["BlockReward", "H256"],
                ]
            },

            "OutPoint": {
                "type": "struct",
                "type_mapping": [
                    ["id", "OutPointSourceId"],
                    ["index", "u32"],
                ]
            },

            "TxInput": {
                "type": "enum",
                "type_mapping": [
                    ["Utxo", "OutPoint"],
                    ["Account", "(AccountOutPoint)"],
                ]
            },

            "AccountOutPoint": {
                "type": "struct",
                "type_mapping": [
                    ["nonce", "Compact<u64>"],
                    ["account", "AccountSpending"],
                ],
            },

            "AccountSpending": {
                "type": "enum",
                "type_mapping": [
                    ["Delegation", "(H256, Amount)"],
                ],
            },

            "TransactionV1": {
                "type": "struct",
                "type_mapping": [
                    ["version", "u8"], # has to be 1
                    ["flags", "Compact<u128>"],
                    ["inputs", "Vec<TxInput>"],
                    ["outputs", "Vec<TxOutput>"],
                ]
            },

            "InputWitness": {
                "type": "enum",
                "type_mapping": [
                    ["NoSignature", "Option<Vec<u8>>"],
                    ["Standard", "StandardInputSignature"],
                ],
            },

            "TokenAdditionalInfo": {
                "type": "struct",
                "type_mapping": [
                    ["num_decimals", "u8"],
                    ["ticker", "Vec<u8>"],
                ]
            },

            "InfoId": {
                "type": "enum",
                "type_mapping": [
                    ["TokenId", "H256"],
                    ["PoolId", "H256"],
                    ["OrderId", "H256"],
                ],
            },

            "TxAdditionalInfo": {
                "type": "enum",
                "type_mapping": [
                    ["TokenInfo", "TokenAdditionalInfo"],
                    ["PoolInfo", "(Amount)"],
                    ["OrderInfo", ""], # TODO
                ],
            },

            "StandardInputSignature": {
                "type": "struct",
                "type_mapping": [
                    ["sighash_type", "u8"],
                    ["raw_signature", "Vec<u8>"],
                ],
            },

            "SignedTransaction": {
                "type": "struct",
                "type_mapping": [
                    ["transaction", "TransactionV1"],
                    ["signatures", "Vec<InputWitness>"],
                ]
            },

            "PartiallySignedTransaction": {
                "type": "struct",
                "type_mapping": [
                    ["tx", "TransactionV1"],
                    ["witnesses", "Vec<Option<InputWitness>>"],
                    ["input_utxos", "Vec<Option<TxOutput>>"],
                    ["destinations", "Vec<Option<Destination>>"],
                    ["htlc_secrets", "Vec<Option<[u8; 32]>>"],
                    ["additional_infos", "BTreeMap<InfoId, TxAdditionalInfo>"],
                ]
            },

            "SignedTransactionIntent": {
                "type": "struct",
                "type_mapping": [
                    ["signed_message", "String"],
                    ["signatures", "Vec<Vec<u8>>"],
                ]
            },

            "AuthorizedPublicKeyHashSpend" : {
                "type": "struct",
                "type_mapping": [
                    ["public_key", "PublicKey"],
                    ["signature", "Signature"],
                ]
            },

            "SemVer": {
                "type": "struct",
                "type_mapping": [
                    ["major", "u8"],
                    ["minor", "u8"],
                    ["patch", "u16"],
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
                    ["protocol", "u32"],
                    ["network", "[u8; 4]"],
                    ["services", "u64"],
                    ["user_agent", "String"],
                    ["version", "SemVer"],
                    ["receiver_address", "Option<PeerAddress>"],
                    ["current_time", "Compact<u64>"],
                    ["handshake_nonce", "u64"],
                ]
            },

            "HandshakeHelloAck": {
                "type": "struct",
                "type_mapping": [
                    ["protocol", "u32"],
                    ["network", "[u8; 4]"],
                    ["services", "u64"],
                    ["user_agent", "String"],
                    ["version", "SemVer"],
                    ["receiver_address", "Option<PeerAddress>"],
                    ["current_time", "Compact<u64>"],
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

            "BlockHeader": {
                "type": "struct",
                "type_mapping": [
                    ["version", "u8"],
                    ["prev_block_id", "H256"],
                    ["tx_merkle_root", "H256"],
                    ["witness_merkle_root", "H256"],
                    ["timestamp", "Compact<u64>"],
                    ["consensus_data", "ConsensusData"],
                ]
            },

            "SignedBlockHeader": {
                "type": "struct",
                "type_mapping": [
                    ["header", "BlockHeader"],
                    ["signature", "BlockHeaderSignature"],
                ]
            },

            "BlockHeaderSignature": {
                "type": "enum",
                "type_mapping": [
                    ["None", "()"],
                    ["HeaderSignature", "(BlockHeaderSignatureData)"],
                ]
            },

            "BlockHeaderSignatureData": {
                "type": "struct",
                "type_mapping": [
                    ["signature", "(Signature)"],
                ]
            },

            "Signature": {
                "type": "enum",
                "type_mapping": [
                    ["Secp256k1Schnorr", "[u8; 64]"],
                ],
            },

            "ConsensusData": {
                "type": "enum",
                "type_mapping": [
                    ["None", "()"],
                    ["PoW", "PoWData"],
                    ["PoS", "PoSData"],
                ]
            },

            "PoWData": {
                "type": "struct",
                "type_mapping": [
                    ["bits", "u32"],
                    ["nonce", "u128"],
                ]
            },

            "PoSData": {
                "type": "struct",
                "type_mapping": [
                    ["kernel_inputs", "Vec<TxInput>"],
                    ["kernel_witness", "Vec<InputWitness>"],
                    ["stake_pool_id", "PoolId"],
                    ["vrf_data", "VRFReturn"],
                    ["compact_target", "u32"],
                ]
            },

            "VRFReturn": {
                "type": "enum",
                "type_mapping": [
                    ["Schnorrkel", "(SchnorrkelVRFReturn)"],
                ],
            },

            "SchnorrkelVRFReturn": {
                "type": "struct",
                "type_mapping": [
                    ["preout", "[u8; 32]"],
                    ["proof", "[u8; 64]"],
                ],
            },

            "BlockIdAtHeight": "H256",

            "BlockBody": {
                "type": "struct",
                "type_mapping": [
                    ["reward", "BlockReward"],
                    ["transactions", "Vec<SignedTransaction>"],
                ],
            },

            "BlockReward": {
                "type": "struct",
                "type_mapping": [
                    ["reward_outputs", "Vec<TxOutput>"],
                ],
            },


            "Block": {
                "type": "enum",
                "type_mapping": [
                    ["V1", "(BlockV1)"],
                ],
            },

            "BlockV1": {
                "type": "struct",
                "type_mapping": [
                    ["header", "SignedBlockHeader"],
                    ["body", "BlockBody"],
                ]
            },

            "Id": "[u8; 32]",

            "HeaderListRequest": "Vec<Id>",

            "HeaderList": "Vec<SignedBlockHeader>",

            "TransactionResponse": {
                "type": "enum",
                "type_mapping": [
                    ["not_found", "Id"],
                    ["found", "SignedTransaction"],
                ],
            },

            "Message": {
                "type": "enum",
                "type_mapping": [
                    ["handshake", "HandshakeMessage"],
                    ["ping_request", "PingMessage"],
                    ["ping_response", "PingMessage"],
                    ["new_transaction", "Id"],
                    ["header_list_request", "HeaderListRequest"],
                    ["header_list", "HeaderList"],
                    ["block_list_request", "Vec<Id>"], # TODO
                    ["block_response", "()"], # TODO
                    ["announce_addr_request", "PeerAddress"], # TODO
                    ["addr_list_request", "()"], # TODO
                    ["addr_list_response", "Vec<PeerAddress>"], # TODO
                    ["transaction_request", "Id"],
                    ["transaction_response", "TransactionResponse"],
                ]
            },

            "GenerateBlockInputData": {
                "type": "enum",
                "type_mapping": [
                    ["None", "()"],
                    ["PoW", "PoWGenerateBlockInputData"],
                    ["PoS", "PoSGenerateBlockInputData"]
                ]
            },

            "PoSGenerateBlockInputData": {
                "type": "struct",
                "type_mapping": [
                    ["stake_private_key", "PrivateKey"],
                    ["vrf_private_key", "VRFPrivateKey"],
                    ["pool_id", "PoolId"],
                    ["kernel_inputs", "Vec<TxInput>"],
                    ["kernel_input_utxo", "Vec<TxOutput>"],
                ],
            },

            "Privatekey": {
                "type": "struct",
                "type_mapping": [
                    ["key", "PrivateKeyHolder"],
                ],
            },

            "PrivateKeyHolder": {
                "type": "enum",
                "type_mapping": [
                    ["Secp256k1Schnorr", "(Secp256k1PrivateKey)"],
                ],
            },

            "Secp256k1PrivateKey": {
                "type": "struct",
                "type_mapping": [
                    ["data", "[u8; 32]"],
                ],
            },

            "VRFPrivateKey": {
                "type": "struct",
                "type_mapping": [
                    ["key", "VRFPrivateKeyHolder"],
                ],
            },

            "VRFPrivateKeyHolder": {
                "type": "enum",
                "type_mapping": [
                    ["Schnorrkel", "(SchnorrkelPrivateKey)"],
                ],
            },

            "SchnorrkelPrivateKey": {
                "type": "struct",
                "type_mapping": [
                    ["key", "[u8; 64]"]
                ],
            },

            "PoWGenerateBlockInputData": {
                "type": "struct",
                "type_mapping": [
                    ["reward_destination", "Destination"],
                ]
            },
        }
    }

    scalecodec.base.RuntimeConfiguration().update_type_registry(custom_types)

init_mintlayer_types()
