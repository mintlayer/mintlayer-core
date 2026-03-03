// Copyright (c) 2021-2025 RBB S.r.l
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

use serialization::hex::{HexDecode, HexEncode as _};

use crate::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        htlc::{HashedTimelockContract, HtlcSecret, HTLC_SECRET_SIZE},
        output_value::OutputValue,
        partially_signed_transaction::{
            v1::PartiallySignedTransactionV1, OrderAdditionalInfo, PartiallySignedTransaction,
            PartiallySignedTransactionConsistencyCheck, PoolAdditionalInfo, TxAdditionalInfo,
        },
        signature::{
            inputsig::{standard_signature::StandardInputSignature, InputWitness},
            sighash::sighashtype::SigHashType,
        },
        timelock::OutputTimeLock,
        tokens::TokenId,
        Destination, OrderAccountCommand, OrderId, PoolId, Transaction, TxInput, TxOutput,
        UtxoOutPoint,
    },
    primitives::{Amount, Id, H256},
};

#[test]
fn encode_serialize_consistency_v1() {
    let tx_id1 = Id::<Transaction>::new(H256::repeat_byte(1));
    let tx_id2 = Id::<Transaction>::new(H256::repeat_byte(2));
    let order_id1 = OrderId::new(H256::repeat_byte(3));
    let order_id2 = OrderId::new(H256::repeat_byte(4));
    let pool_id = PoolId::new(H256::repeat_byte(5));
    let dest1 = Destination::PublicKeyHash(PublicKeyHash::repeat_byte(6));
    let dest2 = Destination::PublicKeyHash(PublicKeyHash::repeat_byte(7));
    let dest3 = Destination::PublicKeyHash(PublicKeyHash::repeat_byte(8));
    let dest4 = Destination::PublicKeyHash(PublicKeyHash::repeat_byte(9));
    let token_id1 = TokenId::new(H256::repeat_byte(10));
    let token_id2 = TokenId::new(H256::repeat_byte(11));

    let htlc_secret = HtlcSecret::new([11; HTLC_SECRET_SIZE]);
    let htlc_secret_hash = htlc_secret.hash();

    let tx = Transaction::new(
        12345,
        vec![
            TxInput::Utxo(UtxoOutPoint::new(tx_id1.into(), 123)),
            TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                order_id1,
                Amount::from_atoms(111),
            )),
            TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(order_id2)),
            TxInput::Utxo(UtxoOutPoint::new(tx_id2.into(), 234)),
        ],
        vec![TxOutput::Burn(OutputValue::Coin(Amount::from_atoms(222)))],
    )
    .unwrap();
    let ptx = PartiallySignedTransaction::V1(
        PartiallySignedTransactionV1::new(
            tx,
            vec![
                Some(InputWitness::Standard(StandardInputSignature::new(
                    SigHashType::all(),
                    vec![1, 2, 3],
                ))),
                None,
                None,
                None,
            ],
            vec![
                Some(TxOutput::ProduceBlockFromStake(dest1.clone(), pool_id)),
                None,
                None,
                Some(TxOutput::Htlc(
                    OutputValue::Coin(Amount::from_atoms(333)),
                    Box::new(HashedTimelockContract {
                        secret_hash: htlc_secret_hash,
                        spend_key: dest3.clone(),
                        refund_timelock: OutputTimeLock::ForBlockCount(2345),
                        refund_key: dest4,
                    }),
                )),
            ],
            vec![Some(dest1), None, Some(dest2), Some(dest3)],
            Some(vec![None, None, None, Some(htlc_secret)]),
            TxAdditionalInfo::new()
                .with_pool_info(
                    pool_id,
                    PoolAdditionalInfo {
                        staker_balance: Amount::from_atoms(444),
                    },
                )
                .with_order_info(
                    order_id1,
                    OrderAdditionalInfo {
                        initially_asked: OutputValue::Coin(Amount::from_atoms(555)),
                        initially_given: OutputValue::TokenV1(token_id1, Amount::from_atoms(666)),
                        ask_balance: Amount::from_atoms(500),
                        give_balance: Amount::from_atoms(600),
                    },
                )
                .with_order_info(
                    order_id2,
                    OrderAdditionalInfo {
                        initially_asked: OutputValue::TokenV1(token_id2, Amount::from_atoms(777)),
                        initially_given: OutputValue::Coin(Amount::from_atoms(888)),
                        ask_balance: Amount::from_atoms(700),
                        give_balance: Amount::from_atoms(800),
                    },
                ),
            PartiallySignedTransactionConsistencyCheck::WithAdditionalInfo,
        )
        .unwrap(),
    );

    let hex_encoded_ptx = ptx.hex_encode();
    let expected_hex_encoded_ptx = concat!(
        "4001e5c010000001010101010101010101010101010101010101010101010101",
        "010101010101017b000000030003030303030303030303030303030303030303",
        "03030303030303030303030303bd010302040404040404040404040404040404",
        "0404040404040404040404040404040404000002020202020202020202020202",
        "02020202020202020202020202020202020202ea000000040200790310010101",
        "0c01020300000010010401060606060606060606060606060606060606060605",
        "0505050505050505050505050505050505050505050505050505050505050500",
        "00010a003505600dfb87c24d80020f92023588880643a321700a010808080808",
        "08080808080808080808080808080802a5240109090909090909090909090909",
        "0909090909090910010106060606060606060606060606060606060606060001",
        "0107070707070707070707070707070707070707070101080808080808080808",
        "080808080808080808080810000000010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b04050505050505050505050505050505",
        "0505050505050505050505050505050505f10608030303030303030303030303",
        "030303030303030303030303030303030303030300ad08020a0a0a0a0a0a0a0a",
        "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a690ad10761090404",
        "040404040404040404040404040404040404040404040404040404040404020b",
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b25",
        "0c00e10df10a810c"
    );
    assert_eq!(hex_encoded_ptx, expected_hex_encoded_ptx);

    // Sanity check: the ptx can be decoded.
    let decoded_ptx = PartiallySignedTransaction::hex_decode_all(&hex_encoded_ptx).unwrap();
    assert_eq!(decoded_ptx, ptx);

    let ptx_as_json = serde_json::to_string(&ptx).unwrap();
    let expected_ptx_as_json = r#"{
        "type":"V1",
        "tx":{
            "V1":{
                "version":1,
                "flags":12345,
                "inputs":[
                    {
                        "Utxo":{
                            "id":{
                                "Transaction":"0101010101010101010101010101010101010101010101010101010101010101"
                            },
                            "index":123
                        }
                    },
                    {
                        "OrderAccountCommand":{
                            "FillOrder":[
                                "HexifiedOrderId{0x0303030303030303030303030303030303030303030303030303030303030303}",
                                {
                                    "atoms":"111"
                                }
                            ]
                        }
                    },
                    {
                        "OrderAccountCommand":{
                            "ConcludeOrder":"HexifiedOrderId{0x0404040404040404040404040404040404040404040404040404040404040404}"
                        }
                    },
                    {
                        "Utxo":{
                            "id":{
                                "Transaction":"0202020202020202020202020202020202020202020202020202020202020202"
                            },
                            "index":234
                        }
                    }
                ],
                "outputs":[
                    {
                        "Burn":{
                            "Coin":{
                                "atoms":"222"
                            }
                        }
                    }
                ]
            }
        },
        "witnesses":[
            {
                "Standard":{
                    "sighash_type":1,
                    "raw_signature":[
                        1,
                        2,
                        3
                    ]
                }
            },
            null,
            null,
            null
        ],
        "input_utxos":[
            {
                "ProduceBlockFromStake":[
                    "HexifiedDestination{0x010606060606060606060606060606060606060606}",
                    "HexifiedPoolId{0x0505050505050505050505050505050505050505050505050505050505050505}"
                ]
            },
            null,
            null,
            {
                "Htlc":[
                    {
                        "Coin":{
                            "atoms":"333"
                        }
                    },
                    {
                        "secret_hash":"600dfb87c24d80020f92023588880643a321700a",
                        "spend_key":"HexifiedDestination{0x010808080808080808080808080808080808080808}",
                        "refund_timelock":{
                            "type":"ForBlockCount",
                            "content":2345
                        },
                        "refund_key":"HexifiedDestination{0x010909090909090909090909090909090909090909}"
                    }
                ]
            }
        ],
        "destinations":[
            "HexifiedDestination{0x010606060606060606060606060606060606060606}",
            null,
            "HexifiedDestination{0x010707070707070707070707070707070707070707}",
            "HexifiedDestination{0x010808080808080808080808080808080808080808}"
        ],
        "htlc_secrets":[
            null,
            null,
            null,
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
        ],
        "additional_info":{
            "pool_info":{
                "HexifiedPoolId{0x0505050505050505050505050505050505050505050505050505050505050505}":{
                    "staker_balance":{
                        "atoms":"444"
                    }
                }
            },
            "order_info":{
                "HexifiedOrderId{0x0303030303030303030303030303030303030303030303030303030303030303}":{
                    "initially_asked":{
                        "Coin":{
                            "atoms":"555"
                        }
                    },
                    "initially_given":{
                        "TokenV1":[
                            "HexifiedTokenId{0x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a}",
                            {
                                "atoms":"666"
                            }
                        ]
                    },
                    "ask_balance":{
                        "atoms":"500"
                    },
                    "give_balance":{
                        "atoms":"600"
                    }
                },
                "HexifiedOrderId{0x0404040404040404040404040404040404040404040404040404040404040404}":{
                    "initially_asked":{
                        "TokenV1":[
                            "HexifiedTokenId{0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b}",
                            {
                                "atoms":"777"
                            }
                        ]
                    },
                    "initially_given":{
                        "Coin":{
                            "atoms":"888"
                        }
                    },
                    "ask_balance":{
                        "atoms":"700"
                    },
                    "give_balance":{
                        "atoms":"800"
                    }
                }
            }
        }
    }"#;
    let expected_ptx_as_json = {
        let mut expected_ptx_as_json = expected_ptx_as_json.to_owned();
        expected_ptx_as_json.retain(|c| !c.is_whitespace());
        expected_ptx_as_json
    };
    assert_eq!(ptx_as_json, expected_ptx_as_json);

    // Note: PartiallySignedTransaction is not deserializable, so can't do the same sanity check
    // here.
}
