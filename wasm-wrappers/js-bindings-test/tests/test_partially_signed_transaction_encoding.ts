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

import {
  Amount,
  decode_partially_signed_transaction_to_js,
  encode_destination,
  encode_input_for_conclude_order,
  encode_input_for_fill_order,
  encode_input_for_utxo,
  encode_lock_until_height,
  encode_multisig_challenge,
  encode_output_lock_then_transfer,
  encode_output_htlc,
  encode_output_produce_block_from_stake,
  encode_output_transfer,
  encode_partially_signed_transaction,
  encode_transaction,
  encode_witness,
  make_default_account_privkey,
  make_receiving_address,
  multisig_challenge_to_address,
  Network,
  pubkey_to_pubkeyhash_address,
  public_key_from_private_key,
  SignatureHashType,
  TxAdditionalInfo,
} from "../../pkg/wasm_wrappers.js";

import { assert_eq_vals } from "./utils.js";

import {
  ANOTHER_ORDER_ID,
  MNEMONIC,
  POOL_ID,
  ORDER_ID,
  SIGHASH_INPUT_COMMITMENTS_V1_TESTNET_FORK_HEIGHT,
  TOKEN_ID,
  HTLC_SECRET_HASH,
  HTLC_SECRET,
} from "./defs.js";
import { ADDRESS } from "./test_address_generation.js";

export function test_partially_signed_transaction_encoding() {
  const height = SIGHASH_INPUT_COMMITMENTS_V1_TESTNET_FORK_HEIGHT;
  const account_privkey = make_default_account_privkey(
    MNEMONIC,
    Network.Testnet,
  );
  function make_addr(key_index: number) {
    const sk = make_receiving_address(account_privkey, key_index);
    const pk = public_key_from_private_key(sk);
    return pubkey_to_pubkeyhash_address(pk, Network.Testnet)
  }

  const produce_block_from_stake_utxo = encode_output_produce_block_from_stake(
    POOL_ID,
    ADDRESS,
    Network.Testnet
  );
  const block_outpoint = new Uint8Array(33).fill(1);
  const tx_outpoint = new Uint8Array(33).fill(0);
  const produce_block_from_stake_input = encode_input_for_utxo(block_outpoint, 1);

  const fill_order_input = encode_input_for_fill_order(
    ORDER_ID,
    Amount.from_atoms("40000"),
    ADDRESS,
    BigInt(1),
    BigInt(height),
    Network.Testnet
  );

  const conclude_order_input = encode_input_for_conclude_order(
    ANOTHER_ORDER_ID,
    BigInt(1),
    BigInt(height),
    Network.Testnet
  );

  const transfer_input_sk = make_receiving_address(account_privkey, 0);
  const transfer_input_pk = public_key_from_private_key(transfer_input_sk);
  const transfer_input_addr = pubkey_to_pubkeyhash_address(
    transfer_input_pk,
    Network.Testnet
  );

  const transfer_utxo = encode_output_transfer(Amount.from_atoms("100"), transfer_input_addr, Network.Testnet);

  const alice_sk = make_receiving_address(account_privkey, 1);
  const bob_sk = make_receiving_address(account_privkey, 2);
  const alice_pk = public_key_from_private_key(alice_sk);
  const bob_pk = public_key_from_private_key(bob_sk);
  const htlc_challenge = encode_multisig_challenge(Uint8Array.from([...alice_pk, ...bob_pk]), 2, Network.Testnet);
  const htlc_multisig_destination = multisig_challenge_to_address(htlc_challenge, Network.Testnet);

  const htlc_spend_addr = make_addr(3);
  const htlc_utxo = encode_output_htlc(
    Amount.from_atoms("40000"),
    undefined,
    HTLC_SECRET_HASH,
    htlc_spend_addr,
    htlc_multisig_destination,
    encode_lock_until_height(BigInt(100)),
    Network.Testnet
  );
  const transfer_input = encode_input_for_utxo(tx_outpoint, 1);
  const htlc_input = encode_input_for_utxo(tx_outpoint, 2);

  const inputs = [...produce_block_from_stake_input, ...fill_order_input, ...conclude_order_input, ...transfer_input, ...htlc_input];
  const input_utxos = [1, ...produce_block_from_stake_utxo, 0, 0, 1, ...transfer_utxo, 1, ...htlc_utxo];

  const output_lock = encode_lock_until_height(BigInt(123));
  const lock_tehn_transfer_dest_addr = make_addr(4);
  const output = encode_output_lock_then_transfer(
    Amount.from_atoms("100"),
    lock_tehn_transfer_dest_addr,
    output_lock,
    Network.Testnet
  );
  const outputs = [...output];

  const produce_block_from_stake_input_dest_addr = make_addr(5);
  const conclude_order_input_dest_addr = make_addr(6);

  const tx = encode_transaction(Uint8Array.from(inputs), Uint8Array.from(outputs), BigInt(0));

  const additional_info: TxAdditionalInfo = {
    pool_info: { [POOL_ID]: { staker_balance: { atoms: "4000000000000000" } } },
    order_info: {
      [ORDER_ID]: {
        initially_asked: {
          coins: { atoms: "3000000000000000" },
        },
        initially_given: {
          tokens: {
            token_id: TOKEN_ID,
            amount: { atoms: "3000000000000000" }
          }
        },
        ask_balance: { atoms: "3000000000000000" },
        give_balance: { atoms: "3000000000000000" }
      },
      [ANOTHER_ORDER_ID]: {
        initially_asked: {
          coins: { atoms: "4000000000000000" },
        },
        initially_given: {
          tokens: {
            token_id: TOKEN_ID,
            amount: { atoms: "4000000000000000" }
          }
        },
        ask_balance: { atoms: "4000000000000000" },
        give_balance: { atoms: "4000000000000000" }
      }
    }
  };

  const transfer_input_sig = encode_witness(
    SignatureHashType.ALL,
    transfer_input_sk,
    transfer_input_addr,
    tx,
    Uint8Array.from(input_utxos),
    0,
    additional_info,
    BigInt(height),
    Network.Testnet
  );
  const signatures = [0, 0, 0, 1, ...transfer_input_sig, 0];

  const produce_block_from_stake_input_dest = encode_destination(produce_block_from_stake_input_dest_addr, Network.Testnet);
  const conclude_order_input_dest = encode_destination(conclude_order_input_dest_addr, Network.Testnet);
  const transfer_input_dest = encode_destination(transfer_input_addr, Network.Testnet);
  const htlc_input_dest = encode_destination(htlc_spend_addr, Network.Testnet);

  const input_destinations = [
    1, ...produce_block_from_stake_input_dest, 0, 1, ...conclude_order_input_dest, 1, ...transfer_input_dest, 1, ...htlc_input_dest
  ];
  const htlc_secrets = [0, 0, 0, 0, 1, ...HTLC_SECRET];

  const ptx = encode_partially_signed_transaction(
    tx, Uint8Array.from(signatures),
    Uint8Array.from(input_utxos),
    Uint8Array.from(input_destinations),
    Uint8Array.from(htlc_secrets),
    additional_info,
    Network.Testnet
  );

  const ptx_json = decode_partially_signed_transaction_to_js(ptx, Network.Testnet);
  const expected_ptx_json = {
    "tx":{
        "V1":{
          "version":1,
          "flags":0,
          "inputs":[
              {
                "Utxo":{
                    "id":{
                      "BlockReward":"0101010101010101010101010101010101010101010101010101010101010101"
                    },
                    "index":1
                }
              },
              {
                "OrderAccountCommand":{
                    "FillOrder":[
                      "tordr1xxt0avjtt4flkq0tnlyphmdm4aaj9vmkx5r2m4g863nw3lgf7nzs7mlkqc",
                      {
                          "atoms":"40000"
                      }
                    ]
                }
              },
              {
                "OrderAccountCommand":{
                    "ConcludeOrder":"tordr1mslcn8z774t3ug9zcxa6mqr9yc29r60fg8fkhajnngc98ryh5m3sqz6jvz"
                }
              },
              {
                "Utxo":{
                    "id":{
                      "Transaction":"0000000000000000000000000000000000000000000000000000000000000000"
                    },
                    "index":1
                }
              },
              {
                "Utxo":{
                    "id":{
                      "Transaction":"0000000000000000000000000000000000000000000000000000000000000000"
                    },
                    "index":2
                }
              }
          ],
          "outputs":[
              {
                "LockThenTransfer":[
                    {
                      "Coin":{
                          "atoms":"100"
                      }
                    },
                    "tmt1qyuf7yschhzdhumusrl2r4vydhqp5l0vtsff2aw9",
                    {
                      "type":"UntilHeight",
                      "content":123
                    }
                ]
              }
          ]
        }
    },
    "witnesses":[
        null,
        null,
        null,
        {
          "Standard":{
              "sighash_type":1,
              // Note: the leading 4 bytes of transfer_input_sig are:
              // the index of the InputWitness::Standard variant, sighash_type and 2 bytes
              // for the length of the raw_signature vec.
              "raw_signature": Array.from(transfer_input_sig).slice(4)
          }
        },
        null
    ],
    "input_utxos":[
        {
          "ProduceBlockFromStake":[
              "tmt1q9dn5m4svn8sds3fcy09kpxrefnu75xekgr5wa3n",
              "tpool1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqza035u"
          ]
        },
        null,
        null,
        {
          "Transfer":[
              {
                "Coin":{
                    "atoms":"100"
                }
              },
              "tmt1q9dn5m4svn8sds3fcy09kpxrefnu75xekgr5wa3n"
          ]
        },
        {
          "Htlc":[
              {
                "Coin":{
                    "atoms":"40000"
                }
              },
              {
                "secret_hash":"b5a48c7780e597de8012346fb30761965248e3f2",
                "spend_key":"tmt1qyfvlt0tc8z8gaqyu8sjlm2yte5jr8mlnutmxwn2",
                "refund_timelock":{
                    "type":"UntilHeight",
                    "content":100
                },
                "refund_key":"tmtc1qszl7xx5rcy5s7azhee88qadccfnhj7l6vgzxlym"
              }
          ]
        }
    ],
    "destinations":[
        "tmt1q9df8haugxrq83wky4ym6ldmthzzyecjr5qd3sr6",
        null,
        "tmt1qxdchxlzxj3srxdtfukdwdxy2n27wytq5yzkl4yc",
        "tmt1q9dn5m4svn8sds3fcy09kpxrefnu75xekgr5wa3n",
        "tmt1qyfvlt0tc8z8gaqyu8sjlm2yte5jr8mlnutmxwn2"
    ],
    "htlc_secrets":[
        null,
        null,
        null,
        null,
        {
          "secret": HTLC_SECRET
        }
    ],
    "additional_info":{
        "pool_info":{
          "tpool1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqza035u":{
              "staker_balance":{
                "atoms":"4000000000000000"
              }
          }
        },
        "order_info":{
          "tordr1xxt0avjtt4flkq0tnlyphmdm4aaj9vmkx5r2m4g863nw3lgf7nzs7mlkqc":{
              "initially_asked":{
                "Coin":{
                    "atoms":"3000000000000000"
                }
              },
              "initially_given":{
                "TokenV1":[
                    "tmltk15tgfrs49rv88v8utcllqh0nvpaqtgvn26vdxhuner5m6ewg9c3msn9fxns",
                    {
                      "atoms":"3000000000000000"
                    }
                ]
              },
              "ask_balance":{
                "atoms":"3000000000000000"
              },
              "give_balance":{
                "atoms":"3000000000000000"
              }
          },
          "tordr1mslcn8z774t3ug9zcxa6mqr9yc29r60fg8fkhajnngc98ryh5m3sqz6jvz":{
              "initially_asked":{
                "Coin":{
                    "atoms":"4000000000000000"
                }
              },
              "initially_given":{
                "TokenV1":[
                    "tmltk15tgfrs49rv88v8utcllqh0nvpaqtgvn26vdxhuner5m6ewg9c3msn9fxns",
                    {
                      "atoms":"4000000000000000"
                    }
                ]
              },
              "ask_balance":{
                "atoms":"4000000000000000"
              },
              "give_balance":{
                "atoms":"4000000000000000"
              }
          }
        }
    }
  };

  assert_eq_vals(
    JSON.stringify(ptx_json),
    JSON.stringify(expected_ptx_json),
  );
}
