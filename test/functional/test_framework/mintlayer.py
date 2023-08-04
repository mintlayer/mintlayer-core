#  Copyright (c) 2023 RBB S.r.l
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

""" Module for mintlayer-specific utilities for testing """

import hashlib
import scalecodec
import time

MLT_COIN = 100_000_000_000

base_tx_obj = scalecodec.base.RuntimeConfiguration().create_scale_object('TransactionV1')
block_header_obj = scalecodec.base.RuntimeConfiguration().create_scale_object('BlockHeader')
block_input_data_obj = scalecodec.base.RuntimeConfiguration().create_scale_object('GenerateBlockInputData')
block_obj = scalecodec.base.RuntimeConfiguration().create_scale_object('BlockV1')
outpoint_obj = scalecodec.base.RuntimeConfiguration().create_scale_object('OutPoint')
signed_tx_obj = scalecodec.base.RuntimeConfiguration().create_scale_object('SignedTransaction')
vec_output_obj = scalecodec.base.RuntimeConfiguration().create_scale_object('Vec<TxOutput>')

def mintlayer_hash(data):
    return hashlib.blake2b(data, digest_size = 64).digest()[0:32]

def hash_object(obj, data):
    return scalecodec.ScaleBytes(mintlayer_hash(obj.encode(data).data)).to_hex()[2:]

def reward_input(block_id, index = 0):
    return { 'Utxo' : {
           'id': { 'BlockReward': '0x{}'.format(block_id) },
           'index': index,
        }
    }

def tx_input(tx_id, index = 0):
    return { 'Utxo' : {
           'id': { 'Transaction': '0x{}'.format(tx_id) },
           'index': index,
        }
    }

def tx_output(amount, timelock = None):
    if isinstance(amount, dict):
        return amount
    if timelock is None:
        return {'Transfer': [ { 'Coin': amount }, { 'AnyoneCanSpend': None } ]}
    else:
        return {'LockThenTransfer': [ { 'Coin': amount }, { 'AnyoneCanSpend': None }, timelock ]}


def make_tx(inputs, outputs, flags = 0):
    outputs = [ tx_output(amt) for amt in outputs ]
    witness = { 'NoSignature': None }
    tx = {
        'version': 1,
        'flags': flags,
        'inputs': inputs,
        'outputs': outputs,
    }
    signed_tx = {
        'transaction': tx,
        'signatures': [witness for _ in inputs],
    }
    tx_id = hash_object(base_tx_obj, tx)
    encoded_tx = signed_tx_obj.encode(signed_tx).to_hex()[2:]
    return (encoded_tx, tx_id)

def make_empty_block(parent_id, nonce, transactions = []):
    empty_merkle_root = "0x" + hash_object(vec_output_obj, [])
    pow_data = {
        'bits': 0x207fffff,
        'nonce': nonce,
    }
    header = {
        'version': 1,
        'prev_block_id': "0x{}".format(parent_id),
        'tx_merkle_root': empty_merkle_root,
        'witness_merkle_root': empty_merkle_root,
        'timestamp': int(time.time()),
        'consensus_data': { 'PoW': pow_data },
    }
    signed_header = {
        'header': header,
        'signature': { 'None': None },
    }
    block_body = {
        'reward': {
            'reward_outputs': [],
        },
        'transactions': transactions,
    }
    block = {
        'header': signed_header,
        'body': block_body,
    }
    block_id = hash_object(block_header_obj, header)
    encoded_block = block_obj.encode(block).to_hex()[2:]
    return (encoded_block, block_id)

def mine_empty_block(parent_id):
    for nonce in range(1000):
        (block, block_id) = make_empty_block(parent_id, nonce)
        if block_id[-2] in "0123456":
            return (block, block_id)
    assert False, "Cannot mine block"
