#!/usr/bin/env python3
#  Copyright (c) 2023-2025 RBB S.r.l
#  Copyright (c) 2017-2021 The Bitcoin Core developers
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
"""Common base class for certain POS-related tests
"""

from abc import abstractmethod
from scalecodec.base import ScaleBytes, ScaleDecoder
from test_framework.authproxy import JSONRPCException
from test_framework.mintlayer import (
    ATOMS_PER_COIN,
    block_input_data_obj,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

import asyncio
import sys
import time


GENESIS_POOL_ID = "123c4c600097c513e088b9be62069f0c74c7671c523c8e3469a1c3f14b7ea2c4"
GENESIS_STAKE_PRIVATE_KEY = "8717e6946febd3a33ccdc3f3a27629ec80c33461c33a0fc56b4836fcedd26638"
GENESIS_STAKE_PUBLIC_KEY = "03c53526caf73cd990148e127cb57249a5e266d78df23968642c976a532197fdaa"
GENESIS_VRF_PUBLIC_KEY = "fa2f59dc7a7e176058e4f2d155cfa03ee007340e0285447892158823d332f744"

GENESIS_VRF_PRIVATE_KEY = (
    "3fcf7b813bec2a293f574b842988895278b396dd72471de2583b242097a59f06"
    "e9f3cd7b78d45750afd17292031373fddb5e7a8090db51221038f5e05f29998e"
)

GENESIS_POOL_ID_ADDR = "rpool1zg7yccqqjlz38cyghxlxyp5lp36vwecu2g7gudrf58plzjm75tzq99fr6v"

CHAIN_POS_NET_UPGRADES = 1


class WalletPOSTestBase(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            f"--chain-pos-netupgrades={CHAIN_POS_NET_UPGRADES}",
            "--blockprod-min-peers-to-produce-blocks=0",
        ]]

    def wallet_chain_config_args(self):
        return [f"--chain-pos-netupgrades={CHAIN_POS_NET_UPGRADES}"]

    def setup_network(self):
        self.setup_nodes()
        self.sync_all(self.nodes[0:1])

    def assert_chain(self, block, previous_tip):
        assert_equal(block["header"]["header"]["prev_block_id"][2:], previous_tip)

    def assert_height(self, expected_height, expected_block):
        block_id = self.nodes[0].chainstate_block_id_at_height(expected_height)
        block = self.nodes[0].chainstate_get_block(block_id)
        assert_equal(block, expected_block)

    def assert_pos_consensus(self, block):
        if block["header"]["header"]["consensus_data"].get("PoS") is None:
            raise AssertionError("Block {} was not PoS".format(block))

    def assert_tip(self, expected_block):
        tip = self.nodes[0].chainstate_best_block_id()
        block = self.nodes[0].chainstate_get_block(tip)
        assert_equal(block, expected_block)

    def generate_block(self, expected_height, block_input_data, transactions):
        previous_block_id = self.nodes[0].chainstate_best_block_id()

        fill_mode = 'LeaveEmptySpace'
        # Block production may fail if the Job Manager found a new tip, so try and sleep
        for _ in range(5):
            try:
                block_hex = self.nodes[0].blockprod_generate_block(block_input_data, transactions, [], fill_mode)
                break
            except JSONRPCException:
                block_hex = self.nodes[0].blockprod_generate_block(block_input_data, transactions, [], fill_mode)
                time.sleep(1)

        block_hex_array = bytearray.fromhex(block_hex)
        block = ScaleDecoder.get_decoder_class('BlockV1', ScaleBytes(block_hex_array)).decode()

        self.nodes[0].chainstate_submit_block(block_hex)

        self.assert_tip(block_hex)
        self.assert_height(expected_height, block_hex)
        self.assert_pos_consensus(block)
        self.assert_chain(block, previous_block_id)

    def genesis_pool_id(self):
        return self.hex_to_dec_array(GENESIS_POOL_ID)

    def hex_to_dec_array(self, hex_string):
        return [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)]

    def previous_block_id(self):
        previous_block_id = self.nodes[0].chainstate_best_block_id()
        return self.hex_to_dec_array(previous_block_id)

    def stake_private_key(self, stake_private_key):
        return {
            "key": {
                "Secp256k1Schnorr": {
                    "data": self.hex_to_dec_array(stake_private_key),
                },
            },
        }

    def stake_public_key(self, stake_public_key):
        return {
            "key": {
                "Secp256k1Schnorr": {
                    "pubkey_data": self.hex_to_dec_array(stake_public_key),
                },
            },
        }

    def vrf_private_key(self, vrf_private_key):
        return {
            "key": {
                "Schnorrkel": {
                    "key": self.hex_to_dec_array(vrf_private_key),
                },
            },
        }

    def vrf_public_key(self, vrf_public_key):
        return {
            "key": {
                "Schnorrkel": {
                    "key": self.hex_to_dec_array(vrf_public_key),
                },
            },
        }

    def run_test(self):
        asyncio.run(self.async_test())

    def setup_pool_and_transfer(self, transactions):
        block_input_data = block_input_data_obj.encode({
            "PoS": {
                "stake_private_key": self.stake_private_key(GENESIS_STAKE_PRIVATE_KEY),
                "vrf_private_key": self.vrf_private_key(GENESIS_VRF_PRIVATE_KEY),
                "pool_id": self.genesis_pool_id(),
                "kernel_inputs": [
                        {
                            "Utxo": {
                                "id": {
                                    "BlockReward": self.previous_block_id()
                                },
                                "index": 1,
                            },
                        },
                ],
                 "kernel_input_utxo": [
                    {
                        "CreateStakePool": [
                            self.genesis_pool_id(),
                            {
                                "value": 40_000*ATOMS_PER_COIN,
                                "staker": {
                                    "PublicKey": self.stake_public_key(GENESIS_STAKE_PUBLIC_KEY),
                                },
                                "vrf_public_key": self.vrf_public_key(GENESIS_VRF_PUBLIC_KEY),
                                "decommission_key": {
                                    "PublicKey": self.stake_public_key(GENESIS_STAKE_PUBLIC_KEY),
                                },
                                "margin_ratio_per_thousand": 1000,
                                "cost_per_block" : "0"
                            },
                        ],
                    }
                ],
            }
        }).to_hex()[2:]

        self.generate_block(1, block_input_data, transactions)

    def gen_pos_block(self, transactions, block_height, block_id=None):
        block_id = self.previous_block_id() if block_id is None else block_id
        block_input_data = block_input_data_obj.encode({
            "PoS": {
                "stake_private_key": self.stake_private_key(GENESIS_STAKE_PRIVATE_KEY),
                "vrf_private_key": self.vrf_private_key(GENESIS_VRF_PRIVATE_KEY),
                "pool_id": self.genesis_pool_id(),
                "kernel_inputs": [
                        {
                            "Utxo": {
                                "id": {
                                    "BlockReward": block_id
                                },
                                "index": 0,
                            },
                        },
                ],
                 "kernel_input_utxo": [
                    {
                        "ProduceBlockFromStake": [
                            {
                                "PublicKey": self.stake_public_key(GENESIS_STAKE_PUBLIC_KEY),
                            },
                            self.genesis_pool_id(),
                        ],
                    }
                ],
            }
        }).to_hex()[2:]

        self.generate_block(block_height, block_input_data, transactions)

    @abstractmethod
    async def async_test(self):
        raise NotImplementedError
