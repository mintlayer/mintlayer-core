#!/usr/bin/env python3
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

from scalecodec.base import ScaleBytes, ScaleDecoder
from test_framework.authproxy import JSONRPCException
from test_framework.mintlayer import (
    base_tx_obj,
    block_input_data_obj,
    mintlayer_hash,
    make_delegation_id,
    make_pool_id,
    hex_to_dec_array,
    ATOMS_PER_COIN,
    outpoint_obj,
    signed_tx_obj,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)

import random
import time

GENESIS_POOL_ID = "123c4c600097c513e088b9be62069f0c74c7671c523c8e3469a1c3f14b7ea2c4"
GENESIS_STAKE_PRIVATE_KEY = "8717e6946febd3a33ccdc3f3a27629ec80c33461c33a0fc56b4836fcedd26638"
GENESIS_STAKE_PUBLIC_KEY = "03c53526caf73cd990148e127cb57249a5e266d78df23968642c976a532197fdaa"
GENESIS_VRF_PUBLIC_KEY = "fa2f59dc7a7e176058e4f2d155cfa03ee007340e0285447892158823d332f744"

GENESIS_VRF_PRIVATE_KEY = (
    "3fcf7b813bec2a293f574b842988895278b396dd72471de2583b242097a59f06"
    "e9f3cd7b78d45750afd17292031373fddb5e7a8090db51221038f5e05f29998e"
)


# Test that PoS consensus version V1 incentivizes pool with more pledge.
# Create 2 pools with same balance but different pledge ration: first pool 1:5 pledge to delegation, second pool 1:1.
# Chain has a netupgrade from V0 to V1 at height 100. Generate first 100 block and check that both pools
# has the same balance (+-1???). After netupgrade generate another 100 block and check that
# second pool received more rewards than the first one.
class StakingIncentivesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            "--chain-pos-netupgrades-v0-to-v1=200",
            "--chain-initial-difficulty=419627008",
            "--blockprod-min-peers-to-produce-blocks=0",
        ]]

    def assert_chain(self, block, previous_tip):
        assert_equal(block["header"]["header"]
                     ["prev_block_id"][2:], previous_tip)

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

    def generate_block(self, node_index, block_input_data, transactions):
        # Block production may fail if the Job Manager found a new tip, so try and sleep
        for _ in range(5):
            try:
                block_hex = self.nodes[node_index].blockprod_generate_block(
                    block_input_data, transactions)
                break
            except JSONRPCException:
                block_hex = self.nodes[node_index].blockprod_generate_block(
                    block_input_data, transactions)
                time.sleep(1)
        return block_hex

    def submit_block(self, node_index, block_hex):
        previous_block_id = self.nodes[node_index].chainstate_best_block_id()

        block_hex_array = bytearray.fromhex(block_hex)
        block = ScaleDecoder.get_decoder_class(
            'BlockV1', ScaleBytes(block_hex_array)).decode()

        self.nodes[node_index].chainstate_submit_block(block_hex)

        self.assert_tip(block_hex)
        self.assert_pos_consensus(block)
        self.assert_chain(block, previous_block_id)

    def extract_timestamp_from_block(self, block_hex):
        block_hex_array = bytearray.fromhex(block_hex)
        block = ScaleDecoder.get_decoder_class(
            'BlockV1', ScaleBytes(block_hex_array)).decode()
        return block["header"]["header"]["timestamp"]

    def generate_and_submit_block(self, node_index, block_input_data, transactions):
        block_hex = self.generate_block(
            node_index, block_input_data, transactions)
        self.submit_block(node_index, block_hex)

    def genesis_pool_id(self):
        return hex_to_dec_array(GENESIS_POOL_ID)

    def new_stake_keys(self):
        new_stake_private_key_hex = self.nodes[0].test_functions_new_private_key(
        )
        new_stake_private_key = self.stake_private_key(
            new_stake_private_key_hex[2:])

        new_stake_public_key_hex = self.nodes[0].test_functions_public_key_from_private_key(
            new_stake_private_key_hex)
        new_stake_public_key = self.stake_public_key(
            new_stake_public_key_hex[2:])

        return (new_stake_private_key, new_stake_public_key)

    def new_vrf_keys(self):
        new_vrf_private_key_hex = self.nodes[0].test_functions_new_vrf_private_key(
        )
        new_vrf_private_key = self.vrf_private_key(new_vrf_private_key_hex[2:])

        new_vrf_public_key_hex = self.nodes[0].test_functions_vrf_public_key_from_private_key(
            new_vrf_private_key_hex)
        new_vrf_public_key = self.vrf_public_key(new_vrf_public_key_hex[2:])

        return (new_vrf_private_key, new_vrf_public_key)

    def pack_transaction(self, transaction):
        transaction_encoded = signed_tx_obj.encode(transaction).to_hex()[2:]
        transaction_id = ScaleBytes(
            mintlayer_hash(base_tx_obj.encode(transaction["transaction"]).data)
        ).to_hex()[2:]

        return (transaction_encoded, transaction_id)

    def previous_block_id(self):
        previous_block_id = self.nodes[0].chainstate_best_block_id()
        return hex_to_dec_array(previous_block_id)

    def stake_private_key(self, stake_private_key):
        return {
            "key": {
                "Secp256k1Schnorr": {
                    "data": hex_to_dec_array(stake_private_key),
                },
            },
        }

    def stake_public_key(self, stake_public_key):
        return {
            "key": {
                "Secp256k1Schnorr": {
                    "pubkey_data": hex_to_dec_array(stake_public_key),
                },
            },
        }

    def vrf_private_key(self, vrf_private_key):
        return {
            "key": {
                "Schnorrkel": {
                    "key": hex_to_dec_array(vrf_private_key),
                },
            },
        }

    def vrf_public_key(self, vrf_public_key):
        return {
            "key": {
                "Schnorrkel": {
                    "key": hex_to_dec_array(vrf_public_key),
                },
            },
        }

    def generate_n_blocks(self, n, pool_1_last_block, pool_id_1, stake_pk_1, stake_sk_1, vrf_sk_1, pool_2_last_block, pool_id_2, stake_pk_2, stake_sk_2, vrf_sk_2):
        for i in range(0, n):
            # generate 2 blocks using both pools then choose the one with the lowest timestamp and submit it
            block_pool1_hex = self.generate_block_from(
                pool_1_last_block, pool_id_1, stake_pk_1, stake_sk_1, vrf_sk_1)
            block_pool2_hex = self.generate_block_from(
                pool_2_last_block, pool_id_2, stake_pk_2, stake_sk_2, vrf_sk_2)

            block_pool1_timestamp = self.extract_timestamp_from_block(
                block_pool1_hex)
            block_pool2_timestamp = self.extract_timestamp_from_block(
                block_pool2_hex)

            if block_pool1_timestamp < block_pool2_timestamp:
                self.submit_block(0, block_pool1_hex)
                pool_1_last_block = self.nodes[0].chainstate_best_block_id()
            elif block_pool1_timestamp > block_pool2_timestamp:
                self.submit_block(0, block_pool2_hex)
                pool_2_last_block = self.nodes[0].chainstate_best_block_id()
            else:
                # in case timestamps are equal, randomly choose a pool
                if random.getrandbits(1) == 0:
                    self.submit_block(0, block_pool1_hex)
                    pool_1_last_block = self.nodes[0].chainstate_best_block_id()
                else:
                    self.submit_block(0, block_pool2_hex)
                    pool_2_last_block = self.nodes[0].chainstate_best_block_id()
        return pool_1_last_block, pool_2_last_block

    def create_pool_tx(self, input_outpoint, stake_pk, vrf_pk, pledge_amount, margin, transfer_change_amount):
        input_outpoint_encoded = outpoint_obj.encode(
            input_outpoint).to_hex()[2:]
        pool_id = make_pool_id(input_outpoint_encoded)
        create_pool_tx = {
            "transaction": {
                "version": 1,
                "flags": 0,
                "inputs": [
                    {
                        "Utxo": input_outpoint,
                    }
                ],
                "outputs": [
                    {
                        "CreateStakePool": [
                            pool_id,
                            {
                                "value": pledge_amount,
                                "staker": {
                                    "PublicKey": stake_pk,
                                },
                                "vrf_public_key": vrf_pk,
                                "decommission_key": "AnyoneCanSpend",
                                "margin_ratio_per_thousand": margin,
                                "cost_per_block": "0"
                            },
                        ],
                    },
                    {
                        "Transfer": [
                            {
                                "Coin": transfer_change_amount,
                            },
                            "AnyoneCanSpend",
                        ],
                    }
                ],
            },
            "signatures": [
                {
                    "NoSignature": None,
                },
            ],
        }
        (create_pool_tx_encoded, create_pool_tx_id) = self.pack_transaction(
            create_pool_tx)
        return (pool_id, create_pool_tx_encoded, create_pool_tx_id)

    def create_delegation_id_tx(self, prev_tx_outpoint, pool_id, transfer_change_amount):
        prev_tx_outpoint_encoded = outpoint_obj.encode(
            prev_tx_outpoint).to_hex()[2:]
        delegation_id = make_delegation_id(prev_tx_outpoint_encoded)

        create_delegation_tx = {
            "transaction": {
                "version": 1,
                "flags": 0,
                "inputs": [
                    {
                        "Utxo": prev_tx_outpoint,
                    }
                ],
                "outputs": [
                    {
                        "CreateDelegationId": [
                            "AnyoneCanSpend",
                            pool_id,
                        ],
                    },
                    {
                        "Transfer": [
                            {
                                "Coin": transfer_change_amount,
                            },
                            "AnyoneCanSpend",
                        ],
                    }
                ],
            },
            "signatures": [
                {
                    "NoSignature": None,
                },
            ],
        }
        (create_delegation_tx_encoded, create_delegation_tx_id) = self.pack_transaction(
            create_delegation_tx)
        return (delegation_id, create_delegation_tx_encoded, create_delegation_tx_id)

    def create_delegate_staking_tx(self, input_outpoint, delegation_id, delegation_amount, transfer_change_amount):
        delegate_staking_tx = {
            "transaction": {
                "version": 1,
                "flags": 0,
                "inputs": [
                    {
                        "Utxo": input_outpoint,
                    }
                ],
                "outputs": [
                    {
                        "DelegateStaking": [
                            delegation_amount,
                            delegation_id,
                        ],
                    },
                    {
                        "Transfer": [
                            {
                                "Coin": transfer_change_amount,
                            },
                            "AnyoneCanSpend",
                        ],
                    }
                ],
            },
            "signatures": [
                {
                    "NoSignature": None,
                },
            ],
        }
        (delegate_staking_tx_encoded, delegate_staking_tx_id) = self.pack_transaction(
            delegate_staking_tx)
        return (delegate_staking_tx_encoded, delegate_staking_tx_id)

    def generate_block_from(self, block_id, pool_id, stake_pk, stake_sk, vrf_sk):
        kernel_input_outpoint = {
            "id": {
                "BlockReward": hex_to_dec_array(block_id),
            },
            "index": 0,
        }

        kernel_input_utxo = {
            "ProduceBlockFromStake": [
                {
                    "PublicKey": stake_pk,
                },
                pool_id,
            ],
        }

        block_input_data = block_input_data_obj.encode({
            "PoS": {
                "stake_private_key": stake_sk,
                "vrf_private_key": vrf_sk,
                "pool_id": pool_id,
                "kernel_inputs": [
                    {
                        "Utxo": kernel_input_outpoint,
                    },
                ],
                "kernel_input_utxo": [kernel_input_utxo]
            }
        }).to_hex()[2:]

        return self.generate_block(0, block_input_data, [])

    def run_test(self):
        #
        # Create a block with the first pool and delegation
        #

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
                                "cost_per_block": "0"
                            },
                        ],
                    }
                ],
            }
        }).to_hex()[2:]

        (stake_sk_1, stake_pk_1) = self.new_stake_keys()
        (vrf_sk_1, vrf_pk_1) = self.new_vrf_keys()
        pool_1_pledge = 40_000*ATOMS_PER_COIN

        genesis_kernel0_outpoint = {
            "id": {
                "BlockReward": self.previous_block_id(),
            },
            "index": 0,
        }
        (pool_id_1, tx1_encoded, tx1_id) = self.create_pool_tx(
            genesis_kernel0_outpoint, stake_pk_1, vrf_pk_1, pool_1_pledge, 1000, 400_000*ATOMS_PER_COIN)

        tx1_outpoint = {
            "id": {
                "Transaction": hex_to_dec_array(tx1_id),
            },
            "index": 1,
        }
        (delegation_id_1, tx2_encoded, tx2_id) = self.create_delegation_id_tx(
            tx1_outpoint, pool_id_1, 400_000*ATOMS_PER_COIN)

        tx2_outpoint = {
            "id": {
                "Transaction": hex_to_dec_array(tx2_id),
            },
            "index": 1,
        }
        (tx3_encoded, tx3_id) = self.create_delegate_staking_tx(
            tx2_outpoint, delegation_id_1, 160_000*ATOMS_PER_COIN, 200_000*ATOMS_PER_COIN)

        self.generate_and_submit_block(0, block_input_data, [
            tx1_encoded, tx2_encoded, tx3_encoded])

        #
        # Create a block with second pool and delegation
        #

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

        (stake_sk_2, stake_pk_2) = self.new_stake_keys()
        (vrf_sk_2, vrf_pk_2) = self.new_vrf_keys()
        pool_2_pledge = 150_000*ATOMS_PER_COIN

        tx3_outpoint = {
            "id": {
                "Transaction": hex_to_dec_array(tx3_id),
            },
            "index": 1,
        }

        (pool_id_2, tx4_encoded, tx4_id) = self.create_pool_tx(
            tx3_outpoint, stake_pk_2, vrf_pk_2, pool_2_pledge, 1000, 50_000*ATOMS_PER_COIN)

        tx4_outpoint = {
            "id": {
                "Transaction": hex_to_dec_array(tx4_id),
            },
            "index": 1,
        }
        (delegation_id_2, tx5_encoded, tx5_id) = self.create_delegation_id_tx(
            tx4_outpoint, pool_id_2, 50_000*ATOMS_PER_COIN)

        tx5_outpoint = {
            "id": {
                "Transaction": hex_to_dec_array(tx5_id),
            },
            "index": 1,
        }
        (tx6_encoded, tx6_id) = self.create_delegate_staking_tx(
            tx5_outpoint, delegation_id_2, 50_000*ATOMS_PER_COIN, 0)

        self.generate_and_submit_block(0, block_input_data, [
            tx4_encoded, tx5_encoded, tx6_encoded])

        pool_id_1_hex = ScaleBytes(bytes(pool_id_1)).to_hex()[2:]
        pool_1_balance_initial = self.nodes[0].chainstate_stake_pool_balance(
            pool_id_1_hex)['atoms']
        self.log.debug("Pool 1 original balance {}".format(pool_1_balance_initial))

        pool_id_2_hex = ScaleBytes(bytes(pool_id_2)).to_hex()[2:]
        pool_2_balance_initial = self.nodes[0].chainstate_stake_pool_balance(
            pool_id_2_hex)['atoms']
        self.log.debug("Pool 2 original balance {}".format(pool_2_balance_initial))

        assert_equal(pool_1_balance_initial, pool_2_balance_initial)

        #
        # Generate 2 block just to get rid of CreateStakePool output
        #

        block_input_data = block_input_data_obj.encode({
            "PoS": {
                "stake_private_key": stake_sk_1,
                "vrf_private_key": vrf_sk_1,
                "pool_id": pool_id_1,
                "kernel_inputs": [
                    {
                        "Utxo": {
                            "id": {
                                "Transaction": hex_to_dec_array(tx1_id),
                            },
                            "index": 0,
                        },
                    },
                ],
                "kernel_input_utxo": [
                    {
                        "CreateStakePool": [
                            pool_id_1,
                            {
                                "value": pool_1_pledge,
                                "staker": {
                                    "PublicKey": stake_pk_1,
                                },
                                "vrf_public_key": vrf_pk_1,
                                "decommission_key": "AnyoneCanSpend",
                                "margin_ratio_per_thousand": 1000,
                                "cost_per_block": "0"
                            },
                        ],
                    }
                ],
            }
        }).to_hex()[2:]
        self.generate_and_submit_block(0, block_input_data, [])
        pool_1_last_block = self.nodes[0].chainstate_best_block_id()

        block_input_data = block_input_data_obj.encode({
            "PoS": {
                "stake_private_key": stake_sk_2,
                "vrf_private_key": vrf_sk_2,
                "pool_id": pool_id_2,
                "kernel_inputs": [
                    {
                        "Utxo": {
                            "id": {
                                "Transaction": hex_to_dec_array(tx4_id),
                            },
                            "index": 0,
                        },
                    },
                ],
                "kernel_input_utxo": [
                    {
                        "CreateStakePool": [
                            pool_id_2,
                            {
                                "value": pool_2_pledge,
                                "staker": {
                                    "PublicKey": stake_pk_2,
                                },
                                "vrf_public_key": vrf_pk_2,
                                "decommission_key": "AnyoneCanSpend",
                                "margin_ratio_per_thousand": 1000,
                                "cost_per_block": "0"
                            },
                        ],
                    }
                ],
            }
        }).to_hex()[2:]
        self.generate_and_submit_block(0, block_input_data, [])
        pool_2_last_block = self.nodes[0].chainstate_best_block_id()

        # Generate blocks until netupgrade to V1
        pool_1_last_block, pool_2_last_block = self.generate_n_blocks(
            195, pool_1_last_block, pool_id_1, stake_pk_1, stake_sk_1, vrf_sk_1, pool_2_last_block, pool_id_2, stake_pk_2, stake_sk_2, vrf_sk_2)

        pool_1_reward = self.nodes[0].chainstate_stake_pool_balance(
            pool_id_1_hex)['atoms'] - pool_1_balance_initial
        self.log.debug("Pool 1 reward {}".format(pool_1_reward))
        pool_2_reward = self.nodes[0].chainstate_stake_pool_balance(
            pool_id_2_hex)['atoms'] - pool_2_balance_initial
        self.log.debug("Pool 2 reward {}".format(pool_2_reward))
        pools_reward_ratio_v0 = pool_1_reward / pool_2_reward
        self.log.debug(
            "At height 200: pool1 reward / pool2 reward = {}".format(pools_reward_ratio_v0))

        # generate 200 more blocks with V1
        self.generate_n_blocks(200, pool_1_last_block, pool_id_1, stake_pk_1, stake_sk_1,
                               vrf_sk_1, pool_2_last_block, pool_id_2, stake_pk_2, stake_sk_2, vrf_sk_2)

        pool_1_reward = self.nodes[0].chainstate_stake_pool_balance(
            pool_id_1_hex)['atoms'] - pool_1_balance_initial - pool_1_reward
        self.log.debug("Pool 1 reward {}".format(pool_1_reward))
        pool_2_reward = self.nodes[0].chainstate_stake_pool_balance(
            pool_id_2_hex)['atoms'] - pool_2_balance_initial - pool_2_reward
        pools_reward_ratio_v1 = pool_1_reward / pool_2_reward
        self.log.debug("Pool 2 reward {}".format(pool_2_reward))
        self.log.debug(
            "At height 400: pool1 reward / pool2 reward = {}".format(pools_reward_ratio_v1))

        assert (pool_1_reward < pool_2_reward)
        assert (pools_reward_ratio_v0 > pools_reward_ratio_v1)


if __name__ == '__main__':
    StakingIncentivesTest().main()
