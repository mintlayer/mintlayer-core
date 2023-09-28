#!/usr/bin/env python3
#  Copyright (c) 2023 RBB S.r.l
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
"""Wallet delegations test

Check that:
* We can create a new wallet,
* get an address
* send coins to the wallet's address
* sync the wallet with the node
* check balance
* create a stake pool
* in another account create a delegation to that pool
* stake to that delegation
* transfer from that delegation
* get reward to that delegation
"""

from hashlib import blake2b
from test_framework.authproxy import JSONRPCException
from test_framework.mintlayer import (
    base_tx_obj,
    block_input_data_obj,
    mintlayer_hash,
    MLT_COIN,
    outpoint_obj,
    signed_tx_obj,
)
from scalecodec.base import ScaleBytes, RuntimeConfiguration, ScaleDecoder
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import (make_tx, reward_input, tx_input)
from test_framework.util import assert_raises_rpc_error
from test_framework.mintlayer import mintlayer_hash, block_input_data_obj
from test_framework.wallet_cli_controller import DEFAULT_ACCOUNT_INDEX, WalletCliController
from test_framework.util import (
    assert_equal,
)

import asyncio
import sys
import random, time

GENESIS_POOL_ID = "123c4c600097c513e088b9be62069f0c74c7671c523c8e3469a1c3f14b7ea2c4"
GENESIS_STAKE_PRIVATE_KEY = "8717e6946febd3a33ccdc3f3a27629ec80c33461c33a0fc56b4836fcedd26638"
GENESIS_STAKE_PUBLIC_KEY = "03c53526caf73cd990148e127cb57249a5e266d78df23968642c976a532197fdaa"
GENESIS_VRF_PUBLIC_KEY = "fa2f59dc7a7e176058e4f2d155cfa03ee007340e0285447892158823d332f744"

GENESIS_VRF_PRIVATE_KEY = (
    "3fcf7b813bec2a293f574b842988895278b396dd72471de2583b242097a59f06"
    "e9f3cd7b78d45750afd17292031373fddb5e7a8090db51221038f5e05f29998e"
)

GENESIS_POOL_ID_ADDR = "rpool1zg7yccqqjlz38cyghxlxyp5lp36vwecu2g7gudrf58plzjm75tzq99fr6v"

class WalletSubmitTransaction(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            "--chain-pos-netupgrades=true",
            "--blockprod-min-peers-to-produce-blocks=0",
        ]]

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

    def block_height(self, n):
        tip = self.nodes[n].chainstate_best_block_id()
        return self.nodes[n].chainstate_block_height_in_main_chain(tip)
    def generate_block(self, expected_height, block_input_data, transactions):
        previous_block_id = self.nodes[0].chainstate_best_block_id()

        # Block production may fail if the Job Manager found a new tip, so try and sleep
        for _ in range(5):
            try:
                block_hex = self.nodes[0].blockprod_generate_block(block_input_data, transactions)
                break
            except JSONRPCException:
                block_hex = self.nodes[0].blockprod_generate_block(block_input_data, transactions)
                time.sleep(1)

        block_hex_array = bytearray.fromhex(block_hex)
        # block = ScaleDecoder.get_decoder_class('BlockV1', ScaleBytes(block_hex_array)).decode()

        self.nodes[0].chainstate_submit_block(block_hex)

        self.assert_tip(block_hex)
        self.assert_height(expected_height, block_hex)
        # self.assert_pos_consensus(block)
        # self.assert_chain(block, previous_block_id)

    def generate_pool_id(self, transaction_id):
        kernel_input_outpoint = outpoint_obj.encode({
            "id": {
                "Transaction": self.hex_to_dec_array(transaction_id),
            },
            "index": 0,
        }).to_hex()[2:]

        # Include PoolId pre-image suffix of [0, 0, 0, 0]
        blake2b_hasher = blake2b()
        blake2b_hasher.update(bytes.fromhex(kernel_input_outpoint))
        blake2b_hasher.update(bytes.fromhex("00000000"))

        # Truncate output to match Rust's split()
        return self.hex_to_dec_array(blake2b_hasher.hexdigest()[:64])

    def genesis_pool_id(self):
        return self.hex_to_dec_array(GENESIS_POOL_ID)

    def hex_to_dec_array(self, hex_string):
        return [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)]

    def new_stake_keys(self):
        new_stake_private_key_hex = self.nodes[0].test_functions_new_private_key()
        new_stake_private_key = self.stake_private_key(new_stake_private_key_hex[2:])

        new_stake_public_key_hex = self.nodes[0].test_functions_public_key_from_private_key(new_stake_private_key_hex)
        new_stake_public_key = self.stake_public_key(new_stake_public_key_hex[2:])

        return (new_stake_private_key, new_stake_public_key)

    def new_vrf_keys(self):
        new_vrf_private_key_hex = self.nodes[0].test_functions_new_vrf_private_key()
        new_vrf_private_key = self.vrf_private_key(new_vrf_private_key_hex[2:])

        new_vrf_public_key_hex = self.nodes[0].test_functions_vrf_public_key_from_private_key(new_vrf_private_key_hex)
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
        if 'win32' in sys.platform:
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
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
                                "value": 40_000*MLT_COIN,
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

    def gen_pos_block(self, transactions, block_height):
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

        self.generate_block(block_height, block_input_data, transactions)

    async def async_test(self):
        node = self.nodes[0]
        async with WalletCliController(node, self.config, self.log) as wallet:
            # new wallet
            await wallet.create_wallet()

            # check it is on genesis
            best_block_height = await wallet.get_best_block_height()
            self.log.info(f"best block height = {best_block_height}")
            assert best_block_height == '0'

            # new address
            pub_key_bytes = await wallet.new_public_key()
            assert len(pub_key_bytes) == 33

            # Get chain tip
            tip_id = node.chainstate_best_block_id()
            self.log.debug(f'Tip: {tip_id}')

            # Submit a valid transaction
            output = {
                    'Transfer': [ { 'Coin': 50_000 * MLT_COIN }, { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': pub_key_bytes}}} } ],
            }
            encoded_tx, tx_id = make_tx([reward_input(tip_id)], [output], 0)
            self.log.debug(f"Encoded transaction {tx_id}: {encoded_tx}")

            self.setup_pool_and_transfer([encoded_tx])

            # sync the wallet
            assert "Success" in await wallet.sync()

            # check wallet best block if it is synced
            best_block_height = await wallet.get_best_block_height()
            assert best_block_height == '1'

            balance = await wallet.get_balance()
            assert "Coins amount: 50000" in balance

            assert "Success" in await wallet.create_new_account()
            assert "Success" in await wallet.select_account(1)
            acc1_address = await wallet.new_address()
            assert "Success" in await wallet.select_account(DEFAULT_ACCOUNT_INDEX)
            assert "The transaction was submitted successfully" in await wallet.send_to_address(acc1_address, 100)
            assert "Success" in await wallet.select_account(1)
            transactions = node.mempool_transactions()

            assert "Success" in await wallet.select_account(DEFAULT_ACCOUNT_INDEX)
            assert "The transaction was submitted successfully" in await wallet.create_stake_pool(40000, 0, 0.5)
            transactions2 = node.mempool_transactions()
            for tx in transactions2:
                if tx not in transactions:
                    transactions.append(tx)

            self.gen_pos_block(transactions, 2)
            assert "Success" in await wallet.sync()

            pools = await wallet.list_pool_ids()
            assert len(pools) == 1
            assert pools[0].balance == 40000

            assert "Success" in await wallet.select_account(1)
            delegation_id = await wallet.create_delegation(acc1_address, pools[0].pool_id)
            assert delegation_id is not None
            transactions = node.mempool_transactions()

            # still not in a block
            delegations = await wallet.list_delegation_ids()
            assert len(delegations) == 0

            assert "Success" in await wallet.stake_delegation(10, delegation_id)
            transactions2 = node.mempool_transactions()
            for tx in transactions2:
                if tx not in transactions:
                    transactions.append(tx)

            self.gen_pos_block(transactions, 3)
            assert "Success" in await wallet.sync()

            delegations = await wallet.list_delegation_ids()
            assert len(delegations) == 1
            assert delegations[0].balance == 10

            assert "Success" in await wallet.select_account(DEFAULT_ACCOUNT_INDEX)
            assert "Staking started successfully" in await wallet.start_staking()
            assert "Success" in await wallet.select_account(1)

            last_delegation_balance = delegations[0].balance
            for _ in range(4, 10):
                tip_id = node.chainstate_best_block_id()
                assert "The transaction was submitted successfully" in await wallet.send_to_address(acc1_address, 1)
                transactions = node.mempool_transactions()
                self.wait_until(lambda: node.chainstate_best_block_id() != tip_id, timeout = 5)

                delegations = await wallet.list_delegation_ids()
                assert len(delegations) == 1
                assert delegations[0].balance > last_delegation_balance
                last_delegation_balance = delegations[0].balance

            # stake to acc1 delegation from acc 0
            assert "Success" in await wallet.select_account(DEFAULT_ACCOUNT_INDEX)
            assert "Success" in await wallet.stake_delegation(10, delegation_id)
            self.wait_until(lambda: node.chainstate_best_block_id() != tip_id, timeout = 5)

            # check that we still don't have any delagations for this account
            delegations = await wallet.list_delegation_ids()
            assert len(delegations) == 0

            # create a delegation from acc 0 but with destination address for acc1
            delegation_id = await wallet.create_delegation(acc1_address, pools[0].pool_id)
            tip_id = node.chainstate_best_block_id()
            self.wait_until(lambda: node.chainstate_best_block_id() != tip_id, timeout = 5)

            # check that we still don't have any delagations for this account
            delegations = await wallet.list_delegation_ids()
            assert len(delegations) == 0

            assert "Success" in await wallet.select_account(1)
            delegations = await wallet.list_delegation_ids()
            assert len(delegations) == 2
            assert delegation_id in [delegation.delegation_id for delegation in delegations]


if __name__ == '__main__':
    WalletSubmitTransaction().main()


