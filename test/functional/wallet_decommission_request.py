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
"""Wallet decommission request test

Check that:
* We can create a new wallet,
* create 2 accounts
* generate decommission keys from account1
* create a stake pool from account0 and provide decommission keys from account1
* create a decommission request from account0
* sign decommission request from account1 and submit a tx with it
* check that the pool was decommissioned
"""

from test_framework.authproxy import JSONRPCException
from test_framework.mintlayer import (
    block_input_data_obj,
    ATOMS_PER_COIN,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import (make_tx, reward_input)
from test_framework.util import assert_equal, assert_in
from test_framework.mintlayer import block_input_data_obj
from test_framework.wallet_cli_controller import WalletCliController

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

class WalletDecommissionRequest(BitcoinTestFramework):

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

    def assert_height(self, expected_height, expected_block):
        block_id = self.nodes[0].chainstate_block_id_at_height(expected_height)
        block = self.nodes[0].chainstate_get_block(block_id)
        assert_equal(block, expected_block)

    def assert_tip(self, expected_block):
        tip = self.nodes[0].chainstate_best_block_id()
        block = self.nodes[0].chainstate_get_block(tip)
        assert_equal(block, expected_block)

    def block_height(self, n):
        tip = self.nodes[n].chainstate_best_block_id()
        return self.nodes[n].chainstate_block_height_in_main_chain(tip)

    def generate_block(self, expected_height, block_input_data, transactions):
        fill_mode = 'LeaveEmptySpace'
        # Block production may fail if the Job Manager found a new tip, so try and sleep
        for _ in range(5):
            try:
                block_hex = self.nodes[0].blockprod_generate_block(block_input_data, transactions, [], fill_mode)
                break
            except JSONRPCException:
                block_hex = self.nodes[0].blockprod_generate_block(block_input_data, transactions, [], fill_mode)
                time.sleep(1)

        self.nodes[0].chainstate_submit_block(block_hex)

        self.assert_tip(block_hex)
        self.assert_height(expected_height, block_hex)

    def genesis_pool_id(self):
        return self.hex_to_dec_array(GENESIS_POOL_ID)

    def hex_to_dec_array(self, hex_string):
        return [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)]

    def previous_block_id(self):
        previous_block_id = self.nodes[0].chainstate_best_block_id()
        return self.hex_to_dec_array(previous_block_id)

    def private_key(self, stake_private_key):
        return {
            "key": {
                "Secp256k1Schnorr": {
                    "data": self.hex_to_dec_array(stake_private_key),
                },
            },
        }

    def public_key(self, stake_public_key):
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
                "stake_private_key": self.private_key(GENESIS_STAKE_PRIVATE_KEY),
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
                                    "PublicKey": self.public_key(GENESIS_STAKE_PUBLIC_KEY),
                                },
                                "vrf_public_key": self.vrf_public_key(GENESIS_VRF_PUBLIC_KEY),
                                "decommission_key": {
                                    "PublicKey": self.public_key(GENESIS_STAKE_PUBLIC_KEY),
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
                "stake_private_key": self.private_key(GENESIS_STAKE_PRIVATE_KEY),
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
                                "PublicKey": self.public_key(GENESIS_STAKE_PUBLIC_KEY),
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
        decommission_address = ""

        async with WalletCliController(node, self.config, self.log, wallet_args=["--cold-wallet"], chain_config_args=["--chain-pos-netupgrades", "true"]) as wallet:
            # new cold wallet
            await wallet.create_wallet("cold_wallet")

            decommission_address = await wallet.new_address()

        decommission_req = ""

        async with WalletCliController(node, self.config, self.log, chain_config_args=["--chain-pos-netupgrades", "true"]) as wallet:
            # new hot wallet
            await wallet.create_wallet("hot_wallet")

            # check it is on genesis
            best_block_height = await wallet.get_best_block_height()
            self.log.info(f"best block height = {best_block_height}")
            assert_equal(best_block_height, '0')

            # new address
            pub_key_bytes = await wallet.new_public_key()
            assert_equal(len(pub_key_bytes), 33)

            # Get chain tip
            tip_id = node.chainstate_best_block_id()
            self.log.debug(f'Tip: {tip_id}')

            # Submit a valid transaction
            output = {
                    'Transfer': [ { 'Coin': 50_000 * ATOMS_PER_COIN }, { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': pub_key_bytes}}} } ],
            }
            encoded_tx, tx_id = make_tx([reward_input(tip_id)], [output], 0)
            self.log.debug(f"Encoded transaction {tx_id}: {encoded_tx}")


            self.setup_pool_and_transfer([encoded_tx])

            # sync the wallet
            assert_in("Success", await wallet.sync())

            # check wallet best block if it is synced
            best_block_height = await wallet.get_best_block_height()
            assert_in(best_block_height, '1')

            balance = await wallet.get_balance()
            assert_in("Coins amount: 50000", balance)

            assert_in("The transaction was submitted successfully", await wallet.create_stake_pool(40000, 0, 0.5, decommission_address))
            transactions = node.mempool_transactions()

            self.gen_pos_block(transactions, 2)
            assert_in("Success", await wallet.sync())

            pools = await wallet.list_pool_ids()
            assert_equal(len(pools), 1)
            assert_equal(pools[0].pledge, '40000')
            assert_equal(pools[0].balance, '40000')
            tip_id_with_genesis_pool = node.chainstate_best_block_id()

            if self.use_wallet_to_produce_block:
                # produce block with the wallet so that utxo of a pool changes from CreateStakePool to ProduceBlockWithStakePool
                assert_in("Staking started successfully", await wallet.start_staking())
                self.wait_until(lambda: node.chainstate_best_block_id() != tip_id_with_genesis_pool, timeout = 15)
                assert_in("Success", await wallet.stop_staking())

            # try decommission from hot wallet
            address = await wallet.new_address()
            assert (await wallet.decommission_stake_pool(pools[0].pool_id, address)).startswith("Wallet error: Wallet error: Failed to completely sign")

            # create decommission request
            decommission_req_output = await wallet.decommission_stake_pool_request(pools[0].pool_id, address)
            decommission_req = decommission_req_output.split('\n')[2]

            # try to sign decommission request from hot wallet
            assert_in("Wallet error: Wallet error: Input cannot be signed",
                       await wallet.sign_raw_transaction(decommission_req))

        decommission_signed_tx = ""

        async with WalletCliController(node, self.config, self.log, wallet_args=["--cold-wallet"], chain_config_args=["--chain-pos-netupgrades", "true"]) as wallet:
            # open cold wallet
            await wallet.open_wallet("cold_wallet")

            # sign decommission request
            decommission_signed_tx_output = await wallet.sign_raw_transaction(decommission_req)
            decommission_signed_tx = decommission_signed_tx_output.split('\n')[2]

        async with WalletCliController(node, self.config, self.log, chain_config_args=["--chain-pos-netupgrades", "true"]) as wallet:
            # open hot wallet
            await wallet.open_wallet("hot_wallet")

            assert_in("The transaction was submitted successfully", await wallet.submit_transaction(decommission_signed_tx))

            transactions = node.mempool_transactions()
            assert_in(decommission_signed_tx, transactions)

            tip_height = await wallet.get_best_block_height()
            self.gen_pos_block(transactions, int(tip_height) + 1, self.hex_to_dec_array(tip_id_with_genesis_pool))
            assert_in("Success", await wallet.sync())

            pools = await wallet.list_pool_ids()
            assert_equal(len(pools), 0)

            # check the locked balance is equal to the genesis pool balance
            locked_utxos = await wallet.list_utxos('all', with_locked='locked')
            assert_equal(len(locked_utxos), 1)

# `use_wallet_to_produce_block` indicates whether a test should use a pool created by a wallet to produce block
# `exit_on_success` indicates if the process should exit or continue and run next test case
def wallet_decommission_request_test_case(use_wallet_to_produce_block, exit_on_success):
    tf = WalletDecommissionRequest()
    tf.use_wallet_to_produce_block = use_wallet_to_produce_block
    tf.main(exit_on_success)

if __name__ == '__main__':
    wallet_decommission_request_test_case(False, False)
    wallet_decommission_request_test_case(True, True)
