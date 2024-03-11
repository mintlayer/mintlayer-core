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
from test_framework.wallet_cli_controller import DEFAULT_ACCOUNT_INDEX, WalletCliController

import asyncio
import sys
import time

GENESIS_POOL_ID = "123c4c600097c513e088b9be62069f0c74c7671c523c8e3469a1c3f14b7ea2c4"
MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

GENESIS_STAKE_PRIVATE_KEY = "e01fea8a48e2854fdd0255c12b1d704967d9401f11c3f4980006ced8977574dc"
GENESIS_STAKE_PUBLIC_KEY = "02a7451395735369f2ecdfc829c0f774e88ef1303dfe5b2f04dbaab30a535dfdd6"

GENESIS_VRF_PUBLIC_KEY = "f28e55872d378bf78b49ebcaea70494d9faa8ff763eb43a98c17be3ab5247756"
GENESIS_VRF_PRIVATE_KEY = (
    "200f4d1c52d17b4947733d774619a244e8dc599c55f03708d78a995d936c5b06"
    "b3d0ce97cae603ac54e7bc9254ef55d19f1218e37e361d729e0b5e4a856397e7"
)


class WalletDecommissionGenesis(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

        genesis_settings = ",".join([
            "pool_id:{}",
            "stake_private_key:00{}",
            "vrf_private_key:00{}",
        ]).format(
            GENESIS_POOL_ID,
            GENESIS_STAKE_PRIVATE_KEY,
            GENESIS_VRF_PRIVATE_KEY,
        )
        self.wallet_extra_args = [
            "--chain-pos-netupgrades", "true",
            "--chain-genesis-staking-settings", "{}".format(genesis_settings),
                ]

        self.extra_args = [[
            "--chain-pos-netupgrades=true",
            "--blockprod-min-peers-to-produce-blocks=0",
            "--chain-genesis-staking-settings={}".format(genesis_settings),
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

        async with WalletCliController(node, self.config, self.log, chain_config_args=self.wallet_extra_args) as wallet:
            # new hot wallet
            await wallet.create_wallet("wallet", MNEMONIC)

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

            pools = await wallet.list_pool_ids()
            assert_equal(len(pools), 1)
            genesis_pool_id = pools[0].pool_id

            # create a new stake pool in the other account
            assert_in("Success", await wallet.create_new_account())
            assert_in("Success", await wallet.select_account(1))
            acc1_address = await wallet.new_address()
            assert_in("Success", await wallet.select_account(DEFAULT_ACCOUNT_INDEX))
            assert_in("The transaction was submitted successfully", await wallet.send_to_address(acc1_address, 45000))

            transactions = node.mempool_transactions()
            self.gen_pos_block(transactions, 2)

            # check wallet best block if it is synced
            best_block_height = await wallet.get_best_block_height()
            assert_in(best_block_height, '2')

            assert_in("Success", await wallet.select_account(1))
            decommission_address = await wallet.new_address()
            assert_in("The transaction was submitted successfully", await wallet.create_stake_pool(40000, 0, 0.5, decommission_address))


            assert_in("Success", await wallet.select_account(DEFAULT_ACCOUNT_INDEX))
            assert_in("Staking started successfully", await wallet.start_staking())
            tip_id_with_genesis_pool = node.chainstate_best_block_id()
            self.wait_until(lambda: node.chainstate_best_block_id() != tip_id_with_genesis_pool, timeout = 15)
            assert_in("Success", await wallet.stop_staking())


            self.log.info("all good");
            assert_in("Success", await wallet.sync())

            assert_in("Success", await wallet.select_account(1))
            pools = await wallet.list_pool_ids()
            self.log.info(f"parsed pools: {pools}")
            assert_equal(len(pools), 1)
            assert_equal(pools[0].pledge, '40000')
            assert_equal(pools[0].balance, '40000')
            tip_id_with_genesis_pool = node.chainstate_best_block_id()

            # produce block with the wallet so that utxo of a pool changes from CreateStakePool to ProduceBlockWithStakePool
            assert_in("Success", await wallet.select_account(DEFAULT_ACCOUNT_INDEX))
            assert_in("Staking started successfully", await wallet.start_staking())
            self.wait_until(lambda: node.chainstate_best_block_id() != tip_id_with_genesis_pool, timeout = 15)
            assert_in("Success", await wallet.stop_staking())

            pools = await wallet.list_pool_ids()
            assert_equal(len(pools), 1)
            genesis_pool_balance = pools[0].balance
            # decommission from hot wallet
            address = await wallet.new_address()
            assert_in("The transaction was submitted successfully", await wallet.decommission_stake_pool(genesis_pool_id, address))
            transactions = node.mempool_transactions()
            assert_equal(len(transactions), 1)

            assert_in("Success", await wallet.select_account(1))
            assert_in("Staking started successfully", await wallet.start_staking())
            for _ in range(10):
                latest_tip = node.chainstate_best_block_id()
                self.wait_until(lambda: node.chainstate_best_block_id() != latest_tip, timeout = 15)
            assert_in("Success", await wallet.stop_staking())
            transactions = node.mempool_transactions()
            assert_equal(len(transactions), 0)

            assert_in("Success", await wallet.select_account(DEFAULT_ACCOUNT_INDEX))
            assert_in("Success", await wallet.sync())
            # assert the genesis pool has been decommissioned
            pools = await wallet.list_pool_ids()
            assert_equal(len(pools), 0)
            # check there is one utxo that is in locked state
            utxos = await wallet.list_utxos('lock-then-transfer', 'locked')
            assert_equal(len(utxos), 1)

            # check the locked balance is equal to the genesis pool balance
            locked_balance = await wallet.get_balance('locked')
            # remove decimals to avoid calculating the fee for the decommission req
            genesis_pool_balance = genesis_pool_balance[:genesis_pool_balance.find('.')]
            assert_in(f'Coins amount: {genesis_pool_balance}', locked_balance)


if __name__ == '__main__':
    WalletDecommissionGenesis().main()

