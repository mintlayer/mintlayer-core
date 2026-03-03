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
"""Wallet submission test

Check that:
* We can create a new wallet,
* get N addresses
* send coins to the wallet's addresses
* sync the wallet with the node
* get utxos
* send amount from a specific utxo
* check it has been used
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import (make_tx, reward_input)
from test_framework.util import assert_in, assert_equal
from test_framework.mintlayer import block_input_data_obj
from test_framework.wallet_cli_controller import UtxoOutpoint, WalletCliController

import asyncio
import random


class WalletSubmitTransactionSpecificUtxo(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            "--blockprod-min-peers-to-produce-blocks=0",
        ]]

    def setup_network(self):
        self.setup_nodes()
        self.sync_all(self.nodes[0:1])

    def generate_block(self):
        node = self.nodes[0]

        block_input_data = { "PoW": { "reward_destination": "AnyoneCanSpend" } }
        block_input_data = block_input_data_obj.encode(block_input_data).to_hex()[2:]

        # create a new block, taking transactions from mempool
        block = node.blockprod_generate_block(block_input_data, [], [], "FillSpaceFromMempool")
        node.chainstate_submit_block(block)
        block_id = node.chainstate_best_block_id()

        # Wait for mempool to sync
        self.wait_until(lambda: node.mempool_local_best_block_id() == block_id, timeout = 5)

        return block_id

    def run_test(self):
        asyncio.run(self.async_test())

    async def async_test(self):
        node = self.nodes[0]
        async with WalletCliController(node, self.config, self.log) as wallet:
            # new wallet
            await wallet.create_wallet()

            # check it is on genesis
            best_block_height = await wallet.get_best_block_height()
            self.log.info(f"best block height = {best_block_height}")
            assert_equal(best_block_height, '0')

            # Get chain tip
            tip_id = node.chainstate_best_block_id()
            self.log.debug(f'Tip: {tip_id}')

            # new address
            addresses = []
            num_utxos = random.randint(5, 10)
            for _ in range(num_utxos):
                pub_key_bytes = await wallet.new_public_key()
                assert_equal(len(pub_key_bytes), 33)
                addresses.append(pub_key_bytes)

            # Submit a valid transaction
            def make_output(pub_key_bytes):
                return {
                        'Transfer': [ { 'Coin': 1_000_000_000_000 }, { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': pub_key_bytes}}} } ],
                }
            encoded_tx, tx_id = make_tx([reward_input(tip_id)], [make_output(pk) for pk in addresses], 0)

            node.mempool_submit_transaction(encoded_tx, {})
            assert node.mempool_contains_tx(tx_id)

            block_id = self.generate_block() # Block 1
            assert not node.mempool_contains_tx(tx_id)

            # sync the wallet
            output = await wallet.sync()
            assert_in("Success", output)

            # check wallet best block if it is synced
            best_block_height = await wallet.get_best_block_height()
            assert_equal(best_block_height, '1')

            best_block_id = await wallet.get_best_block()
            assert_equal(best_block_id, block_id)

            balance = await wallet.get_balance()
            assert_in(f"Coins amount: {10*num_utxos}", balance)

            utxos = await wallet.list_utxos()
            assert_equal(len(utxos), num_utxos)

            address = await wallet.new_address()

            # try to select one and send more than it has it should fail
            selected_utxos = random.sample(utxos, 1)
            output = await wallet.send_to_address(address, 11, selected_utxos)
            assert_in("Wallet error: Coin selection error: Not enough funds", output)
            # check that we didn't spent any utxos
            assert_equal(utxos, await wallet.list_utxos())

            # select the first 3 and check that they will be spent
            selected_utxos = random.sample(utxos, random.randint(1, num_utxos-1))
            not_selected_utxos = [utxo for utxo in utxos if utxo not in selected_utxos]
            await wallet.send_to_address(address, 1, selected_utxos)

            self.generate_block()
            assert not node.mempool_contains_tx(tx_id)

            # sync the wallet
            output = await wallet.sync()
            assert_in("Success", output)

            new_utxos = await wallet.list_utxos()
            self.log.info(f"old utxos {len(utxos)}: {utxos}")
            self.log.info(f"new utxos {len(new_utxos)}: {new_utxos}")
            # check that the new utxos have the selected utxos removed,
            # but have a new one from the transfer and one more from the change
            assert_equal(len(new_utxos), num_utxos - len(selected_utxos) + 2)
            # check selected utxos are no longer present
            assert all(selected_utxo not in new_utxos for selected_utxo in selected_utxos)
            # check not-selected utxos are still present
            assert all(not_selected_utxo in new_utxos for not_selected_utxo in not_selected_utxos)

            # try to select already spent utxo
            already_selected = random.sample(selected_utxos, random.randint(1, len(selected_utxos)))
            assert_in("is already consumed", await wallet.send_to_address(address, 1, already_selected))

            # try to select unknown utxo
            unknown_utxo_id = "0" * len(selected_utxos[0].id)
            unknown_utxo = UtxoOutpoint(unknown_utxo_id, 1)
            assert_in("Cannot find UTXO", await wallet.send_to_address(address, 1, [unknown_utxo]))

            # check that we didn't spent any utxos
            assert_equal(new_utxos, await wallet.list_utxos())



if __name__ == '__main__':
    WalletSubmitTransactionSpecificUtxo().main()
