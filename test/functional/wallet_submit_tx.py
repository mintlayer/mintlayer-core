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
* get an address
* send coins to the wallet's address
* sync the wallet with the node
* check balance
"""

import json
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import (make_tx, reward_input, tx_input, ATOMS_PER_COIN)
from test_framework.util import assert_in, assert_equal
from test_framework.mintlayer import mintlayer_hash, block_input_data_obj
from test_framework.wallet_cli_controller import WalletCliController

import asyncio
import sys
import random


class WalletSubmitTransaction(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        relay_fee_rate = random.randint(1, 100_000_000)
        self.extra_args = [[
            "--blockprod-min-peers-to-produce-blocks=0",
            f"--min-tx-relay-fee-rate={relay_fee_rate}",
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
        if 'win32' in sys.platform:
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
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

            # new address
            pub_key_bytes = await wallet.new_public_key()
            assert_equal(len(pub_key_bytes), 33)

            # Get chain tip
            tip_id = node.chainstate_best_block_id()
            genesis_block_id = tip_id
            self.log.debug(f'Tip: {tip_id}')

            # Submit a valid transaction
            coins_to_send = random.randint(2, 100)
            output = {
                    'Transfer': [ { 'Coin': coins_to_send * ATOMS_PER_COIN }, { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': pub_key_bytes}}} } ],
            }
            encoded_tx, tx_id = make_tx([reward_input(tip_id)], [output], 0)

            self.log.debug(f"Encoded transaction {tx_id}: {encoded_tx}")

            assert_in("No transaction found", await wallet.get_transaction(tx_id))

            store_tx_in_wallet = random.choice([True, False])
            assert_in("The transaction was submitted successfully", await wallet.submit_transaction(encoded_tx, not store_tx_in_wallet))

            if store_tx_in_wallet:
                assert_in(f"Coins amount: {coins_to_send}", await wallet.get_balance(utxo_states=['inactive']))
            else:
                assert_in(f"Coins amount: 0", await wallet.get_balance(utxo_states=['inactive']))

            assert node.mempool_contains_tx(tx_id)

            block_id = self.generate_block() # Block 1
            assert not node.mempool_contains_tx(tx_id)

            # sync the wallet
            assert_in("Success", await wallet.sync())

            # check wallet best block if it is synced
            best_block_height = await wallet.get_best_block_height()
            assert_equal(best_block_height, '1')

            best_block_id = await wallet.get_best_block()
            assert_equal(best_block_id, block_id)

            block_id = node.chainstate_block_id_at_height(1)
            block = node.chainstate_get_block_json(block_id)
            timestamp = block['timestamp']['timestamp']

            output = await wallet.get_transaction(tx_id)
            tx_output = output[0]["V1"]
            assert_equal(1, len(tx_output["inputs"]))
            assert_equal(genesis_block_id, tx_output["inputs"][0]["content"]["content"]["id"])
            assert_equal(0, tx_output["inputs"][0]["content"]["content"]["index"])

            assert_equal(1, len(tx_output["outputs"]))
            assert_equal(str(coins_to_send * ATOMS_PER_COIN), tx_output["outputs"][0]["Transfer"][0]["Coin"]["atoms"])

            assert_equal(int(best_block_height), output[1]['Confirmed'][0])
            assert_equal(timestamp, output[1]['Confirmed'][1]['timestamp'])
            assert_equal(0, output[1]['Confirmed'][2])

            # check the raw encoding
            output = await wallet.get_raw_signed_transaction(tx_id)
            assert_equal(output, encoded_tx)

            assert_in(f"Coins amount: {coins_to_send}", await wallet.get_balance())

            address = await wallet.new_address()
            output = await wallet.send_to_address(address, 1)
            assert_in("The transaction was submitted successfully", output)


if __name__ == '__main__':
    WalletSubmitTransaction().main()
