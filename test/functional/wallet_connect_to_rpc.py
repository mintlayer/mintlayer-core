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
"""Wallet connect to RPC wallet from CLI wallet test

Check that:
* We can create a new wallet with RPC enabled,
* We start another wallet that connects to the first wallet
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
        async with WalletCliController(node, self.config, self.log, wallet_args=["--wallet-rpc-bind-address", "127.0.0.1:23134", "--enable-wallet-rpc-interface", "--wallet-rpc-no-authentication"]) as wallet1:

            # new wallet
            await wallet1.create_wallet("wallet1")

            # open a new CLI wallet that connects to the previous one through RPC
            async with WalletCliController(node, self.config, self.log, wallet_args=["--remote-rpc-wallet-address", "127.0.0.1:23134"]) as wallet2:

                # check it is on genesis
                best_block_height = await wallet2.get_best_block_height()
                self.log.info(f"best block height = {best_block_height}")
                assert_equal(best_block_height, '0')

                # new address
                pub_key_bytes = await wallet2.new_public_key()
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

                assert_in("No transaction found", await wallet2.get_transaction(tx_id))

                node.mempool_submit_transaction(encoded_tx, {})
                assert node.mempool_contains_tx(tx_id)

                block_id = self.generate_block() # Block 1
                assert not node.mempool_contains_tx(tx_id)

                # sync the wallet
                assert_in("Success", await wallet2.sync())

                # check wallet best block if it is synced
                best_block_height = await wallet2.get_best_block_height()
                assert_equal(best_block_height, '1')

                best_block_id = await wallet2.get_best_block()
                assert_equal(best_block_id, block_id)

                output = await wallet2.get_transaction(tx_id)
                output = output[0]["V1"]
                assert_equal(1, len(output["inputs"]))
                assert_equal(genesis_block_id, output["inputs"][0]["Utxo"]["id"]["BlockReward"])
                assert_equal(0, output["inputs"][0]["Utxo"]["index"])

                assert_equal(1, len(output["outputs"]))
                assert_equal(coins_to_send * ATOMS_PER_COIN, output["outputs"][0]["Transfer"][0]["Coin"]["val"])

                # check the raw encoding
                output = await wallet2.get_raw_signed_transaction(tx_id)
                assert_equal(output, encoded_tx)

                # same balance from both wallets
                assert_in(f"Coins amount: {coins_to_send}", await wallet2.get_balance())
                assert_in(f"Coins amount: {coins_to_send}", await wallet1.get_balance())


                # ==== Try to close/open the wallet from wallet1 and check that wallet2 will report the change
                # close and create a new wallet
                await wallet1.close_wallet()
                await wallet1.create_wallet("wallet2")
                # first command will error as the wallet is not the same
                assert_in("A different wallet than the existing one has been opened between commands", await wallet2.get_balance())
                # second command will work fine
                assert_in(f"Coins amount: 0", await wallet2.get_balance())

                # close the wallet
                await wallet1.close_wallet()
                assert_in(f"The wallet has been closed between commands", await wallet2.get_balance())
                assert_in(f"Please open or create a wallet file first", await wallet2.get_balance())

                await wallet1.open_wallet("wallet1")
                assert_in(f"A new wallet has been opened between commands", await wallet2.get_balance())
                assert_in(f"Coins amount: {coins_to_send}", await wallet2.get_balance())
                assert_in(f"Coins amount: {coins_to_send}", await wallet1.get_balance())

                address = await wallet2.new_address()
                output = await wallet2.send_to_address(address, 1)
                assert_in("The transaction was submitted successfully", output)


if __name__ == '__main__':
    WalletSubmitTransaction().main()

