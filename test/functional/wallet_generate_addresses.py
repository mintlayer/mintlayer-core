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
"""Wallet address generator test

Check that:
* We can create a new wallet,
* get an address
* send coins to the wallet's address
* sync the wallet with the node
* check balance
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import (make_tx, reward_input, tx_input, ATOMS_PER_COIN)
from test_framework.util import assert_in, assert_equal
from test_framework.mintlayer import mintlayer_hash, block_input_data_obj
from test_framework.wallet_cli_controller import WalletCliController

import asyncio
import sys
import subprocess
import os
import re


class WalletAddressGenerator(BitcoinTestFramework):

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
        block = node.blockprod_generate_block(block_input_data, [], [], 'FillSpaceFromMempool')
        node.chainstate_submit_block(block)
        block_id = node.chainstate_best_block_id()

        # Wait for mempool to sync
        self.wait_until(lambda: node.mempool_local_best_block_id() == block_id, timeout = 5)

        return block_id

    def run_generate_addresses(self, args = []):
        addr_generator_cli = os.path.join(self.config["environment"]["BUILDDIR"], "test_wallet_address_generator"+self.config["environment"]["EXEEXT"] )
        args = ["--network", "regtest"] + args
        self.log.info(f"sending args {args}")

        result = subprocess.run([addr_generator_cli, *args], stdout=subprocess.PIPE)
        output = result.stdout.decode()
        self.log.info(output)

        lines = output.splitlines()
        if lines[3].startswith("Using the seed phrase you provided to generate address"):
            seed_phrase = lines[3][lines[3].find(':')+2:]
            addresses = [addr[2:] for addr in output.splitlines()[7:-2]]
        elif lines[3].startswith("No seed phrase provided"):
            seed_phrase = lines[6]
            addresses = [addr[2:] for addr in output.splitlines()[11:-2]]
        else:
            return None, None


        return seed_phrase, addresses


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
            self.log.debug(f'Tip: {tip_id}')

            # Submit a valid transaction
            output = {
                    'Transfer': [ { 'Coin': 100 * ATOMS_PER_COIN }, { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': pub_key_bytes}}} } ],
            }
            encoded_tx, tx_id = make_tx([reward_input(tip_id)], [output], 0)

            self.log.debug(f"Encoded transaction {tx_id}: {encoded_tx}")

            node.mempool_submit_transaction(encoded_tx, {})
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

            assert_in("Coins amount: 100", await wallet.get_balance())

            # use the new CLI tool to create a new seed_phrase and some addresses
            seed_phrase, addresses = self.run_generate_addresses(["--address-count", "20"])
            assert seed_phrase is not None
            assert addresses is not None

            self.log.info(f"addresses '{addresses}'")
            assert_equal(len(addresses), 20)

            # send some a coin to each one of the addresses to confirm all of them are valid
            for addr in addresses:
                assert_in("The transaction was submitted successfully", await wallet.send_to_address(addr, 1))
            self.generate_block()

            # close this wallet and create a new one with the new seed phrase
            await wallet.close_wallet()
            assert_in("Wallet recovered successfully", await wallet.recover_wallet(seed_phrase))
            assert_in("Success", await wallet.sync())
            assert_in(f"Coins amount: {len(addresses)}", await wallet.get_balance())

            # check that if we specify the same seed phrase it will generate the same addresses
            new_seed_phrase, new_addresses = self.run_generate_addresses(["--address-count", "20", "--mnemonic", seed_phrase])
            assert_equal(seed_phrase, new_seed_phrase)
            assert_equal(addresses, new_addresses)


if __name__ == '__main__':
    WalletAddressGenerator().main()
