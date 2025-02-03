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
"""Wallet accounts recovery test

Check that:
* We can create a new wallet,
* get an address
* send coins to the wallet's address
* sync the wallet with the node
* create random amount of new accounts
* send coins to that accounts as well
* check balance
* recover the wallet using the mnemonic
* check that it has all of the accounts with the correct balances
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import (make_tx, reward_input, tx_input, ATOMS_PER_COIN)
from test_framework.util import assert_in, assert_equal
from test_framework.mintlayer import mintlayer_hash, block_input_data_obj
from test_framework.wallet_cli_controller import DEFAULT_ACCOUNT_INDEX, WalletCliController

import asyncio
import sys
from random import randint


class WalletRecoverAccounts(BitcoinTestFramework):

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
        if 'win32' in sys.platform:
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        asyncio.run(self.async_test())

    async def async_test(self):
        node = self.nodes[0]

        # new wallet
        async with WalletCliController(node, self.config, self.log) as wallet:
            invalid_mnemonic = "asd asd dwa"
            assert_in("Invalid mnemonic:",  await wallet.recover_wallet(invalid_mnemonic))

            await wallet.create_wallet()

            # check it is on genesis
            best_block_height = await wallet.get_best_block_height()
            assert_equal(best_block_height, '0')

            # new address
            pub_key_bytes = await wallet.new_public_key()
            assert_equal(len(pub_key_bytes), 33)

            # Get chain tip
            tip_id = node.chainstate_best_block_id()
            self.log.debug(f'Tip: {tip_id}')

            # Submit a valid transaction
            output = {
                    'Transfer': [ { 'Coin': 10 * ATOMS_PER_COIN }, { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': pub_key_bytes}}} } ],
            }
            encoded_tx, tx_id = make_tx([reward_input(tip_id)], [output], 0)

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
            assert_in("Coins amount: 10", balance)

            # create new accounts
            num_accounts = randint(1, 3)
            for idx in range(num_accounts):
                assert_in("Success", await wallet.create_new_account())
                assert_in("Success", await wallet.select_account(idx+1))
                address = await wallet.new_address()
                assert_in("Success", await wallet.select_account(DEFAULT_ACCOUNT_INDEX))
                assert_in("The transaction was submitted successfully", await wallet.send_to_address(address, idx+1))
                self.generate_block()
                assert_in("Success", await wallet.sync())
                assert_equal(f"{idx+2}", await wallet.get_best_block_height())

            # try to recover the wallet
            mnemonic = await wallet.show_seed_phrase()
            assert mnemonic is not None
            assert_in("Successfully closed the wallet", await wallet.close_wallet())
            assert_in("Wallet recovered successfully", await wallet.recover_wallet(mnemonic))

            # sync and check that accounts are now present and with correct balances
            assert_in("Success", await wallet.sync())

            for idx in range(num_accounts):
                assert_in("Success", await wallet.select_account(idx+1))
                assert_in(f"Coins amount: {idx+1}", await wallet.get_balance())


if __name__ == '__main__':
    WalletRecoverAccounts().main()
