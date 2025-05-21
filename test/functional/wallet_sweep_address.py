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
"""Wallet sweep test

Check that:
* We can create a new wallet,
* get an address
* send multiple times coins to the wallet's addresses
* sync the wallet with the node
* get utxos
* sweep all coins from the address
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import (ATOMS_PER_COIN, make_tx, reward_input, tx_input)
from test_framework.util import assert_in, assert_equal, assert_not_in
from test_framework.mintlayer import mintlayer_hash, block_input_data_obj
from test_framework.wallet_cli_controller import UtxoOutpoint, WalletCliController

import asyncio
import sys
import random


class WalletSweepAddresses(BitcoinTestFramework):

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
            pks = []
            num_utxos = random.randint(5, 10)
            for _ in range(num_utxos):
                address = await wallet.new_address()
                pub_key_bytes = await wallet.new_public_key(address)
                assert_equal(len(pub_key_bytes), 33)
                pks.append(pub_key_bytes)

                address = await wallet.reveal_public_key_as_address(address)
                addresses.append(address)

            # add a locked output which will be filtered out
            address = await wallet.new_address()
            locked_pub_key_bytes = await wallet.new_public_key(address)
            assert_equal(len(locked_pub_key_bytes), 33)
            locked_address = await wallet.reveal_public_key_as_address(address)
            addresses.append(locked_address)

            coins_per_utxo = 100

            # Submit a valid transaction
            def make_output(pub_key_bytes):
                return {
                        'Transfer': [ { 'Coin': coins_per_utxo * ATOMS_PER_COIN }, { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': pub_key_bytes}}} } ],
                }
            def make_locked_output(pub_key_bytes):
                return {
                        'LockThenTransfer': [ { 'Coin': coins_per_utxo * ATOMS_PER_COIN }, { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': pub_key_bytes}}} }, { 'ForBlockCount': 99 } ],
                }
            encoded_tx, tx_id = make_tx([reward_input(tip_id)], [make_output(pk) for pk in pks] + [make_locked_output(locked_pub_key_bytes)], 0)

            node.mempool_submit_transaction(encoded_tx, {})
            assert node.mempool_contains_tx(tx_id)

            block_id = self.generate_block()
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
            assert_in(f"Coins amount: {coins_per_utxo*num_utxos}", balance)
            balance = await wallet.get_balance('locked')
            assert_in(f"Coins amount: {coins_per_utxo}", balance)

            utxos = await wallet.list_utxos()
            assert_equal(len(utxos), num_utxos)

            # create a new account and sweep all addresses to that one
            await wallet.create_new_account()
            await wallet.select_account(1)
            acc1_address = await wallet.new_address()

            await wallet.select_account(0)
            assert_in("The transaction was submitted successfully", await wallet.sweep_addresses(acc1_address, all_addresses=True))

            block_id = self.generate_block()
            assert_in("Success", await wallet.sync())

            # check we sent all our coins
            balance = await wallet.get_balance()
            assert_in("Coins amount: 0", balance)
            # check we still have the locked balance

            balance = await wallet.get_balance('locked')
            assert_in(f"Coins amount: {coins_per_utxo}", balance)

            acc0_address = await wallet.new_address()

            # select the other account now that has the coins and create some tokens
            await wallet.select_account(1)

            # addresses for acc1 to transfer back to acc0
            addresses = []

            # issue some tokens to also transfer
            tokens_address = await wallet.new_address()
            token_id, tx_id, err = await wallet.issue_new_token("XXX", 2, "http://uri", tokens_address)
            assert token_id is not None
            assert tx_id is not None
            assert err is None
            self.log.info(f"new token id: {token_id} tx_id: {tx_id}")
            assert node.mempool_contains_tx(tx_id)
            block_id = self.generate_block()
            assert_in("Success", await wallet.sync())
            assert_in("The transaction was submitted successfully", await wallet.mint_tokens(token_id, tokens_address, 10000))
            addresses.append(tokens_address)

            # issue some more tokens but freeze them
            frozen_tokens_address = await wallet.new_address()
            frozen_token_id, frozen_tx_id, err = await wallet.issue_new_token("XXX", 2, "http://uri", frozen_tokens_address)
            assert frozen_token_id is not None
            assert frozen_tx_id is not None
            assert err is None
            self.log.info(f"new token id: {frozen_token_id}")
            assert node.mempool_contains_tx(frozen_tx_id)
            block_id = self.generate_block()
            assert_in("Success", await wallet.sync())
            assert_in("The transaction was submitted successfully", await wallet.mint_tokens(frozen_token_id, frozen_tokens_address, 10000))
            block_id = self.generate_block()
            assert_in("Success", await wallet.sync())
            assert_in("The transaction was submitted successfully", await wallet.freeze_token(frozen_token_id, 'unfreezable'))
            addresses.append(tokens_address)

            # get a coin address to include in the sweep to pay for the sweep tx fees
            fee_address = await wallet.new_address()
            assert_in("The transaction was submitted successfully", await wallet.send_to_address(fee_address, 1))
            addresses.append(fee_address)

            # now sweep all tokens to acc0
            assert_in("The transaction was submitted successfully", await wallet.sweep_addresses(acc0_address, addresses))

            block_id = self.generate_block()
            assert_in("Success", await wallet.sync())

            # check the balance
            balance = await wallet.get_balance()
            # frozen tokens can't be transferred so they should be here
            assert_in(f"{frozen_token_id} amount: 10000", balance)
            # the other token should not be in the acc1 balance any more
            assert_not_in(f"{token_id}", balance)

            await wallet.select_account(0)
            balance = await wallet.get_balance()
            # frozen tokens can't be transferred so they are not in acc0 balance
            assert_not_in(f"{frozen_token_id}", balance)
            # the other token should be fully transferred in the acc0 balance
            assert_in(f"{token_id} amount: 10000", balance)


if __name__ == '__main__':
    WalletSweepAddresses().main()

