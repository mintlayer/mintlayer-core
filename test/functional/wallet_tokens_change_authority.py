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
"""Wallet tokens change authority test

Check that:
* We can create a new wallet,
* get an address
* send coins to the wallet's address
* sync the wallet with the node
* check balance
* issue new token
* transfer some tokens
* check balance
* transfer authority to another account
* check we can't modify the token from the original acc
* check we can modify the token from the new acc
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import (make_tx, reward_input, tx_input, ATOMS_PER_COIN)
from test_framework.util import assert_in, assert_equal
from test_framework.mintlayer import mintlayer_hash, block_input_data_obj
from test_framework.wallet_cli_controller import DEFAULT_ACCOUNT_INDEX, WalletCliController

import asyncio
import sys
import random

class WalletTokens(BitcoinTestFramework):

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
            await wallet.create_wallet()

            # check it is on genesis
            assert_equal('0', await wallet.get_best_block_height())

            # new address
            pub_key_bytes = await wallet.new_public_key()
            assert_equal(len(pub_key_bytes), 33)

            # Get chain tip
            tip_id = node.chainstate_best_block_id()
            self.log.debug(f'Tip: {tip_id}')

            # Submit a valid transaction
            output = {
                    'Transfer': [ { 'Coin': 1001 * ATOMS_PER_COIN }, { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': pub_key_bytes}}} } ],
            }
            encoded_tx, tx_id = make_tx([reward_input(tip_id)], [output], 0)

            node.mempool_submit_transaction(encoded_tx, {})
            assert node.mempool_contains_tx(tx_id)

            block_id = self.generate_block() # Block 1
            assert not node.mempool_contains_tx(tx_id)

            # sync the wallet
            assert_in("Success", await wallet.sync())

            # check wallet best block if it is synced
            assert_equal(await wallet.get_best_block_height(), '1')
            assert_equal(await wallet.get_best_block(), block_id)

            assert_in("Coins amount: 1001", await wallet.get_balance())

            address = await wallet.new_address()

            # issue a valid token
            token_id, tx_id, err = await wallet.issue_new_token("XXX", 2, "http://uri", address, token_supply='lockable')
            assert token_id is not None
            assert tx_id is not None
            assert err is None
            self.log.info(f"new token id: {token_id}")

            self.generate_block()
            assert_in("Success", await wallet.sync())
            assert_in("Coins amount: 900", await wallet.get_balance())

            assert_in("The transaction was submitted successfully", await wallet.mint_tokens(token_id, address, 10000))

            self.generate_block()
            assert_in("Success", await wallet.sync())

            assert_in(f"{token_id} amount: 10000", await wallet.get_balance())
            assert_in("Coins amount: 850", await wallet.get_balance())

            ## create a new account and send some tokens to it
            await wallet.create_new_account()
            await wallet.select_account(1)
            new_acc_address = await wallet.new_address()

            await wallet.select_account(DEFAULT_ACCOUNT_INDEX)
            output = await wallet.send_tokens_to_address(token_id, new_acc_address, 10.01)
            assert_in("The transaction was submitted successfully", output)
            # send some coins for fees
            assert_in("The transaction was submitted successfully", await wallet.send_to_address(new_acc_address, 600))

            self.generate_block()
            assert_in("Success", await wallet.sync())

            ## check the new balance
            assert_in(f"{token_id} amount: 9989.99", await wallet.get_balance())


            assert_in("The transaction was submitted successfully", await wallet.change_token_authority(token_id, new_acc_address))

            # randomly put the tx in a block or keep in mempool unconfirmed
            produce_block = random.choice([True, False])
            if produce_block:
                self.generate_block()
                assert_in("Success", await wallet.sync())
                assert_in("Coins amount: 230", await wallet.get_balance())


            # try to mint, unmint, lock, freeze and unfreeze
            assert_in("Cannot change a not owned token", await wallet.mint_tokens(token_id, address, 1))
            assert_in("Cannot change a not owned token", await wallet.unmint_tokens(token_id, 1))
            assert_in("Cannot change a not owned token", await wallet.lock_token_supply(token_id))
            assert_in("Cannot change a not owned token", await wallet.freeze_token(token_id, 'unfreezable'))
            assert_in("Cannot change a not owned token", await wallet.unfreeze_token(token_id))


            await wallet.select_account(1)
            # make sure the transfer of authority is confirmed
            if not produce_block:
                self.generate_block()
                assert_in("Success", await wallet.sync())

            # check that the other account is now the owner and can do anything
            assert_in("The transaction was submitted successfully", await wallet.mint_tokens(token_id, address, 1))
            assert_in("The transaction was submitted successfully", await wallet.unmint_tokens(token_id, 1))
            assert_in("The transaction was submitted successfully", await wallet.lock_token_supply(token_id))
            assert_in("The transaction was submitted successfully", await wallet.freeze_token(token_id, 'unfreezable'))
            assert_in("The transaction was submitted successfully", await wallet.unfreeze_token(token_id))


if __name__ == '__main__':
    WalletTokens().main()
