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
"""Wallet tokens change supply test

Check that:
* We can create a new wallet,
* get an address
* send coins to the wallet's address
* sync the wallet with the node
* check balance
* issue new token
* mint new tokens
* unmint existing tokens
* lock the tokens supply
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import (make_tx, reward_input, tx_input, ATOMS_PER_COIN)
from test_framework.util import assert_in, assert_equal, assert_not_in
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
                    'Transfer': [ { 'Coin': 2001 * ATOMS_PER_COIN }, { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': pub_key_bytes}}} } ],
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

            assert_in("Coins amount: 2001", await wallet.get_balance())

            address = await wallet.new_address()

            # invalid ticker
            # > max len
            token_id, tx_id, err = await wallet.issue_new_token("aaabbbcccddde", 2, "http://uri", address)
            assert token_id is None
            assert tx_id is None
            assert err is not None
            assert_in("Invalid ticker length", err)
            # non alphanumeric
            token_id, tx_id, err = await wallet.issue_new_token("asd#", 2, "http://uri", address)
            assert token_id is None
            assert tx_id is None
            assert err is not None
            assert_in("Invalid character in token ticker", err)

            # invalid url
            token_id, tx_id, err = await wallet.issue_new_token("XXX", 2, "123 123", address)
            assert token_id is None
            assert tx_id is None
            assert err is not None
            assert_in("Incorrect metadata URI", err)

            # invalid num decimals
            token_id, tx_id, err = await wallet.issue_new_token("XXX", 99, "http://uri", address)
            assert token_id is None
            assert tx_id is None
            assert err is not None
            assert_in("Too many decimals", err)

            # issue a valid token
            number_of_decimals = random.randrange(0, 4)
            token_id, tx_id, err = await wallet.issue_new_token("XXX", number_of_decimals, "http://uri", address, 'lockable')
            assert token_id is not None
            assert tx_id is not None
            assert err is None
            self.log.info(f"new token id: {token_id}")

            self.generate_block()
            assert_in("Success", await wallet.sync())
            assert_in("Coins amount: 1900", await wallet.get_balance())

            tokens_to_mint = random.randrange(2, 10000)
            total_tokens_supply = tokens_to_mint
            assert_in("The transaction was submitted successfully", await wallet.mint_tokens(token_id, address, tokens_to_mint))

            self.generate_block()
            assert_in("Success", await wallet.sync())
            assert_in("Coins amount: 1850", await wallet.get_balance())

            # randomize minting and unminting
            expected_coins_balance = 1850
            for _ in range(10):
                if random.choice([True, False]):
                    # mint some more tokens
                    tokens_to_mint = random.randrange(1, 10000)
                    total_tokens_supply = total_tokens_supply + tokens_to_mint
                    expected_coins_balance -= 50
                    assert_in("The transaction was submitted successfully", await wallet.mint_tokens(token_id, address, tokens_to_mint))
                else:
                    # unmint some tokens
                    tokens_to_unmint = random.randrange(1, 20000)
                    if tokens_to_unmint <= total_tokens_supply:
                        total_tokens_supply = total_tokens_supply - tokens_to_unmint
                        expected_coins_balance -= 50
                        assert_in("The transaction was submitted successfully", await wallet.unmint_tokens(token_id, tokens_to_unmint))
                    else:
                        assert_in(f"Trying to unmint Amount {{ atoms: {tokens_to_unmint * 10**number_of_decimals} }} but the current supply is Amount {{ atoms: {total_tokens_supply * 10**number_of_decimals} }}", await wallet.unmint_tokens(token_id, tokens_to_unmint))
                        continue

                # either generate a new block or leave the transaction as in-memory state
                if random.choice([True, False]):
                    self.generate_block()
                    assert_in("Success", await wallet.sync())
                    assert_in(f"Coins amount: {expected_coins_balance}", await wallet.get_balance())

                # check total supply is correct
                if total_tokens_supply > 0:
                    assert_in(f"{token_id} amount: {total_tokens_supply}", await wallet.get_balance(utxo_states=['confirmed', 'inactive']))
                else:
                    assert_not_in(f"{token_id}", await wallet.get_balance(utxo_states=['confirmed', 'inactive']))


            # lock token supply
            assert_in("The transaction was submitted successfully", await wallet.lock_token_supply(token_id))
            self.generate_block()
            assert_in("Success", await wallet.sync())
            assert_in(f"Coins amount: {expected_coins_balance - 50}", await wallet.get_balance())
            if total_tokens_supply > 0:
                assert_in(f"{token_id} amount: {total_tokens_supply}", await wallet.get_balance())
            else:
                assert_not_in(f"{token_id}", await wallet.get_balance())

            # cannot mint any more tokens as it is locked
            assert_in("Cannot change a Locked Token supply", await wallet.mint_tokens(token_id, address, tokens_to_mint))
            assert_in("Cannot change a Locked Token supply", await wallet.unmint_tokens(token_id, tokens_to_mint))
            assert_in("Cannot lock Token supply in state: Locked", await wallet.lock_token_supply(token_id))


if __name__ == '__main__':
    WalletTokens().main()
