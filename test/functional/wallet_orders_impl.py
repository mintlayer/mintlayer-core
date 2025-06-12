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
"""Wallet orders test

* Create 3 wallets for Alice, Bob and Carol
* Alice mints some tokens and creates an order that sells these tokens for coins
* Bob fills the order with some coins and receives tokens in exchange
* Check balance
* Carol fills the order with some coins and receives tokens in exchange
* Check balance
* Alice concludes the order withdrawing coins and remaining tokens from it
* Check balance
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import (make_tx, reward_input, ATOMS_PER_COIN)
from test_framework.util import assert_in, assert_equal, assert_not_in
from test_framework.mintlayer import  block_input_data_obj
from test_framework.wallet_rpc_controller import WalletRpcController

import asyncio
import sys
import random

ATOMS_PER_TOKEN = 100

class WalletOrdersImpl(BitcoinTestFramework):
    def set_test_params(self, use_orders_v1):
        self.use_orders_v1 = use_orders_v1
        self.setup_clean_chain = True
        self.num_nodes = 1

        extra_args = ["--blockprod-min-peers-to-produce-blocks=0"]
        extra_args.extend(self.chain_config_args())

        self.extra_args = [extra_args]

    def chain_config_args(self):
        return [f"--chain-chainstate-orders-v1-upgrade-height={1 if self.use_orders_v1 else 999}"]

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

    async def switch_to_wallet(self, wallet, wallet_name):
        await wallet.close_wallet()
        await wallet.open_wallet(wallet_name)
        await wallet.sync()

    def run_test(self):
        if 'win32' in sys.platform:
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        asyncio.run(self.async_test())

    async def async_test(self):
        node = self.nodes[0]

        # new wallet
        async with WalletRpcController(node, self.config, self.log, [], self.chain_config_args()) as wallet:
            await wallet.create_wallet('alice_wallet')

            # check it is on genesis
            assert_equal('0', await wallet.get_best_block_height())

            # new addresses for both accounts to have some coins
            alice_address = await wallet.new_address()
            alice_pub_key_bytes = await wallet.new_public_key(alice_address)
            assert_equal(len(alice_pub_key_bytes), 33)

            await wallet.close_wallet()
            await wallet.create_wallet('bob_wallet')

            bob_address = await wallet.new_address()
            bob_pub_key_bytes = await wallet.new_public_key(bob_address)
            assert_equal(len(bob_pub_key_bytes), 33)

            await wallet.close_wallet()
            await wallet.create_wallet('carol_wallet')

            carol_address = await wallet.new_address()
            carol_pub_key_bytes = await wallet.new_public_key(carol_address)
            assert_equal(len(carol_pub_key_bytes), 33)

            await self.switch_to_wallet(wallet, 'alice_wallet')

            # Get chain tip
            tip_id = node.chainstate_best_block_id()
            self.log.debug(f'Tip: {tip_id}')

            # Submit a valid transaction
            outputs = [{
                'Transfer': [ { 'Coin': 151 * ATOMS_PER_COIN }, { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': alice_pub_key_bytes}}} } ],
            }, {
                'Transfer': [ { 'Coin': 151 * ATOMS_PER_COIN }, { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': bob_pub_key_bytes}}} } ],
            }, {
                'Transfer': [ { 'Coin': 151 * ATOMS_PER_COIN }, { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': carol_pub_key_bytes}}} } ],
            }]
            encoded_tx, tx_id = make_tx([reward_input(tip_id)], outputs, 0)

            node.mempool_submit_transaction(encoded_tx, {})
            assert node.mempool_contains_tx(tx_id)

            block_id = self.generate_block() # Block 1
            assert not node.mempool_contains_tx(tx_id)

            # sync the wallet
            assert_in("Success", await wallet.sync())

            # check wallet best block if it is synced
            assert_equal(await wallet.get_best_block_height(), '1')
            assert_equal(await wallet.get_best_block(), block_id)

            balance = await wallet.get_balance()
            assert_in(f"Coins amount: 151", balance)
            assert_not_in("Tokens", balance)

            # issue a valid token
            token_id, _, _ = (await wallet.issue_new_token("XXXX", 2, "http://uri", alice_address))
            assert token_id is not None
            self.log.info(f"new token id: {token_id}")

            self.generate_block()
            assert_in("Success", await wallet.sync())
            balance = await wallet.get_balance()
            assert_in(f"Coins amount: 50", balance)
            assert_not_in("Tokens", balance)

            amount_to_mint = random.randint(100, 10000)
            mint_result = await wallet.mint_tokens(token_id, alice_address, amount_to_mint)
            assert mint_result['tx_id'] is not None

            self.generate_block()
            assert_in("Success", await wallet.sync())
            balance = await wallet.get_balance()
            assert_in(f"Coins amount: 0", balance)
            assert_in(f"Token: {token_id} amount: {amount_to_mint}", balance)

            ########################################################################################
            # Alice creates an order selling tokens for coins
            create_order_result = await wallet.create_order(None, amount_to_mint * 2, token_id, amount_to_mint, alice_address)
            assert create_order_result['result']['tx_id'] is not None
            order_id = create_order_result['result']['order_id']

            self.generate_block()
            assert_in("Success", await wallet.sync())
            balance = await wallet.get_balance()
            assert_in(f"Coins amount: 0", balance)
            assert_not_in("Tokens", balance)

            ########################################################################################
            # Bob fills the order partially
            await self.switch_to_wallet(wallet, 'bob_wallet')
            balance = await wallet.get_balance()
            assert_in(f"Coins amount: 151", balance)
            assert_not_in("Tokens", balance)

            # buy 1 token
            fill_order_result = await wallet.fill_order(order_id, 2)
            assert fill_order_result['result']['tx_id'] is not None
            self.generate_block()
            assert_in("Success", await wallet.sync())
            balance = await wallet.get_balance()
            assert_in(f"Coins amount: 148.99", balance)
            assert_in(f"Token: {token_id} amount: 1", balance)

            # try conclude order
            conclude_order_result = await wallet.conclude_order(order_id)
            assert_in("Failed to convert partially signed tx to signed", conclude_order_result['error']['message'])

            ########################################################################################
            # Carol fills the order partially
            await self.switch_to_wallet(wallet, 'carol_wallet')
            balance = await wallet.get_balance()
            assert_in(f"Coins amount: 151", balance)
            assert_not_in("Tokens", balance)

            # buy 5 token
            fill_order_result = await wallet.fill_order(order_id, 10)
            assert fill_order_result['result']['tx_id'] is not None
            self.generate_block()
            assert_in("Success", await wallet.sync())
            balance = await wallet.get_balance()
            assert_in(f"Coins amount: 140", balance)
            assert_in(f"Token: {token_id} amount: 5", balance)

            # try freeze order
            freeze_order_result = await wallet.freeze_order(order_id)
            assert_in("Failed to convert partially signed tx to signed", freeze_order_result['error']['message'])

            # try conclude order
            conclude_order_result = await wallet.conclude_order(order_id)
            assert_in("Failed to convert partially signed tx to signed", conclude_order_result['error']['message'])

            if self.use_orders_v1:
                ########################################################################################
                # Alice freezes the order
                await self.switch_to_wallet(wallet, 'alice_wallet')
                assert_in("Success", await wallet.sync())

                freeze_order_result = await wallet.freeze_order(order_id)
                assert freeze_order_result['result']['tx_id'] is not None
                self.generate_block()
                assert_in("Success", await wallet.sync())

                ########################################################################################
                # Carol tries filling again
                await self.switch_to_wallet(wallet, 'carol_wallet')
                fill_order_result = await wallet.fill_order(order_id, 1)
                assert_in("Attempt to fill frozen order", fill_order_result['error']['message'])

            ########################################################################################
            # Alice concludes the order
            await self.switch_to_wallet(wallet, 'alice_wallet')
            assert_in("Success", await wallet.sync())

            conclude_order_result = await wallet.conclude_order(order_id)
            assert conclude_order_result['result']['tx_id'] is not None
            self.generate_block()
            assert_in("Success", await wallet.sync())
            balance = await wallet.get_balance()
            assert_in(f"Coins amount: 12", balance)
            assert_in(f"Token: {token_id} amount: {amount_to_mint - 5 - 1}", balance)

            ########################################################################################
            # Carol tries filling again
            await self.switch_to_wallet(wallet, 'carol_wallet')
            fill_order_result = await wallet.fill_order(order_id, 1)
            assert_in("Unknown order", fill_order_result['error']['message'])
