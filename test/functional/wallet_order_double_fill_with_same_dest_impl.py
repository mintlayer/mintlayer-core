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
""" Try submitting two transactions with "similar" FillOrder inputs (i.e. using the same amount
and, in the case of orders v0, the same destination), without mining a block in between.

Note: the exact result differs depending on the orders version; the purpose of the test is to
prove that nothing bad can happen as a result (e.g. in orders v1, where orders don't use nonces,
using the same amount results in exactly the same FillOrder input being produced; under older
consensus rules, if both of the txs are included in the same block, the block would be invalid).
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

class WalletOrderDoubleFillWithSameDestImpl(BitcoinTestFramework):
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

            await self.switch_to_wallet(wallet, 'alice_wallet')

            # Get chain tip
            tip_id = node.chainstate_best_block_id()
            self.log.debug(f'Tip: {tip_id}')

            # Submit a valid transaction
            outputs = [{
                'Transfer': [ { 'Coin': 151 * ATOMS_PER_COIN }, { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': alice_pub_key_bytes}}} } ],
            }, {
                'Transfer': [ { 'Coin': 151 * ATOMS_PER_COIN }, { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': bob_pub_key_bytes}}} } ],
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
            # Bob fills the order
            await self.switch_to_wallet(wallet, 'bob_wallet')
            balance = await wallet.get_balance()
            assert_in(f"Coins amount: 151", balance)
            assert_not_in("Tokens", balance)

            fill_dest_address = await wallet.new_address()

            # Buy 1 token
            result = await wallet.fill_order(order_id, 2, fill_dest_address)
            fill_tx1_id = result['result']['tx_id']
            assert fill_tx1_id is not None

            if self.use_orders_v1:
                # Immediately buy 1 more token using the same destination address. Since the wallet also uses
                # the passed destination as the destination in the FillOrder input, mempool will think that the
                # second transaction conflicts with the first one.
                result = await wallet.fill_order(order_id, 2, fill_dest_address)
                assert_in("Mempool error: Transaction conflicts with another, irreplaceable transaction", result['error']['message'])

                # We are able to successfully generate a block.
                self.generate_block()
                assert_in("Success", await wallet.sync())

                # Try creating the transaction again, in a new block. Now it should succeed.
                result = await wallet.fill_order(order_id, 2, fill_dest_address)
                fill_tx2_id = result['result']['tx_id']
                assert fill_tx2_id is not None
            else:
                # In orders v0 the destination shouldn't be a problem due to nonces.
                # However, at this moment the wallet gets the nonce from the chainstate only,
                # so creating another "fill" tx when the previos one hasn't been mined yet
                # will use the same nonce.
                result = await wallet.fill_order(order_id, 2, fill_dest_address)
                assert_in("Mempool error: Nonce is not incremental", result['error']['message'])

                self.generate_block()
                assert_in("Success", await wallet.sync())

                # After the first tx has been mined, a new one will be created with the correct nonce.
                result = await wallet.fill_order(order_id, 2, fill_dest_address)
                fill_tx2_id = result['result']['tx_id']
                assert fill_tx2_id is not None

            self.generate_block()
            assert_in("Success", await wallet.sync())

            balance = await wallet.get_balance()
            assert_in(f"Coins amount: 146.99", balance)
            assert_in(f"Token: {token_id} amount: 2", balance)
