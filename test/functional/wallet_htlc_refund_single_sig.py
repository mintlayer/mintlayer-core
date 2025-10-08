#!/usr/bin/env python3
#  Copyright (c) 2025 RBB S.r.l
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
"""Wallet htlc refund test.

The refund addresses are single-sig.

* Create 2 wallets for Alice and Bob.
* Alice mints some tokens and creates an output that locks them in htlc.
* Bob creates an output that locks coins in htlc.
* Both refund their htlcs.
* Check resulting balances.
"""

import asyncio
import random
import sys

from test_framework.mintlayer import (ATOMS_PER_COIN, block_input_data_obj, make_tx, reward_input)
from test_framework.script import hash160
from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet_controller_common import pub_key_hex_to_hexified_dest
from test_framework.wallet_rpc_controller import UtxoOutpoint, WalletRpcController
from test_framework.util import assert_equal, assert_in, assert_not_in


class WalletHtlcRefund(BitcoinTestFramework):
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

        # Create a new block, taking transactions from mempool
        block = node.blockprod_generate_block(block_input_data, [], [], "FillSpaceFromMempool")
        node.chainstate_submit_block(block)
        block_id = node.chainstate_best_block_id()

        # Wait for mempool to sync
        self.wait_until(lambda: node.mempool_local_best_block_id() == block_id, timeout = 5)

        return block_id

    async def switch_to_wallet(self, wallet, wallet_name):
        await wallet.close_wallet()
        await wallet.open_wallet(wallet_name)

    def run_test(self):
        if 'win32' in sys.platform:
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        asyncio.run(self.async_test())

    async def async_test(self):
        node = self.nodes[0]

        async with WalletRpcController(node, self.config, self.log) as wallet:
            ########################################################################################
            # Create wallets and generate addresses

            await wallet.create_wallet('alice_wallet')

            # new addresses for both accounts to have some coins
            alice_address = await wallet.new_address()
            alice_pub_key_bytes = await wallet.new_public_key(alice_address, strip_encoded_enum_prefix=False)
            alice_pub_key_hex = alice_pub_key_bytes.hex()

            await wallet.close_wallet()
            await wallet.create_wallet('bob_wallet')

            bob_address = await wallet.new_address()
            bob_pub_key_bytes = await wallet.new_public_key(bob_address, strip_encoded_enum_prefix=False)
            bob_pub_key_hex = bob_pub_key_bytes.hex()

            ########################################################################################
            # Fund the wallets with coins from genesis.
            # Both wallets will get 151 coins, where 1 coin is for the fees.
            # Alice will spend her 150 coins on creating and minting tokens.
            # Bob will put his 150 coins into htlc.

            # Switch to Alice's wallet right away.
            await self.switch_to_wallet(wallet, 'alice_wallet')

            # Sanity check - we're on genesis
            assert_equal('0', await wallet.get_best_block_height())
            genesis_id = node.chainstate_best_block_id()

            # Create and submit the funding transaction
            outputs = [{
                'Transfer': [
                    { 'Coin': 151 * ATOMS_PER_COIN },
                    { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': alice_pub_key_bytes[1:]}}} }
                ],
            }, {
                'Transfer': [
                    { 'Coin': 151 * ATOMS_PER_COIN },
                    { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': bob_pub_key_bytes[1:]}}} }
                ],
            }]
            encoded_tx, _ = make_tx([reward_input(genesis_id)], outputs, 0)
            await wallet.submit_transaction(encoded_tx)

            self.generate_block()
            assert_in("Success", await wallet.sync())

            # Check Alice's balance
            balance = await wallet.get_balance()
            assert_in("Coins amount: 151", balance)
            assert_not_in("Tokens", balance)

            ########################################################################################
            # Issue and mint tokens

            token_ticker = "XXXX"
            token_number_of_decimals = 2
            atoms_per_token = 10 ** token_number_of_decimals
            token_id, _, _ = await wallet.issue_new_token(
                token_ticker, token_number_of_decimals, "http://uri", alice_address)
            assert token_id is not None
            self.log.info(f"new token id: {token_id}")
            token_id_hex = node.test_functions_reveal_token_id(token_id)

            self.generate_block()
            assert_in("Success", await wallet.sync())
            balance = await wallet.get_balance()
            assert_in("Coins amount: 50", balance)
            assert_not_in("Tokens", balance)

            amount_to_mint = random.randint(1, 10000)
            mint_result = await wallet.mint_tokens(token_id, alice_address, amount_to_mint)
            assert mint_result['tx_id'] is not None

            self.generate_block()
            assert_in("Success", await wallet.sync())

            # Check Alice's balance
            balance = await wallet.get_balance()
            assert_in("Coins amount: 0", balance)
            assert_in(f"Token: {token_id} amount: {amount_to_mint}", balance)

            ########################################################################################
            # Setup Alice's htlc

            alice_secret = bytes([random.randint(0, 255) for _ in range(32)])
            alice_secret_hash = hash160(alice_secret).hex()

            alice_refund_address = alice_address

            alice_amount_to_swap = amount_to_mint
            result = await wallet.create_htlc_transaction(
                alice_amount_to_swap, token_id, alice_secret_hash, bob_address, alice_refund_address, 6)
            alice_htlc_tx_id = result['tx_id']
            alice_htlc_tx = result['tx']

            # Submit Alice's htlc
            output = await wallet.submit_transaction(alice_htlc_tx)
            assert_in("The transaction was submitted successfully", output)

            ########################################################################################
            # Setup Bob's htlc

            await self.switch_to_wallet(wallet, 'bob_wallet')
            assert_in("Success", await wallet.sync())

            bob_refund_address = bob_address

            bob_amount_to_swap = 150
            result = await wallet.create_htlc_transaction(
                bob_amount_to_swap, None, alice_secret_hash, alice_address, bob_refund_address, 6)
            bob_htlc_tx_id = result['tx_id']
            bob_htlc_tx = result['tx']

            # Submit Bob's htlc
            output = await wallet.submit_transaction(bob_htlc_tx)
            assert_in("The transaction was submitted successfully", output)

            ########################################################################################
            # Generate a block to mine the htlcs creation

            self.generate_block()

            # Check Alice's wallet - it's empty
            await self.switch_to_wallet(wallet, 'alice_wallet')
            assert_in("Success", await wallet.sync())
            balance = await wallet.get_balance(with_locked='any')
            assert_in("Coins amount: 0", balance)
            assert_not_in("Tokens", balance)

            # Check Bob's wallet - it's empty
            await self.switch_to_wallet(wallet, 'bob_wallet')
            assert_in("Success", await wallet.sync())
            balance = await wallet.get_balance(with_locked='any')
            assert_in("Coins amount: 0", balance)
            assert_not_in("Tokens", balance)

            # Also check the height we're at
            assert_equal('4', await wallet.get_best_block_height())

            ########################################################################################
            # Create Alice's refund transaction

            await self.switch_to_wallet(wallet, 'alice_wallet')

            output = {
                'Transfer': [
                    { 'TokenV1': [f"0x{token_id_hex}", {"atoms": str(alice_amount_to_swap * atoms_per_token)} ] },
                    pub_key_hex_to_hexified_dest(alice_pub_key_hex)
                ],
            }
            result = await wallet.compose_transaction(
                [output], [UtxoOutpoint(alice_htlc_tx_id, 0), UtxoOutpoint(alice_htlc_tx_id, 1)], [None, None])
            print(f"result = {result}")
            alice_refund_tx_hex = result['result']['hex']

            output = await wallet.sign_raw_transaction(alice_refund_tx_hex)
            assert_in("The transaction has been fully signed and is ready to be broadcast to network", output)
            alice_signed_refund_tx = output.split('\n')[2]

            # Alice's refund cannot be spent yet due to the timelock
            output = await wallet.submit_transaction(alice_signed_refund_tx)
            # Spending height is 9 and not 5 as one might expect because mempool uses effective_height
            # equal to tip's height + FUTURE_TIMELOCK_TOLERANCE_BLOCKS.
            assert_in("Spending at height 9, locked until height 10", output)

            ########################################################################################
            # Create Bob's refund transaction.
            # For the sake of variety, Bob will be using a LockThenTransfer output.

            await self.switch_to_wallet(wallet, 'bob_wallet')

            output = {
                'LockThenTransfer': [
                    { "Coin": {"atoms": str(bob_amount_to_swap * ATOMS_PER_COIN)} },
                    pub_key_hex_to_hexified_dest(bob_pub_key_hex),
                    { "type": "UntilHeight", "content": 99 }
                ],
            }
            result = await wallet.compose_transaction(
                [output], [UtxoOutpoint(bob_htlc_tx_id, 0), UtxoOutpoint(bob_htlc_tx_id, 1)], [None, None])
            print(f"result = {result}")
            bob_refund_tx_hex = result['result']['hex']

            output = await wallet.sign_raw_transaction(bob_refund_tx_hex)
            assert_in("The transaction has been fully signed and is ready to be broadcast to network", output)
            bob_signed_refund_tx = output.split('\n')[2]

            # Bob's refund cannot be spent yet due to the timelock
            output = await wallet.submit_transaction(bob_signed_refund_tx)
            # Same note about the spending height as above.
            assert_in("Spending at height 9, locked until height 10", output)

            ########################################################################################
            # Generate a block so that the txs can get into mempool
            self.generate_block()

            # Submit the refund txs; it doesn't matter which wallet does this.
            assert_in("Success", await wallet.sync())

            # Submit Alice's refund tx
            output = await wallet.submit_transaction(alice_signed_refund_tx)
            tx_id = output.split('\n')[2]
            assert node.mempool_contains_tx(tx_id)

            # Submit Bob's refund tx
            output = await wallet.submit_transaction(bob_signed_refund_tx)
            tx_id = output.split('\n')[2]
            assert node.mempool_contains_tx(tx_id)

            # The txs won't get into blockchain right away because of timelock
            for _ in range(4):
                self.generate_block()

            # Switch to Alice's wallet and check balance - still nothing
            await self.switch_to_wallet(wallet, 'alice_wallet')
            assert_in("Success", await wallet.sync())
            balance = await wallet.get_balance(with_locked='any')
            assert_in("Coins amount: 0", balance)
            assert_not_in("Tokens", balance)

            # Switch to Bob's wallet and check balance - still nothing
            await self.switch_to_wallet(wallet, 'alice_wallet')
            assert_in("Success", await wallet.sync())
            balance = await wallet.get_balance(with_locked='any')
            assert_in("Coins amount: 0", balance)
            assert_not_in("Tokens", balance)

            # Generate the final block, where the refund txs will be mined.
            self.generate_block()

            # Switch to Alice's wallet and check balance - she got her tokens back.
            await self.switch_to_wallet(wallet, 'alice_wallet')
            assert_in("Success", await wallet.sync())
            all_balance = await wallet.get_balance(with_locked='any')
            unlocked_balance = await wallet.get_balance(with_locked='unlocked')
            assert_in("Coins amount: 0", all_balance)
            assert_in("Coins amount: 0", unlocked_balance)
            assert_in(f"Token: {token_id} amount: {alice_amount_to_swap}", all_balance)
            assert_in(f"Token: {token_id} amount: {alice_amount_to_swap}", unlocked_balance)

            # Switch to Bob's wallet and check balance - he got his coins back, but the're locked
            # because he used LockThenTransfer.
            await self.switch_to_wallet(wallet, 'bob_wallet')
            assert_in("Success", await wallet.sync())
            all_balance = await wallet.get_balance(with_locked='any')
            unlocked_balance = await wallet.get_balance(with_locked='unlocked')
            assert_in(f"Coins amount: {bob_amount_to_swap}", all_balance)
            assert_in(f"Coins amount: 0", unlocked_balance)
            assert_not_in("Tokens", all_balance)
            assert_not_in("Tokens", unlocked_balance)


if __name__ == '__main__':
    WalletHtlcRefund().main()
