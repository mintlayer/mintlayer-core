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
"""Wallet htlc spend with a secret test

* Create 2 wallets for Alice and Bob
* Alice mints some tokens and creates an output that locks those tokens in htlc
* Bob creates an output that locks coins in htlc
* Check that Alice cannot spend her htlc output even with the secret
* Check that Bob cannot spend Alice's htlc without the secret
* Check that Alice can spend Bob's htlc output only by revealing the secret
* Check that Bob can extract secret from Alice's tx and use it to spend Alice's htlc output
* Check resulting balances
"""

from test_framework.script import hash160
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import (make_tx, reward_input, ATOMS_PER_COIN)
from test_framework.util import assert_in, assert_equal, assert_not_in
from test_framework.mintlayer import  block_input_data_obj
from test_framework.wallet_rpc_controller import TransferTxOutput, UtxoOutpoint, WalletRpcController

import asyncio
import sys
import random

ATOMS_PER_TOKEN = 100

class WalletHtlcSpend(BitcoinTestFramework):

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

    async def switch_to_wallet(self, wallet, wallet_name):
        await wallet.close_wallet()
        await wallet.open_wallet(wallet_name)

    def run_test(self):
        if 'win32' in sys.platform:
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        asyncio.run(self.async_test())

    async def async_test(self):
        node = self.nodes[0]

        # new wallet
        async with WalletRpcController(node, self.config, self.log) as wallet:
            await wallet.create_wallet('alice_wallet')

            # check it is on genesis
            assert_equal('0', await wallet.get_best_block_height())

            # new addresses for both accounts to have some coins
            alice_address = await wallet.new_address()
            alice_pub_key = await wallet.reveal_public_key_as_address(alice_address)
            alice_pub_key_bytes = await wallet.new_public_key(alice_address)
            alice_pub_key_hex = await wallet.reveal_public_key_as_hex(alice_address)
            assert_equal(len(alice_pub_key_bytes), 33)

            await wallet.close_wallet()
            await wallet.create_wallet('bob_wallet')

            bob_address = await wallet.new_address()
            bob_pub_key = await wallet.reveal_public_key_as_address(bob_address)
            bob_pub_key_bytes = await wallet.new_public_key(bob_address)
            bob_pub_key_hex = await wallet.reveal_public_key_as_hex(bob_address)
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
            assert_in("Coins amount: 151", balance)
            assert_not_in("Tokens", balance)

            # issue a valid token
            token_id, _, _ = (await wallet.issue_new_token("XXXX", 2, "http://uri", alice_address))
            assert token_id is not None
            self.log.info(f"new token id: {token_id}")

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
            balance = await wallet.get_balance()
            assert_in("Coins amount: 0", balance)
            assert_in(f"Token: {token_id} amount: {amount_to_mint}", balance)

            ########################################################################################
            # Setup Alice's htlc
            alice_secret = bytes([random.randint(0, 255) for _ in range(32)])
            alice_secret_hex = alice_secret.hex()
            alice_secret_hash = hash160(alice_secret).hex()

            alice_amount_to_swap = amount_to_mint
            refund_address = await wallet.add_standalone_multisig_address(2, [alice_pub_key, bob_pub_key], None)
            alice_htlc_tx = await wallet.create_htlc_transaction(alice_amount_to_swap, token_id, alice_secret_hash, bob_address, refund_address, 2)
            output = await wallet.submit_transaction(alice_htlc_tx['tx'])
            alice_htlc_tx_id = output.split('\n')[2]
            self.generate_block()
            assert_in("Success", await wallet.sync())

            # Setup Bob's htlc
            await self.switch_to_wallet(wallet, 'bob_wallet')
            assert_in("Success", await wallet.sync())

            bob_amount_to_swap = 150
            bob_htlc_tx = await wallet.create_htlc_transaction(bob_amount_to_swap, None, alice_secret_hash, alice_address, refund_address, 2)
            output = await wallet.submit_transaction(bob_htlc_tx['tx'])
            bob_htlc_tx_id = output.split('\n')[2]
            self.generate_block()
            assert_in("Success", await wallet.sync())

            ########################################################################################
            # Try spending
            await self.switch_to_wallet(wallet, 'alice_wallet')
            assert_in("Success", await wallet.sync())

            random_secret = bytes([random.randint(0, 255) for _ in range(32)])
            random_secret_hex = random_secret.hex()

            balance = await wallet.get_balance()
            assert_in("Coins amount: 0", balance)
            assert_not_in("Tokens", balance)

            # Alice can't spend Alice's htlc without a secret
            token_id_hex = node.test_functions_reveal_token_id(token_id)
            tx_output = TransferTxOutput(alice_amount_to_swap * ATOMS_PER_TOKEN, alice_pub_key_hex, token_id_hex)
            result = await wallet.compose_transaction([tx_output], [UtxoOutpoint(alice_htlc_tx_id, 0)], [None])
            output = await wallet.sign_raw_transaction(result['result']['hex'])
            assert_in("Not all transaction inputs have been signed", output)

            # Alice can't spend Alice's htlc with incorrect secret
            result = await wallet.compose_transaction([tx_output], [UtxoOutpoint(alice_htlc_tx_id, 0)], [random_secret_hex])
            output = await wallet.sign_raw_transaction(result['result']['hex'])
            assert_in("Not all transaction inputs have been signed", output)

            # Alice can't spend Alice's htlc with correct secret
            result = await wallet.compose_transaction([tx_output], [UtxoOutpoint(alice_htlc_tx_id, 0)], [alice_secret_hex])
            output = await wallet.sign_raw_transaction(result['result']['hex'])
            assert_in("Not all transaction inputs have been signed", output)

            ########################################################################################
            await self.switch_to_wallet(wallet, 'bob_wallet')
            assert_in("Success", await wallet.sync())

            balance = await wallet.get_balance()
            assert_in("Coins amount: 0", balance)
            assert_not_in("Tokens", balance)

            # Bob can't spend it without secret
            result = await wallet.compose_transaction([tx_output], [UtxoOutpoint(alice_htlc_tx_id, 0)], [None])
            output = await wallet.sign_raw_transaction(result['result']['hex'])
            assert_in("The transaction has been fully signed and is ready to be broadcast to network", output)
            signed_tx = output.split('\n')[2]
            output = await wallet.submit_transaction(signed_tx)
            assert_in("Signature decoding failed", output)
            # Bob can't spend it with incorrect secret
            result = await wallet.compose_transaction([tx_output], [UtxoOutpoint(alice_htlc_tx_id, 0)], [random_secret_hex])
            output = await wallet.sign_raw_transaction(result['result']['hex'])
            assert_in("The transaction has been fully signed and is ready to be broadcast to network", output)
            signed_tx = output.split('\n')[2]
            output = await wallet.submit_transaction(signed_tx)
            assert_in("Preimage doesn't match the hash", output)

            ########################################################################################
            await self.switch_to_wallet(wallet, 'alice_wallet')
            assert_in("Success", await wallet.sync())

            #Alice can't spend Bob's htlc without a secret
            tx_output = TransferTxOutput(bob_amount_to_swap * ATOMS_PER_COIN, alice_pub_key_hex, None)
            result = await wallet.compose_transaction([tx_output], [UtxoOutpoint(bob_htlc_tx_id, 0)], [None])
            output = await wallet.sign_raw_transaction(result['result']['hex'])
            assert_in("The transaction has been fully signed and is ready to be broadcast to network", output)
            signed_tx = output.split('\n')[2]
            output = await wallet.submit_transaction(signed_tx)
            assert_in("Signature decoding failed", output)
            # Alice can't spend it with incorrect secret
            result = await wallet.compose_transaction([tx_output], [UtxoOutpoint(bob_htlc_tx_id, 0)], [random_secret_hex])
            output = await wallet.sign_raw_transaction(result['result']['hex'])
            assert_in("The transaction has been fully signed and is ready to be broadcast to network", output)
            signed_tx = output.split('\n')[2]
            output = await wallet.submit_transaction(signed_tx)
            assert_in("Preimage doesn't match the hash", output)
            # Alice can only spend Bob's htlc by revealing a proper secret
            result = await wallet.compose_transaction([tx_output], [UtxoOutpoint(bob_htlc_tx_id, 0), UtxoOutpoint(alice_htlc_tx_id, 1)], [alice_secret_hex, None])
            output = await wallet.sign_raw_transaction(result['result']['hex'])
            assert_in("The transaction has been fully signed and is ready to be broadcast to network", output)
            signed_tx = output.split('\n')[2]
            result_secret = node.test_functions_extract_htlc_secret(signed_tx, UtxoOutpoint(bob_htlc_tx_id, 0).to_json())
            assert_equal(result_secret, alice_secret_hex)
            output = await wallet.submit_transaction(signed_tx)
            assert_in("The transaction was submitted successfully", output)
            self.generate_block()
            assert_in("Success", await wallet.sync())

            balance = await wallet.get_balance()
            assert_in(f"Coins amount: {bob_amount_to_swap}", balance)
            assert_not_in("Tokens", balance)

            ########################################################################################
            await self.switch_to_wallet(wallet, 'bob_wallet')
            assert_in("Success", await wallet.sync())

            # Now Bob can spend Alice's htlc with extracted secret
            tx_output = TransferTxOutput(alice_amount_to_swap * ATOMS_PER_TOKEN, bob_pub_key_hex, token_id_hex)
            result = await wallet.compose_transaction([tx_output], [UtxoOutpoint(alice_htlc_tx_id, 0), UtxoOutpoint(bob_htlc_tx_id, 1)], [alice_secret_hex, None])
            output = await wallet.sign_raw_transaction(result['result']['hex'])
            assert_in("The transaction has been fully signed and is ready to be broadcast to network", output)
            signed_tx = output.split('\n')[2]
            output = await wallet.submit_transaction(signed_tx)
            assert_in("The transaction was submitted successfully", output)
            self.generate_block()
            assert_in("Success", await wallet.sync())

            balance = await wallet.get_balance()
            assert_in("Coins amount: 0", balance)
            assert_in(f"Token: {token_id} amount: {alice_amount_to_swap}", balance)


if __name__ == '__main__':
    WalletHtlcSpend().main()
