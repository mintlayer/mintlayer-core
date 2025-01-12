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
"""Wallet htlc refund test

* Create 2 wallets for Alice and Bob
* Alice mints some tokens and creates an output that locks that tokens in htlc
* Bob creates an output that locks coins in htlc
*
* Check resulting balances
"""

from scalecodec.base import ScaleBytes
from test_framework.script import hash160
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import (hash_object, hex_to_dec_array, make_tx, make_tx_dict, reward_input, ATOMS_PER_COIN, tx_input)
from test_framework.util import assert_in, assert_equal, assert_not_in
from test_framework.mintlayer import  block_input_data_obj, signed_tx_obj, base_tx_obj
from test_framework.wallet_rpc_controller import WalletRpcController

import asyncio
import sys
import scalecodec
import random

ATOMS_PER_TOKEN = 100

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
            assert_equal(len(alice_pub_key_bytes), 33)

            await wallet.close_wallet()
            await wallet.create_wallet('bob_wallet')

            bob_address = await wallet.new_address()
            bob_pub_key = await wallet.reveal_public_key_as_address(bob_address)
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
            token_ticker = "XXXX"
            token_number_of_decimals = 2
            token_id, _ = (await wallet.issue_new_token(token_ticker, token_number_of_decimals, "http://uri", alice_address))
            assert token_id is not None
            self.log.info(f"new token id: {token_id}")
            token_id_hex = node.test_functions_reveal_token_id(token_id)

            self.generate_block()
            assert_in("Success", await wallet.sync())
            balance = await wallet.get_balance()
            assert_in(f"Coins amount: 50", balance)
            assert_not_in("Tokens", balance)

            amount_to_mint = random.randint(1, 10000)
            mint_result = await wallet.mint_tokens(token_id, alice_address, amount_to_mint)
            assert mint_result['tx_id'] is not None

            self.generate_block()
            assert_in("Success", await wallet.sync())
            balance = await wallet.get_balance()
            print(balance)
            assert_in(f"Coins amount: 0", balance)
            assert_in(f"Token: {token_id} amount: {amount_to_mint}", balance)

            ########################################################################################
            # Setup Alice's htlc
            alice_secret = bytes([random.randint(0, 255) for _ in range(32)])
            alice_secret_hash = hash160(alice_secret).hex()

            refund_address = await wallet.add_standalone_multisig_address(2, [alice_pub_key, bob_pub_key], None)

            alice_amount_to_swap = amount_to_mint
            alice_htlc_tx = await wallet.create_htlc_transaction(alice_amount_to_swap, token_id, alice_secret_hash, bob_address, refund_address, 6)
            alice_signed_tx_obj = signed_tx_obj.decode(ScaleBytes("0x" + alice_htlc_tx))
            alice_htlc_outputs = alice_signed_tx_obj['transaction']['outputs']
            alice_htlc_change_dest = alice_htlc_outputs[1]['Transfer'][1]
            alice_htlc_tx_id = hash_object(base_tx_obj, alice_signed_tx_obj['transaction'])

            refund_dest = node.test_functions_address_to_destination(refund_address)
            refund_dest_obj = scalecodec.base.RuntimeConfiguration().create_scale_object('Destination', ScaleBytes("0x"+refund_dest))
            refund_dest_obj = refund_dest_obj.decode()

            # Create Alice's refund transaction
            token_id_hex = node.test_functions_reveal_token_id(token_id)
            output = {
                    'Transfer': [ { 'TokenV1': [hex_to_dec_array(token_id_hex), alice_amount_to_swap * ATOMS_PER_TOKEN] },
                                  { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': alice_pub_key_bytes}}} } ],
            }
            tx = make_tx_dict([tx_input(alice_htlc_tx_id, 0), tx_input(alice_htlc_tx_id, 1)], [output])
            alice_refund_ptx = {
                'tx': tx['transaction'],
                'witnesses': [None, None],
                'input_utxos': alice_htlc_outputs,
                'destinations': [refund_dest_obj, alice_htlc_change_dest],
                'htlc_secrets': [None, None],
                'additional_infos': {'token_info': [], 'pool_info': [], 'order_info': []}
            }
            alice_refund_tx_hex = scalecodec.base.RuntimeConfiguration().create_scale_object('PartiallySignedTransaction').encode(alice_refund_ptx).to_hex()[2:]

            ########################################################################################
            # Setup Bob's htlc
            await self.switch_to_wallet(wallet, 'bob_wallet')
            assert_in("Success", await wallet.sync())

            await wallet.add_standalone_multisig_address(2, [alice_pub_key, bob_pub_key], None)

            bob_amount_to_swap = 150
            bob_htlc_tx = await wallet.create_htlc_transaction(bob_amount_to_swap, None, alice_secret_hash, alice_address, refund_address, 6)
            bob_signed_tx_obj = signed_tx_obj.decode(ScaleBytes("0x" + bob_htlc_tx))
            bob_htlc_outputs = bob_signed_tx_obj['transaction']['outputs']
            bob_htlc_change_dest = bob_htlc_outputs[1]['Transfer'][1]
            bob_htlc_tx_id = hash_object(base_tx_obj, bob_signed_tx_obj['transaction'])

            # Create Bob's refund transaction
            output = {
                    'Transfer': [ { 'Coin': bob_amount_to_swap * ATOMS_PER_COIN }, { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': bob_pub_key_bytes}}} } ],
            }
            tx = make_tx_dict([tx_input(bob_htlc_tx_id, 0), tx_input(bob_htlc_tx_id, 1)], [output])
            bob_refund_ptx = {
                'tx': tx['transaction'],
                'witnesses': [None, None],
                'input_utxos': bob_htlc_outputs,
                'destinations': [refund_dest_obj, bob_htlc_change_dest],
                'htlc_secrets': [None, None],
                'additional_infos': {'token_info': [], 'pool_info': [], 'order_info': []}
            }
            bob_refund_tx_hex = scalecodec.base.RuntimeConfiguration().create_scale_object('PartiallySignedTransaction').encode(bob_refund_ptx).to_hex()[2:]

            ########################################################################################
            # Bob signs Alice's refund
            output = await wallet.sign_raw_transaction(alice_refund_tx_hex)
            assert_in("Not all transaction inputs have been signed", output)
            alice_refund_ptx = output.split('\n')[2]

            # Alice's htlc tx can now be broadcasted
            output = await wallet.submit_transaction(alice_htlc_tx)
            assert_in("The transaction was submitted successfully", output)

            # Alice signs Bob's refund
            await self.switch_to_wallet(wallet, 'alice_wallet')
            assert_in("Success", await wallet.sync())
            output = await wallet.sign_raw_transaction(bob_refund_tx_hex)
            assert_in("Not all transaction inputs have been signed", output)
            bob_refund_ptx = output.split('\n')[2]

            # Bob's htlc tx can now be broadcasted
            output = await wallet.submit_transaction(bob_htlc_tx)
            assert_in("The transaction was submitted successfully", output)

            self.generate_block()
            assert_in("Success", await wallet.sync())

            # Check Alice's balance
            balance = await wallet.get_balance()
            assert_in(f"Coins amount: 0", balance)
            assert_not_in("Tokens", balance)

            # Check Bob's balance now
            await self.switch_to_wallet(wallet, 'bob_wallet')
            assert_in("Success", await wallet.sync())
            balance = await wallet.get_balance()
            assert_in(f"Coins amount: 0", balance)
            assert_not_in("Tokens", balance)

            ########################################################################################
            # Alice signs the refund
            await self.switch_to_wallet(wallet, 'alice_wallet')
            assert_in("Success", await wallet.sync())
            output = await wallet.sign_raw_transaction(alice_refund_ptx)
            assert_in("The transaction has been fully signed and is ready to be broadcast to network", output)

            # But Alice's refund cannot be spent yet due to the timelock
            alice_refund_tx = output.split('\n')[2]
            output = await wallet.submit_transaction(alice_refund_tx)
            # spending height is 9 and not 5 as expected because of mempool's FUTURE_TIMELOCK_TOLERANCE_BLOCKS
            assert_in("Spending at height 9, locked until height 10", output)

            balance = await wallet.get_balance()
            assert_in(f"Coins amount: 0", balance)
            assert_not_in("Tokens", balance)

            # Bob signs and spends the refund
            await self.switch_to_wallet(wallet, 'bob_wallet')
            assert_in("Success", await wallet.sync())
            output = await wallet.sign_raw_transaction(bob_refund_ptx)
            assert_in("The transaction has been fully signed and is ready to be broadcast to network", output)
            bob_refund_tx = output.split('\n')[2]

            # But Bob's refund cannot be spent yet due to the timelock
            output = await wallet.submit_transaction(bob_refund_tx)
            # spending height is 9 and not 5 as expected because of mempool's FUTURE_TIMELOCK_TOLERANCE_BLOCKS
            assert_in("Spending at height 9, locked until height 10", output)

            balance = await wallet.get_balance()
            assert_in(f"Coins amount: 0", balance)
            assert_not_in("Tokens", balance)

            ########################################################################################
            # Generate a block so that txs can get into mempool
            self.generate_block()
            assert_in("Success", await wallet.sync())
            output = await wallet.submit_transaction(alice_refund_tx)
            tx_id = output.split('\n')[2]
            assert node.mempool_contains_tx(tx_id)
            output = await wallet.submit_transaction(bob_refund_tx)
            tx_id = output.split('\n')[2]
            assert node.mempool_contains_tx(tx_id)

            # tx won't get into blockchain because of timelock
            self.generate_block()
            assert_in("Success", await wallet.sync())
            balance = await wallet.get_balance()
            assert_in(f"Coins amount: 0", balance)
            assert_not_in("Tokens", balance)

            self.generate_block()
            self.generate_block()
            self.generate_block()
            self.generate_block()

            # now check that fund got back to original owners
            await self.switch_to_wallet(wallet, 'alice_wallet')
            assert_in("Success", await wallet.sync())
            balance = await wallet.get_balance()
            assert_in(f"Coins amount: 0", balance)
            assert_in(f"Token: {token_id} amount: {alice_amount_to_swap}", balance)

            await self.switch_to_wallet(wallet, 'bob_wallet')
            assert_in("Success", await wallet.sync())
            balance = await wallet.get_balance()
            assert_in(f"Coins amount: 150", balance)
            assert_not_in("Tokens", balance)


if __name__ == '__main__':
    WalletHtlcRefund().main()
