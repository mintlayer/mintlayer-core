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
"""Wallet conflict tx test

Check that:
* We can create a new wallet,
* get an address
* send coins to the wallet's address
* sync the wallet with the node
* check balance
* create a token
* create 2 txs 1 to send tokens and 1 to freeze the token
* put the freeze tx in a block, the transfer should be rejected and conflicting in the wallet
"""

import json
from scalecodec.base import ScaleBytes
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import (make_tx, reward_input, ATOMS_PER_COIN, signed_tx_obj)
from test_framework.util import assert_in, assert_equal
from test_framework.mintlayer import mintlayer_hash, block_input_data_obj
from test_framework.wallet_cli_controller import WalletCliController, DEFAULT_ACCOUNT_INDEX

import asyncio
import sys
import random


class WalletConflictTransaction(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            "--blockprod-min-peers-to-produce-blocks=0",
        ]]

    def setup_network(self):
        self.setup_nodes()
        self.sync_all(self.nodes[0:1])

    def generate_block(self, transactions = []):
        node = self.nodes[0]

        block_input_data = { "PoW": { "reward_destination": "AnyoneCanSpend" } }
        block_input_data = block_input_data_obj.encode(block_input_data).to_hex()[2:]

        # create a new block, taking transactions from mempool
        block = node.blockprod_generate_block(block_input_data, transactions, [], "FillSpaceFromMempool")
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

            # new address
            pub_key_bytes = await wallet.new_public_key()
            assert_equal(len(pub_key_bytes), 33)

            # Get chain tip
            tip_id = node.chainstate_best_block_id()

            # Submit a valid transaction
            token_fee = 1000
            coins_to_send = 1
            token_fee_output = {
                    'Transfer': [ { 'Coin': token_fee * ATOMS_PER_COIN }, { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': pub_key_bytes}}} } ],
            }
            tx_fee_output = {
                    'Transfer': [ { 'Coin': coins_to_send * ATOMS_PER_COIN }, { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': pub_key_bytes}}} } ],
            }
            encoded_tx, tx_id = make_tx([reward_input(tip_id)], [token_fee_output] + [tx_fee_output] * 2, 0)

            self.log.debug(f"Encoded transaction {tx_id}: {encoded_tx}")

            assert_in("No transaction found", await wallet.get_transaction(tx_id))

            node.mempool_submit_transaction(encoded_tx, {})
            assert node.mempool_contains_tx(tx_id)

            self.generate_block()
            assert not node.mempool_contains_tx(tx_id)

            # sync the wallet
            assert_in("Success", await wallet.sync())

            assert_in(f"Coins amount: {coins_to_send * 2 + token_fee}", await wallet.get_balance())

            address = await wallet.new_address()
            token_id, tx_id, err = await wallet.issue_new_token("XXX", 2, "http://uri", address)
            assert token_id is not None
            assert tx_id is not None
            assert err is None

            self.generate_block()
            assert_in("Success", await wallet.sync())

            # create new account and get an address
            assert_in("Success", await wallet.create_new_account())
            assert_in("Success", await wallet.select_account(1))
            acc1_address = await wallet.new_address()
            assert_in("Success", await wallet.select_account(DEFAULT_ACCOUNT_INDEX))

            tokens_to_mint = 10000
            assert_in("The transaction was submitted successfully", await wallet.mint_tokens(token_id, acc1_address, tokens_to_mint))
            assert_in("The transaction was submitted successfully", await wallet.send_to_address(acc1_address, 1))


            self.generate_block()
            assert_in("Success", await wallet.sync())


            # now send tokens from acc1 and freeze the tokens from default acc
            assert_in("Success", await wallet.select_account(1))
            assert_in(f"{token_id} amount: {tokens_to_mint}", await wallet.get_balance())
            assert_in("The transaction was submitted successfully", await wallet.send_tokens_to_address(token_id, address, tokens_to_mint))
            transactions = node.mempool_transactions()
            assert_equal(len(transactions), 1)
            transfer_tx = transactions[0]
            pending_txs = await wallet.list_pending_transactions()
            assert_equal(1, len(pending_txs))
            transfer_tx_id = pending_txs[0]

            assert_in("Success", await wallet.select_account(DEFAULT_ACCOUNT_INDEX))
            assert_in("The transaction was submitted successfully", await wallet.freeze_token(token_id, "unfreezable"))
            transactions = node.mempool_transactions()
            assert_equal(len(transactions), 2)
            transactions.remove(transfer_tx)
            freeze_tx = transactions[0]

            assert_equal(1, len(await wallet.list_pending_transactions()))


            # try to send tokens again should fail as the tokens are already sent
            assert_in("Success", await wallet.select_account(1))
            assert_in("Coin selection error: No available UTXOs", await wallet.send_tokens_to_address(token_id, address, tokens_to_mint))
            # check that the mempool still has the transfer tx
            assert node.mempool_contains_tx(transfer_tx_id)
            # abandon it from the wallet side so it is not rebroadcasted
            assert_in("The transaction was marked as abandoned successfully", await wallet.abandon_transaction(transfer_tx_id))

            # create a block with the freeze token transaction
            self.generate_block([freeze_tx])
            assert_in("Success", await wallet.sync())

            # after the token is frozen the transfer token tx should be evicted by the mempool as conflicting
            # wait until mempool evicts the conflicting tx
            self.wait_until(lambda: not node.mempool_contains_tx(transfer_tx_id), timeout = 5)

            assert_in("Success", await wallet.select_account(DEFAULT_ACCOUNT_INDEX))
            assert_in("The transaction was submitted successfully", await wallet.unfreeze_token(token_id))
            self.generate_block()
            assert_in("Success", await wallet.sync())

            assert_in("Success", await wallet.select_account(1))
            assert_in("The transaction was submitted successfully", await wallet.send_tokens_to_address(token_id, address, 10))

            pending_txs = await wallet.list_pending_transactions()
            assert_equal(1, len(pending_txs))
            new_transfer_tx_id = pending_txs[0]

            self.generate_block()
            assert_in("Success", await wallet.sync())

            assert_in("Success", await wallet.select_account(DEFAULT_ACCOUNT_INDEX))
            assert_in(f"{token_id} amount: 10", await wallet.get_balance())

            # check we cannot abandon an already confirmed transaction
            assert_in("Success", await wallet.select_account(1))
            assert_in("Cannot change a transaction's state from Confirmed", await wallet.abandon_transaction(new_transfer_tx_id))



if __name__ == '__main__':
    WalletConflictTransaction().main()
