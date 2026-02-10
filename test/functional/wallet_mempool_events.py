#!/usr/bin/env python3
#  Copyright (c) 2026 RBB S.r.l
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
"""Wallet mempool events test

Check that:
* We create 2 wallets with same mnemonic,
* get an address from the first wallet
* send coins to the wallet's address
* sync both wallets with the node
* check balance in both wallets
* from the first wallet send coins from Acc 0 to Acc 1 without creating a block
* the second wallet should get the new Tx from mempool events
* second wallet can create a new unconfirmed Tx on top of the Tx in mempool
"""

import asyncio

from test_framework.mintlayer import (ATOMS_PER_COIN, block_input_data_obj,
                                      make_tx, reward_input)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_in
from test_framework.wallet_cli_controller import (DEFAULT_ACCOUNT_INDEX,
                                                  WalletCliController)


class WalletMempoolEvents(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [
            [
                "--blockprod-min-peers-to-produce-blocks=0",
            ]
        ]

    def setup_network(self):
        self.setup_nodes()
        self.sync_all(self.nodes[0:1])

    def generate_block(self, transactions=[]):
        node = self.nodes[0]

        block_input_data = {"PoW": {"reward_destination": "AnyoneCanSpend"}}
        block_input_data = block_input_data_obj.encode(block_input_data).to_hex()[2:]

        # create a new block, taking transactions from mempool
        block = node.blockprod_generate_block(
            block_input_data, transactions, [], "FillSpaceFromMempool"
        )
        node.chainstate_submit_block(block)
        block_id = node.chainstate_best_block_id()

        # Wait for mempool to sync
        self.wait_until(
            lambda: node.mempool_local_best_block_id() == block_id, timeout=5
        )

        return block_id

    def run_test(self):
        asyncio.run(self.async_test())

    async def async_test(self):
        node = self.nodes[0]
        async with WalletCliController(
            node, self.config, self.log
        ) as wallet, WalletCliController(node, self.config, self.log) as wallet2:
            # new wallet
            await wallet.create_wallet()
            # create wallet2 with the same mnemonic
            mnemonic = await wallet.show_seed_phrase()
            assert mnemonic is not None
            assert_in(
                "Wallet recovered successfully", await wallet2.recover_wallet(mnemonic)
            )

            # check it is on genesis
            best_block_height = await wallet.get_best_block_height()
            self.log.info(f"best block height = {best_block_height}")
            assert_equal(best_block_height, "0")
            best_block_height = await wallet2.get_best_block_height()
            assert_equal(best_block_height, "0")

            # new address
            pub_key_bytes = await wallet.new_public_key()
            assert_equal(len(pub_key_bytes), 33)

            # Get chain tip
            tip_id = node.chainstate_best_block_id()

            # Submit a valid transaction
            token_fee = 1000
            coins_to_send = 1
            token_fee_output = {
                "Transfer": [
                    {"Coin": token_fee * ATOMS_PER_COIN},
                    {
                        "PublicKey": {
                            "key": {"Secp256k1Schnorr": {"pubkey_data": pub_key_bytes}}
                        }
                    },
                ],
            }
            tx_fee_output = {
                "Transfer": [
                    {"Coin": coins_to_send * ATOMS_PER_COIN},
                    {
                        "PublicKey": {
                            "key": {"Secp256k1Schnorr": {"pubkey_data": pub_key_bytes}}
                        }
                    },
                ],
            }
            encoded_tx, tx_id = make_tx(
                [reward_input(tip_id)], [token_fee_output] + [tx_fee_output] * 2, 0
            )

            self.log.debug(f"Encoded transaction {tx_id}: {encoded_tx}")

            assert_in("No transaction found", await wallet.get_transaction(tx_id))

            node.mempool_submit_transaction(encoded_tx, {})
            assert node.mempool_contains_tx(tx_id)

            self.generate_block()
            assert not node.mempool_contains_tx(tx_id)

            # sync the wallet
            assert_in("Success", await wallet.sync())
            assert_in("Success", await wallet2.sync())

            acc0_address = await wallet.new_address()

            # both wallets have the same balances after syncing the new block
            assert_in(
                f"Coins amount: {coins_to_send * 2 + token_fee}",
                await wallet.get_balance(),
            )
            assert_in(
                f"Coins amount: {coins_to_send * 2 + token_fee}",
                await wallet2.get_balance(),
            )

            # create new account and get an address
            assert_in("Success", await wallet.create_new_account())
            assert_in("Success", await wallet2.create_new_account())
            assert_in("Success", await wallet.select_account(1))
            acc1_address = await wallet.new_address()

            # go back to Acc 0 and send 1 coin to Acc 1
            coins_to_send = 2
            assert_in("Success", await wallet.select_account(DEFAULT_ACCOUNT_INDEX))
            assert_in(
                "The transaction was submitted successfully",
                await wallet.send_to_address(acc1_address, coins_to_send),
            )

            # check mempool has 1 transaction now
            transactions = node.mempool_transactions()
            assert_equal(len(transactions), 1)

            # check wallet 1 has it as pending
            pending_txs = await wallet.list_pending_transactions()
            assert_equal(1, len(pending_txs))
            transfer_tx_id = pending_txs[0]

            # check wallet 2 also received it from mempool events
            pending_txs = await wallet2.list_pending_transactions()
            assert_equal(1, len(pending_txs))
            assert_equal(transfer_tx_id, pending_txs[0])

            assert_in("Success", await wallet.select_account(1))
            # wallet 2 should automatically recover Acc 1
            assert_in("Success", await wallet2.select_account(1))

            # check both balances have `coins_to_send` coins in-mempool state
            assert_in(
                f"Coins amount: {coins_to_send}",
                await wallet.get_balance(utxo_states=["in-mempool"]),
            )
            assert_in(
                f"Coins amount: {coins_to_send}",
                await wallet2.get_balance(utxo_states=["in-mempool"]),
            )

            # check wallet2 can send 1 coin back to Acc0 from the not yet confirmed tx in mempool
            assert_in(
                "The transaction was submitted successfully",
                await wallet2.send_to_address(acc0_address, 1),
            )

            self.generate_block()

            assert_in("Success", await wallet.sync())
            assert_in("Success", await wallet2.sync())


if __name__ == "__main__":
    WalletMempoolEvents().main()
