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
"""Wallet watch standalone address test

Check that:
* We can create a new wallet,
* get an address
* send coins to the wallet's address
* create a new wallet
* add an address from wallet 1 to wallet 2 to be watched
* send coins to wallet 1's address
* check that wallet 2 is keeping truck of transactions using that address in inputs or outputs
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import (make_tx, reward_input, ATOMS_PER_COIN)
from test_framework.util import assert_in, assert_equal, assert_not_in
from test_framework.mintlayer import block_input_data_obj
from test_framework.wallet_cli_controller import WalletCliController

import asyncio
import sys
import random


class WalletSubmitTransaction(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        relay_fee_rate = random.randint(1, 100_000_000)
        self.extra_args = [[
            "--blockprod-min-peers-to-produce-blocks=0",
            f"--min-tx-relay-fee-rate={relay_fee_rate}",
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
            await wallet.create_wallet('wallet1')

            # check it is on genesis
            best_block_height = await wallet.get_best_block_height()
            self.log.info(f"best block height = {best_block_height}")
            assert_equal(best_block_height, '0')

            # new address
            pub_key_bytes = await wallet.new_public_key()
            assert_equal(len(pub_key_bytes), 33)

            # Get chain tip
            tip_id = node.chainstate_best_block_id()
            self.log.debug(f'Tip: {tip_id}')

            # Submit a valid transaction
            coins_to_send = random.randint(2, 100)
            output = {
                    'Transfer': [ { 'Coin': coins_to_send * ATOMS_PER_COIN }, { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': pub_key_bytes}}} } ],
            }
            encoded_tx, receive_coins_tx_id = make_tx([reward_input(tip_id)], [output], 0)

            self.log.debug(f"Encoded transaction {receive_coins_tx_id}: {encoded_tx}")

            assert_in("No transaction found", await wallet.get_transaction(receive_coins_tx_id))

            store_tx_in_wallet = random.choice([True, False])
            assert_in("The transaction was submitted successfully", await wallet.submit_transaction(encoded_tx, not store_tx_in_wallet))

            if store_tx_in_wallet:
                assert_in(f"Coins amount: {coins_to_send}", await wallet.get_balance(utxo_states=['inactive']))
            else:
                assert_in("Coins amount: 0", await wallet.get_balance(utxo_states=['inactive']))

            assert node.mempool_contains_tx(receive_coins_tx_id)

            block_id = self.generate_block() # Block 1
            assert not node.mempool_contains_tx(receive_coins_tx_id)

            # sync the wallet
            assert_in("Success", await wallet.sync())

            # check wallet best block if it is synced
            best_block_height = await wallet.get_best_block_height()
            assert_equal(best_block_height, '1')

            best_block_id = await wallet.get_best_block()
            assert_equal(best_block_id, block_id)

            # create a new account and get an address from it
            await wallet.create_new_account()
            await wallet.select_account(1)
            address_from_wallet1 = await wallet.new_address()


            await wallet.close_wallet()
            await wallet.create_wallet('wallet2')
            assert_in("Success", await wallet.sync())

            label = 'some_label' if random.choice([True, False]) else None
            assert_in("Success, the new address has been added to the account", await wallet.add_standalone_address(address_from_wallet1, label))

            await wallet.close_wallet()
            await wallet.open_wallet('wallet1')

            # send coins to that address
            output = await wallet.send_to_address(address_from_wallet1, 1)
            assert_in("The transaction was submitted successfully", output)
            receive_coins_tx_id = output.splitlines()[-1]

            # check in wallet2
            await wallet.close_wallet()
            await wallet.open_wallet('wallet2')

            # tx is still in mempool
            assert node.mempool_contains_tx(receive_coins_tx_id)

            assert_in("No transaction found", await wallet.get_raw_signed_transaction(receive_coins_tx_id))

            block_id = self.generate_block()
            assert not node.mempool_contains_tx(receive_coins_tx_id)
            assert_in("Success", await wallet.sync())

            # after syncing the tx should be found
            assert_not_in("No transaction found", await wallet.get_raw_signed_transaction(receive_coins_tx_id))


            # go back to wallet 1
            await wallet.close_wallet()
            await wallet.open_wallet('wallet1')

            # send coins from that address to another one
            await wallet.select_account(1)
            other_address = await wallet.new_address()
            output = await wallet.send_to_address(other_address, 0.1)
            assert_in("The transaction was submitted successfully", output)
            send_coins_tx_id = output.splitlines()[-1]


            # go back to wallet 2
            await wallet.close_wallet()
            await wallet.open_wallet('wallet2')

            # tx is still in mempool
            assert node.mempool_contains_tx(send_coins_tx_id)

            assert_in("No transaction found", await wallet.get_raw_signed_transaction(send_coins_tx_id))

            block_id = self.generate_block()
            assert not node.mempool_contains_tx(send_coins_tx_id)
            assert_in("Success", await wallet.sync())

            # after syncing the tx should be found
            assert_not_in("No transaction found", await wallet.get_raw_signed_transaction(send_coins_tx_id))

            output = await wallet.get_standalone_addresses()
            assert_in(address_from_wallet1, output)
            if label:
                assert_in(label, output)


if __name__ == '__main__':
    WalletSubmitTransaction().main()

