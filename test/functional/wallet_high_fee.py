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
"""Wallet high fee submission test

Check that:
* We can create a new wallet,
* get an address
* send coins to the wallet's address
* sync the wallet with the node
* check balance
* submit many txs with high fee
* try to spend coins from the wallet should fail
"""

from time import time
import scalecodec
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import (calc_tx_id, make_tx_dict, reward_input, tx_input, ATOMS_PER_COIN, tx_output)
from test_framework.util import assert_greater_than, assert_in, assert_equal
from test_framework.mintlayer import mintlayer_hash, block_input_data_obj
from test_framework.wallet_cli_controller import WalletCliController

import asyncio
import sys

class WalletSubmitTransaction(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            "--blockprod-min-peers-to-produce-blocks=0",
        ]]

    def setup_network(self):
        self.setup_nodes()
        self.sync_all(self.nodes[0:1])

    def make_tx(self, inputs, outputs, flags = 0, calc_id = True):
        self.log.info(f"making tx")
        signed_tx = make_tx_dict(inputs, outputs, flags)
        self.log.info(f"calc tx id")
        tx_id = calc_tx_id(signed_tx) if calc_id else None
        self.log.info(f"obj")
        signed_tx_obj = scalecodec.base.RuntimeConfiguration().create_scale_object('SignedTransaction')
        self.log.info(f"encode")
        encoded_tx = signed_tx_obj.encode(signed_tx).to_hex()[2:]
        return (encoded_tx, tx_id)


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
        async with WalletCliController(node, self.config, self.log, ["--in-top-x-mb", "1"]) as wallet:
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
            self.log.debug(f'Tip: {tip_id}')

            # Submit a valid transaction
            output = {
                    'Transfer': [ { 'Coin': 10 * ATOMS_PER_COIN }, { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': pub_key_bytes}}} } ],
            }
            inputs = list(range(5))
            total = 300000//len(inputs)
            output2 = {
                'Transfer': [ { 'Coin': total * ATOMS_PER_COIN }, { 'AnyoneCanSpend': None } ],
            }
            encoded_tx, tx_id = self.make_tx([reward_input(tip_id)], [output2] * len(inputs) + [output], 0)

            self.log.debug(f"Encoded transaction {tx_id}: {encoded_tx}")

            node.mempool_submit_transaction(encoded_tx, {})
            assert node.mempool_contains_tx(tx_id)

            block_id = self.generate_block() # Block 1
            assert not node.mempool_contains_tx(tx_id)

            # sync the wallet
            output = await wallet.sync()
            assert_in("Success", output)

            # check wallet best block if it is synced
            best_block_height = await wallet.get_best_block_height()
            assert_equal(best_block_height, '1')

            best_block_id = await wallet.get_best_block()
            assert_equal(best_block_id, block_id)

            balance = await wallet.get_balance()
            assert_in("Coins amount: 10", balance)

            # check fee rate before inserting txs
            output = node.mempool_get_fee_rate(1)
            assert_equal(int(output['amount_per_kb']['atoms']), 1000)

            total_size_of_txs_in_mempool = 0
            for inp_idx in inputs:
                transactions = node.test_functions_generate_transactions(tx_id, inp_idx, 5, total - 300, 300)
                for encoded_tx in transactions:
                    node.mempool_submit_transaction(encoded_tx, {})
                    total_size_of_txs_in_mempool += len(bytes.fromhex(encoded_tx))


            self.log.info(f"total size {total_size_of_txs_in_mempool}")
            #check total size of txs are more then 1MB
            assert_greater_than(total_size_of_txs_in_mempool, 1_000_000)
            # check the feerate has increased
            output = node.mempool_get_fee_rate(1)
            self.log.info(f"feerate: {output}")
            assert_greater_than(int(output['amount_per_kb']['atoms']), 3 * ATOMS_PER_COIN)

            balance = await wallet.get_balance()
            self.log.info(f"balance: {balance}")
            assert_in("Coins amount: 10", balance)

            # try to send 9 out of 10 to itself, 1 coin should not be enough to pay the high fee
            address = await wallet.new_address()
            output = await wallet.send_to_address(address, 9)
            self.log.info(output)
            assert "successfully" not in output

            # sending 6 and having 4 for fee should be enough
            output = await wallet.send_to_address(address, 6)
            self.log.info(output)
            assert "successfully" in output


if __name__ == '__main__':
    WalletSubmitTransaction().main()
