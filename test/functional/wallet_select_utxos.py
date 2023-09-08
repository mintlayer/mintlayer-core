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
"""Wallet submission test

Check that:
* We can create a new wallet,
* get N addresses
* send coins to the wallet's addresses
* sync the wallet with the node
* get utxos
* send amount from a specific utxo
* check it has been used
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import (make_tx, reward_input, tx_input)
from test_framework.util import assert_raises_rpc_error
from test_framework.mintlayer import mintlayer_hash, block_input_data_obj
from test_framework.wallet_cli_controller import WalletCliController

import asyncio
import sys


class WalletSubmitTransactionSpecificUtxo(BitcoinTestFramework):

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
        block = node.blockprod_generate_block(block_input_data, None)
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
            assert best_block_height == '0'

            # Get chain tip
            tip_id = node.chainstate_best_block_id()
            self.log.debug(f'Tip: {tip_id}')

            # new address
            addresses = []
            num_utxos = 5
            for _ in range(num_utxos):
                pub_key_bytes = await wallet.new_public_key()
                assert len(pub_key_bytes) == 33
                addresses.append(pub_key_bytes)

            # Submit a valid transaction
            def make_output(pub_key_bytes):
                return {
                        'Transfer': [ { 'Coin': 1_000_000_000_000 }, { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': pub_key_bytes}}} } ],
                }
            encoded_tx, tx_id = make_tx([reward_input(tip_id)], [make_output(pk) for pk in addresses], 0)

            node.mempool_submit_transaction(encoded_tx)
            assert node.mempool_contains_tx(tx_id)

            block_id = self.generate_block() # Block 1
            assert not node.mempool_contains_tx(tx_id)

            # sync the wallet
            output = await wallet.sync()
            assert "Success" in output

            # check wallet best block if it is synced
            best_block_height = await wallet.get_best_block_height()
            assert best_block_height == '1'

            best_block_id = await wallet.get_best_block()
            assert best_block_id == block_id

            balance = await wallet.get_balance()
            assert f"Coins amount: {10*num_utxos}" in balance

            utxos = await wallet.list_utxos()
            assert len(utxos) == num_utxos

            address = await wallet.new_address()
            selected_utxos = utxos[:3]
            await wallet.send_to_address(address, 1, selected_utxos)

            self.generate_block()
            assert not node.mempool_contains_tx(tx_id)

            # sync the wallet
            output = await wallet.sync()
            assert "Success" in output

            new_utxos = await wallet.list_utxos()
            self.log.info(f"old utxos {len(utxos)}: {utxos}")
            self.log.info(f"new utxos {len(new_utxos)}: {new_utxos}")
            # check that the new utxos have the selected utxos removed,
            # but have a new one from the transfer and one more from the change
            assert len(new_utxos) == num_utxos - len(selected_utxos) + 2
            # check selected utxos are no longer present
            assert all(selected_utxo not in new_utxos for selected_utxo in selected_utxos)



if __name__ == '__main__':
    WalletSubmitTransactionSpecificUtxo().main()


