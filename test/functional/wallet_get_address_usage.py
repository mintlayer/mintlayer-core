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
"""Wallet get address usage format test

Check that:
* We recover a wallet with fixed seed phrase,
* get 5 address
* send coins to the 5th address
* sync the wallet with the node
* check printed format of the get address usage
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import (make_tx, reward_input, tx_input)
from test_framework.util import assert_raises_rpc_error
from test_framework.mintlayer import mintlayer_hash, block_input_data_obj
from test_framework.wallet_cli_controller import WalletCliController

import asyncio
import sys


class WalletGetAddressUsage(BitcoinTestFramework):

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

        # new wallet
        async with WalletCliController(node, self.config, self.log) as wallet:
            mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            assert "New wallet created successfully" in await wallet.recover_wallet(mnemonic)

            # check it is on genesis
            best_block_height = await wallet.get_best_block_height()
            assert best_block_height == '0'

            # new address
            for _ in range(4):
                pub_key_bytes = await wallet.new_public_key()
                assert len(pub_key_bytes) == 33

            pub_key_bytes = await wallet.new_public_key()
            assert len(pub_key_bytes) == 33

            # 2 more unused addresses
            await wallet.new_address()
            await wallet.new_public_key()

            # Get chain tip
            tip_id = node.chainstate_best_block_id()
            self.log.debug(f'Tip: {tip_id}')

            # Submit a valid transaction
            output = {
                    'Transfer': [ { 'Coin': 1_000_000_000_000 }, { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': pub_key_bytes}}} } ],
            }
            encoded_tx, tx_id = make_tx([reward_input(tip_id)], [output], 0)

            node.mempool_submit_transaction(encoded_tx)
            assert node.mempool_contains_tx(tx_id)

            self.generate_block() # Block 1
            assert not node.mempool_contains_tx(tx_id)

            # sync the wallet
            output = await wallet.sync()
            assert "Success" in output

            expected_output = """+-------+----------------------------------------------+--------------------------------+
| Index | Address                                      | Is used in transaction history |
+=======+==============================================+================================+
| 0     | rmt1qx5p4r2en7c99mpmg2tz9hucxfarf4k6dypq388a | Yes                            |
+-------+----------------------------------------------+--------------------------------+
| 1     | rmt1q9jvqp9p8rzp2prmpa8y9vde7yrvlxgz3s54n787 | Yes                            |
+-------+----------------------------------------------+--------------------------------+
| 2     | rmt1qx7dwah3rtkh2mv7lyd4qserqx59mqjknc6qdn77 | Yes                            |
+-------+----------------------------------------------+--------------------------------+
| 3     | rmt1qxrkx54pykusw7am7zr282t6tzsl3wzkysrh0k2a | Yes                            |
+-------+----------------------------------------------+--------------------------------+
| 4     | rmt1qyyra5j3qduhyd43wa50lpn2ddpg9ql0u50ceu68 | Yes                            |
+-------+----------------------------------------------+--------------------------------+
| 5     | rmt1q8upmt2mjxel84msaqjj2rkquguvswwzquy6w8sn | No                             |
+-------+----------------------------------------------+--------------------------------+
| 6     | rmt1q8lrw5tzgmwjnsc26v8qfu8k2jmddpmhwqz6kwt7 | No                             |
+-------+----------------------------------------------+--------------------------------+"""
            assert expected_output == await wallet.get_addresses_usage()


if __name__ == '__main__':
    WalletGetAddressUsage().main()


