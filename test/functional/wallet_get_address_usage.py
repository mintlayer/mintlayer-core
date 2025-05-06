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
from test_framework.mintlayer import (ATOMS_PER_COIN, make_tx, reward_input)
from test_framework.util import assert_in, assert_equal, assert_not_in
from test_framework.mintlayer import block_input_data_obj
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

        # new wallet
        async with WalletCliController(node, self.config, self.log) as wallet:
            mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            assert_in("Wallet recovered successfully", await wallet.recover_wallet(mnemonic, "wallet"))

            # check it is on genesis
            best_block_height = await wallet.get_best_block_height()
            assert_equal(best_block_height, '0')

            # new address
            for _ in range(4):
                pub_key_bytes = await wallet.new_public_key()
                assert_equal(len(pub_key_bytes), 33)

            pub_key_bytes = await wallet.new_public_key()
            assert_equal(len(pub_key_bytes), 33)

            # 2 more unused addresses
            await wallet.new_address()
            await wallet.new_public_key()

            # Get chain tip
            tip_id = node.chainstate_best_block_id()
            self.log.debug(f'Tip: {tip_id}')

            # Submit a valid transaction
            stake_pool_amount = 40000
            output = {
                    'Transfer': [ { 'Coin': (stake_pool_amount + 100) * ATOMS_PER_COIN }, { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': pub_key_bytes}}} } ],
            }
            encoded_tx, tx_id = make_tx([reward_input(tip_id)], [output], 0)

            node.mempool_submit_transaction(encoded_tx, {})
            assert node.mempool_contains_tx(tx_id)

            self.generate_block() # Block 1
            assert not node.mempool_contains_tx(tx_id)

            # sync the wallet
            output = await wallet.sync()
            assert_in("Success", output)

            expected_output = """+-------+---------+----------------------------------------------+--------------------------------+-------+
| Index | Purpose | Address                                      | Is used in transaction history | Coins |
+=======+=========+==============================================+================================+=======+
| 0     | Receive | rmt1qx5p4r2en7c99mpmg2tz9hucxfarf4k6dypq388a | Yes                            | 0     |
+-------+---------+----------------------------------------------+--------------------------------+-------+
| 1     | Receive | rmt1q9jvqp9p8rzp2prmpa8y9vde7yrvlxgz3s54n787 | Yes                            | 0     |
+-------+---------+----------------------------------------------+--------------------------------+-------+
| 2     | Receive | rmt1qx7dwah3rtkh2mv7lyd4qserqx59mqjknc6qdn77 | Yes                            | 0     |
+-------+---------+----------------------------------------------+--------------------------------+-------+
| 3     | Receive | rmt1qxrkx54pykusw7am7zr282t6tzsl3wzkysrh0k2a | Yes                            | 0     |
+-------+---------+----------------------------------------------+--------------------------------+-------+
| 4     | Receive | rmt1qyyra5j3qduhyd43wa50lpn2ddpg9ql0u50ceu68 | Yes                            | 0     |
+-------+---------+----------------------------------------------+--------------------------------+-------+
| 5     | Receive | rmt1q8upmt2mjxel84msaqjj2rkquguvswwzquy6w8sn | No                             | 0     |
+-------+---------+----------------------------------------------+--------------------------------+-------+
| 6     | Receive | rmt1q8lrw5tzgmwjnsc26v8qfu8k2jmddpmhwqz6kwt7 | No                             | 0     |
+-------+---------+----------------------------------------------+--------------------------------+-------+"""
            output = await wallet.get_addresses_usage()
            for (line, expected_line) in zip(output.splitlines(), expected_output.splitlines()):
                assert_equal(line, expected_line)

            decommission_address = await wallet.new_address()
            expected_vrf_output = """+-------+---------+--------------------------------+
| Index | Address | Is used in transaction history |
+=======+=========+================================+
+-------+---------+--------------------------------+"""
            output = await wallet.get_vrf_addresses_usage()
            self.log.info(output)
            for (line, expected_line) in zip(output.splitlines(), expected_vrf_output.splitlines()):
                assert_equal(line, expected_line)

            for _ in range(100):
                assert_in("Not enough funds", await wallet.create_stake_pool(stake_pool_amount + 100, 0, 0.5, decommission_address))

            output = await wallet.get_addresses_usage()
            for (line, expected_line) in zip(output.splitlines(), expected_output.splitlines()):
                assert_equal(line, expected_line)

            assert_in("The transaction was submitted successfully", await wallet.create_stake_pool(stake_pool_amount, 0, 0.5, decommission_address))
            self.generate_block()
            # sync the wallet
            output = await wallet.sync()
            assert_in("Success", output)

            expected_output = """+-------+---------+----------------------------------------------+--------------------------------+
| Index | Purpose | Address                                      | Is used in transaction history | Coins
+=======+=========+==============================================+================================+======
| 0     | Receive | rmt1qx5p4r2en7c99mpmg2tz9hucxfarf4k6dypq388a | Yes                            | 0
+-------+---------+----------------------------------------------+--------------------------------+------
| 1     | Receive | rmt1q9jvqp9p8rzp2prmpa8y9vde7yrvlxgz3s54n787 | Yes                            | 0
+-------+---------+----------------------------------------------+--------------------------------+------
| 2     | Receive | rmt1qx7dwah3rtkh2mv7lyd4qserqx59mqjknc6qdn77 | Yes                            | 0
+-------+---------+----------------------------------------------+--------------------------------+------
| 3     | Receive | rmt1qxrkx54pykusw7am7zr282t6tzsl3wzkysrh0k2a | Yes                            | 0
+-------+---------+----------------------------------------------+--------------------------------+------
| 4     | Receive | rmt1qyyra5j3qduhyd43wa50lpn2ddpg9ql0u50ceu68 | Yes                            | 0
+-------+---------+----------------------------------------------+--------------------------------+------
| 5     | Receive | rmt1q8upmt2mjxel84msaqjj2rkquguvswwzquy6w8sn | Yes                            | 0
+-------+---------+----------------------------------------------+--------------------------------+------
| 6     | Receive | rmt1q8lrw5tzgmwjnsc26v8qfu8k2jmddpmhwqz6kwt7 | Yes                            | 0
+-------+---------+----------------------------------------------+--------------------------------+------
| 7     | Receive | rmt1q824xhhlcdazxj38yuqr6llqz3wm7whhgvmyvyjz | Yes                            | 0
+-------+---------+----------------------------------------------+--------------------------------+------"""

            expected_change_output = """| 0     | Change  | rmt1qyltm78pn55qyv6vngnk0nlh6m2rrjg5cs5p5xsm | Yes                            | 99.99999999715 |"""

            output = await wallet.get_addresses_usage()
            for (line, expected_line) in zip(output.splitlines(), expected_output.splitlines()):
                assert_in(expected_line, line)

            # change outputs will not be present
            for line in expected_change_output.splitlines():
                assert_not_in(line, output)

            output = await wallet.get_addresses_usage(with_change=True)
            for (line, expected_line) in zip(output.splitlines(), expected_output.splitlines()):
                assert_in(expected_line, line)

            # change outputs will be present
            for line in expected_change_output.splitlines():
                assert_in(line, output)

            vrf_public_key = "rvrfpk1qregu4v895mchautf84u46nsf9xel2507a37ksaf3stmuw44y3m4vc2kzme"
            expected_vrf_output = f"""+-------+--------------------------------------------------------------------+--------------------------------+
| Index | Address                                                            | Is used in transaction history |
+=======+====================================================================+================================+
| 0     | {vrf_public_key} | Yes                            |
+-------+--------------------------------------------------------------------+--------------------------------+"""
            output = await wallet.get_vrf_addresses_usage()
            for (line, expected_line) in zip(output.splitlines(), expected_vrf_output.splitlines()):
                assert_equal(line, expected_line)

            assert_in("Successfully rescanned the blockchain", await wallet.rescan())

            output = await wallet.get_addresses_usage()
            for (line, expected_line) in zip(output.splitlines(), expected_output.splitlines()):
                assert_in(expected_line, line)

            output = await wallet.get_vrf_addresses_usage()
            for (line, expected_line) in zip(output.splitlines(), expected_vrf_output.splitlines()):
                assert_equal(line, expected_line)

            pools = await wallet.list_pool_ids()
            assert_equal(pools[0].pledge, '40000')
            assert_equal(pools[0].balance, '40000')
            assert_equal(pools[0].creation_block_height, 2)
            assert_equal(pools[0].vrf_public_key, vrf_public_key)
            assert_equal(pools[0].staker, "rpmt1qgqq92qeytkezwypc2ydcm78rv9v2m85fqnxh46cnrw7c2huc79f638zcx8l48")
            assert_equal(pools[0].decommission_key, "rmt1q824xhhlcdazxj38yuqr6llqz3wm7whhgvmyvyjz")

            assert_equal("rvrfpk1qqe29knh5xdmtn6jqznq3w753dr9jcnryllnjfcgktcedu5dkruksvcupzm", await wallet.get_legacy_vrf_public_key())

            await wallet.close_wallet()
            await wallet.open_wallet('wallet')

            output = await wallet.get_addresses_usage()
            for (line, expected_line) in zip(output.splitlines(), expected_output.splitlines()):
                assert_in(expected_line, line)

            output = await wallet.get_vrf_addresses_usage()
            for (line, expected_line) in zip(output.splitlines(), expected_vrf_output.splitlines()):
                assert_equal(line, expected_line)

            pools = await wallet.list_pool_ids()
            assert_equal(pools[0].pledge, '40000')
            assert_equal(pools[0].balance, '40000')
            assert_equal(pools[0].creation_block_height, 2)
            assert_equal(pools[0].vrf_public_key, vrf_public_key)
            assert_equal(pools[0].staker, "rpmt1qgqq92qeytkezwypc2ydcm78rv9v2m85fqnxh46cnrw7c2huc79f638zcx8l48")
            assert_equal(pools[0].decommission_key, "rmt1q824xhhlcdazxj38yuqr6llqz3wm7whhgvmyvyjz")

            assert_equal("rvrfpk1qqe29knh5xdmtn6jqznq3w753dr9jcnryllnjfcgktcedu5dkruksvcupzm", await wallet.get_legacy_vrf_public_key())



if __name__ == '__main__':
    WalletGetAddressUsage().main()
