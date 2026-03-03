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
"""Wallet account info test

Check that:
* We can create a new wallet,
* get an address
* send coins to the wallet's address
* sync the wallet with the node
* check balance
* create a new account
* rename the account
* get wallet info
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import (make_tx, reward_input, ATOMS_PER_COIN)
from test_framework.util import assert_in, assert_equal
from test_framework.mintlayer import block_input_data_obj
from test_framework.wallet_cli_controller import WalletCliController

import asyncio
import random
import string


class WalletAccountInfo(BitcoinTestFramework):

    def set_test_params(self):
        self.wallet_controller = WalletCliController
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
        asyncio.run(self.async_test())

    async def async_test(self):
        node = self.nodes[0]
        async with self.wallet_controller(node, self.config, self.log) as wallet:
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
            coins_to_send = random.randint(2, 100)
            output = {
                    'Transfer': [ { 'Coin': coins_to_send * ATOMS_PER_COIN }, { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': pub_key_bytes}}} } ],
            }
            encoded_tx, tx_id = make_tx([reward_input(tip_id)], [output], 0)
            assert_in("The transaction was submitted successfully", await wallet.submit_transaction(encoded_tx))

            assert node.mempool_contains_tx(tx_id)

            self.generate_block() # Block 1
            assert not node.mempool_contains_tx(tx_id)

            # sync the wallet
            assert_in("Success", await wallet.sync())

            acc1_name = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(random.randint(1, 5)))
            assert_in("Success, the new account index is: 1", await wallet.create_new_account(acc1_name))

            info = await wallet.wallet_info()
            assert_equal(2, len(info))
            assert_equal(info[0].index, 0)
            assert_equal(info[0].name, None)
            assert_equal(info[1].index, 1)
            assert_equal(info[1].name, acc1_name)

            acc0_name = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(random.randint(1, 5)))
            assert_in("Success, the account name has been successfully renamed", await wallet.rename_account(acc0_name))

            info = await wallet.wallet_info()
            assert_equal(2, len(info))
            assert_equal(info[0].index, 0)
            assert_equal(info[0].name, acc0_name)
            assert_equal(info[1].index, 1)
            assert_equal(info[1].name, acc1_name)


if __name__ == '__main__':
    WalletAccountInfo().main()

