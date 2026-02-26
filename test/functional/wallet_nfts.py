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
"""Wallet NFTs test

Check that:
* We can create a new wallet,
* get an address
* send coins to the wallet's address
* sync the wallet with the node
* check balance
* issue new nft
* transfer the nft
* check balance
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import (make_tx, reward_input, ATOMS_PER_COIN)
from test_framework.util import assert_in, assert_equal
from test_framework.mintlayer import block_input_data_obj
from test_framework.wallet_cli_controller import WalletCliController

import asyncio
import random
import string

class WalletNfts(BitcoinTestFramework):

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
        asyncio.run(self.async_test())

    async def async_test(self):
        node = self.nodes[0]

        # new wallet
        async with WalletCliController(node, self.config, self.log) as wallet:
            await wallet.create_wallet()

            # check it is on genesis
            assert_equal('0', await wallet.get_best_block_height())

            # new address
            pub_key_bytes = await wallet.new_public_key()
            assert_equal(len(pub_key_bytes), 33)

            # Get chain tip
            tip_id = node.chainstate_best_block_id()
            self.log.debug(f'Tip: {tip_id}')

            # Submit a valid transaction
            output = {
                'Transfer': [
                    { 'Coin': 1000 * ATOMS_PER_COIN },
                    { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': pub_key_bytes}}} }
                ],
            }
            encoded_tx, tx_id = make_tx([reward_input(tip_id)], [output], 0)

            node.mempool_submit_transaction(encoded_tx, {})
            assert node.mempool_contains_tx(tx_id)

            block_id = self.generate_block() # Block 1
            assert not node.mempool_contains_tx(tx_id)


            # sync the wallet
            assert_in("Success", await wallet.sync())

            # check wallet best block if it is synced
            assert_equal(await wallet.get_best_block_height(), '1')
            assert_equal(await wallet.get_best_block(), block_id)

            assert_in("Coins amount: 1000", await wallet.get_balance())

            address = await wallet.new_address()

            # invalid ticker
            # > max len
            invalid_ticker = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(random.randint(13, 20)))
            nft_id, _, err = await wallet.issue_new_nft(address, "123456", "Name", "SomeNFT", invalid_ticker)
            assert nft_id is None
            assert err is not None
            assert_in("Invalid ticker length", err)
            # non alphanumeric
            invalid_ticker = "asd" + random.choice(r"#$%&'()*+,-./:;<=>?@[]^_`{|}~")
            nft_id, _, err = await wallet.issue_new_nft(address, "123456", "Name", "SomeNFT", invalid_ticker)
            assert nft_id is None
            assert err is not None
            assert_in("Invalid character in token ticker", err)

            # invalid name
            # > max len
            invalid_name = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(random.randint(11, 20)))
            nft_ticker = "XXX"
            nft_id, _, err = await wallet.issue_new_nft(address, "123456", invalid_name, "SomeNFT", nft_ticker)
            assert nft_id is None
            assert err is not None
            assert_in("Invalid name length", err)
            # non alphanumeric
            invalid_name = "asd" + random.choice(r"#$%&'()*+,-./:;<=>?@[]^_`{|}~")
            nft_id, _, err = await wallet.issue_new_nft(address, "123456", invalid_name, "SomeNFT", nft_ticker)
            assert nft_id is None
            assert err is not None
            assert_in("Invalid character in token name", err)

            # invalid description
            # > max len
            invalid_desc = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(random.randint(101, 200)))
            nft_id, _, err = await wallet.issue_new_nft(address, "123456", "Name", invalid_desc, nft_ticker)
            assert nft_id is None
            assert err is not None
            assert_in("Invalid description length", err)

            # issue a valid NFT
            nft_id, _, err = await wallet.issue_new_nft(address, "123456", "Name", "SomeNFT", nft_ticker)
            assert err is None
            assert nft_id is not None
            self.log.info(f"new nft id: '{nft_id}'")

            self.generate_block()
            assert_in("Success", await wallet.sync())
            assert_in(f"Coins amount: 994", await wallet.get_balance())

            self.log.info(await wallet.get_balance())
            assert_in(f"{nft_id} ({nft_ticker}), amount: 1", await wallet.get_balance())

            # create a new account and send some tokens to it
            await wallet.create_new_account()
            await wallet.select_account(1)
            address = await wallet.new_address()

            await wallet.select_account(0)
            assert_in(f"{nft_id} ({nft_ticker}), amount: 1", await wallet.get_balance())
            output = await wallet.send_tokens_to_address(nft_id, address, 1)
            self.log.info(output)
            assert_in("The transaction was submitted successfully", output)

            self.generate_block()
            assert_in("Success", await wallet.sync())

            # check the new balance nft is not present
            assert nft_id not in await wallet.get_balance()

if __name__ == '__main__':
    WalletNfts().main()
