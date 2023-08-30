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
"""Wallet accounts recovery test

Check that:
* We can create a new wallet,
* get an address
* send coins to the wallet's address
* sync the wallet with the node
* create random amount of new accounts
* send coins to that accounts as well
* check balance
* recover the wallet using the mnemonic
* check that it has all of the accounts with the correct balances
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import (make_tx, reward_input, tx_input)
from test_framework.util import assert_raises_rpc_error
from test_framework.mintlayer import mintlayer_hash, block_input_data_obj
from test_framework.wallet_cli_controller import WalletCliController


class WalletRecoverAccounts(BitcoinTestFramework):

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
        node = self.nodes[0]

        # new wallet
        with WalletCliController(node, self.config, self.log) as wallet:
            wallet.create_wallet()

            # check it is on genesis
            best_block_height = wallet.get_best_block_height()
            assert best_block_height == '0'

            # new address
            pub_key_bytes = wallet.new_public_key()
            assert len(pub_key_bytes) == 33

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

            block_id = self.generate_block() # Block 1
            assert not node.mempool_contains_tx(tx_id)

            # sync the wallet
            output = wallet.sync()
            assert "Success" in output

            # check wallet best block if it is synced
            best_block_height = wallet.get_best_block_height()
            assert best_block_height == '1'

            best_block_id = wallet.get_best_block()
            assert best_block_id == block_id

            balance = wallet.get_balance()
            assert "Coins amount: 10" in balance

            # create 3 new accounts
            DEFAULT_ACCOUNT_INDEX = 0
            num_accounts = 3
            for idx in range(num_accounts):
                assert "Success" in wallet.create_new_account()
                assert "Success" in wallet.select_account(idx+1)
                address = wallet.new_address()
                assert "Success" in wallet.select_account(DEFAULT_ACCOUNT_INDEX)
                assert "The transaction was submitted successfully" in wallet.send_to_address(address, idx+1)
                self.generate_block()
                assert "Success" in wallet.sync()
                assert f"{idx+2}" == wallet.get_best_block_height()

            # try to recover the wallet
            mnemonic = wallet.show_seed_phrase()
            assert mnemonic is not None
            assert "Successfully closed the wallet" in wallet.close_wallet()
            assert "New wallet created successfully" in wallet.recover_wallet(mnemonic)
            # check that balance is 0 and accounts are not present
            assert "Coins amount: 0" in wallet.get_balance()
            for idx in range(num_accounts):
                assert f"Account not found for index: {idx+1}" in wallet.select_account(idx+1)

            # sync and check that accounts are now present and with correct balances
            assert "Success" in wallet.sync()

            for idx in range(num_accounts):
                assert "Success" in wallet.select_account(idx+1)
                assert f"Coins amount: {idx+1}" in wallet.get_balance()


if __name__ == '__main__':
    WalletRecoverAccounts().main()


