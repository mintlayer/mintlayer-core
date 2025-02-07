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
"""Wallet sweep delegation test

Check that:
* We can create a new wallet,
* get an address
* send coins to the wallet's address
* sync the wallet with the node
* check balance
* create a stake pool
* in another account create a delegation to that pool
* stake to that delegation
* sweep from that delegation
"""

from test_framework.mintlayer import (ATOMS_PER_COIN, make_tx, reward_input)
from test_framework.util import assert_equal, assert_in
from test_framework.wallet_cli_controller import DEFAULT_ACCOUNT_INDEX, WalletCliController
from wallet_pos_test_base import WalletPOSTestBase


class WalletSweepDelegationsCLI(WalletPOSTestBase):

    def set_test_params(self):
        super().set_test_params()
        self.wallet_controller = WalletCliController

    async def async_test(self):
        node = self.nodes[0]
        wallet_name = "wallet"
        chain_config_args = self.wallet_chain_config_args()

        async with self.wallet_controller(node, self.config, self.log, chain_config_args=chain_config_args) as wallet:
            # new wallet
            await wallet.create_wallet(wallet_name)

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
            coins_to_send = 100_000
            output = {
                'Transfer': [ { 'Coin': coins_to_send * ATOMS_PER_COIN }, { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': pub_key_bytes}}} } ],
            }
            encoded_tx, tx_id = make_tx([reward_input(tip_id)], [output], 0)
            self.log.debug(f"Encoded transaction {tx_id}: {encoded_tx}")


            self.setup_pool_and_transfer([encoded_tx])

            # sync the wallet
            assert_in("Success", await wallet.sync())

            # check wallet best block if it is synced
            best_block_height = await wallet.get_best_block_height()
            assert_in(best_block_height, '1')

            balance = await wallet.get_balance()
            assert_in(f"Coins amount: {coins_to_send}", balance)

            assert_in("Success", await wallet.create_new_account())
            assert_in("Success", await wallet.select_account(1))
            acc1_address = await wallet.new_address()
            assert_in("Success", await wallet.select_account(DEFAULT_ACCOUNT_INDEX))
            assert_in("The transaction was submitted successfully", await wallet.send_to_address(acc1_address, 55000))
            assert_in("Success", await wallet.select_account(1))
            transactions = node.mempool_transactions()

            assert_in("Success", await wallet.select_account(DEFAULT_ACCOUNT_INDEX))
            decommission_address = await wallet.new_address()
            assert_in("The transaction was submitted successfully", await wallet.create_stake_pool(40000, 0, 0.5, decommission_address))
            transactions2 = node.mempool_transactions()
            for tx in transactions2:
                if tx not in transactions:
                    transactions.append(tx)

            self.gen_pos_block(transactions, 2)
            assert_in("Success", await wallet.sync())

            pools = await wallet.list_pool_ids()
            assert_equal(len(pools), 1)
            assert_equal(pools[0].pledge, '40000')
            assert_equal(pools[0].balance, '40000')
            pool_id = pools[0].pool_id

            assert_in("Success", await wallet.select_account(1))
            balance = await wallet.get_balance()
            assert_in("Coins amount: 55000", balance)
            delegation_id = await wallet.create_delegation(acc1_address, pool_id)
            assert delegation_id is not None
            transactions = node.mempool_transactions()

            assert_in("Success", await wallet.stake_delegation(1000, delegation_id))
            transactions2 = node.mempool_transactions()
            for tx in transactions2:
                if tx not in transactions:
                    transactions.append(tx)

            self.gen_pos_block(transactions, 3)
            assert_in("Success", await wallet.sync())

            delegations = await wallet.list_delegation_ids()
            assert_equal(len(delegations), 1)
            assert_equal(delegations[0].delegation_id, delegation_id)
            assert_equal(delegations[0].balance, '1000')

            address = await wallet.new_address()
            assert_in("The transaction was submitted successfully", await wallet.sweep_delegation(address, delegation_id))
            transactions = node.mempool_transactions()
            self.gen_pos_block(transactions, 4)
            assert_in("Success", await wallet.sync())

            delegations = await wallet.list_delegation_ids()
            # check all coins are swept
            assert_equal(len(delegations), 0)


if __name__ == '__main__':
    WalletSweepDelegationsCLI().main()
