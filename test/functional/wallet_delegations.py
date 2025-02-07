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
"""Wallet delegations test

Check that:
* We can create a new wallet,
* get an address
* send coins to the wallet's address
* sync the wallet with the node
* check balance
* create a stake pool
* in another account create a delegation to that pool
* stake to that delegation
* transfer from that delegation
* get reward to that delegation
"""

from random import choice
from test_framework.mintlayer import (ATOMS_PER_COIN, make_tx, reward_input)
from test_framework.util import assert_equal, assert_greater_than, assert_in
from test_framework.wallet_cli_controller import DEFAULT_ACCOUNT_INDEX, CreatedBlockInfo, WalletCliController
from wallet_pos_test_base import WalletPOSTestBase

import re, os


class WalletDelegationsCLI(WalletPOSTestBase):
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

            # still not in a block
            delegations = await wallet.list_delegation_ids()
            assert_equal(len(delegations), 0)

            assert_in("Success", await wallet.stake_delegation(1000, delegation_id))
            transactions2 = node.mempool_transactions()
            for tx in transactions2:
                if tx not in transactions:
                    transactions.append(tx)

            self.gen_pos_block(transactions, 3)
            assert_in("Success", await wallet.sync())
            last_block_id = self.previous_block_id()

            delegations = await wallet.list_delegation_ids()
            assert_equal(len(delegations), 1)
            assert_equal(delegations[0].balance, '1000')

            # create another pool in account 1 with decommission_address from acc 0
            assert_in("The transaction was submitted successfully", await wallet.create_stake_pool(40000, 0, 0.5, decommission_address))

            assert_in("Success", await wallet.select_account(DEFAULT_ACCOUNT_INDEX))
            pools = await wallet.list_pool_ids()
            assert_equal(len(pools), 1)
            assert_equal(pools[0].pledge, '40000')
            # balance will contain the delegation as well
            assert_equal(pools[0].balance, '41000')

            created_block_ids = await wallet.list_created_blocks_ids()
            # no created block by us yet
            assert_equal(0, len(created_block_ids))
            assert_in("Staking started successfully", await wallet.start_staking())
            assert_equal("Staking", await wallet.staking_status())
            assert_in("Success", await wallet.select_account(1))

            block_height = await wallet.get_best_block_height()
            block_ids = []
            last_delegation_balance = delegations[0].balance
            for _ in range(4, 10):
                if choice([True, False]):
                    await wallet.close_wallet()
                    await wallet.open_wallet('wallet')
                    assert_in("Success", await wallet.select_account(DEFAULT_ACCOUNT_INDEX))
                    assert_in("Staking started successfully", await wallet.start_staking())
                    assert_in("Success", await wallet.select_account(1))

                tip_id = node.chainstate_best_block_id()
                assert_in("The transaction was submitted successfully", await wallet.send_to_address(acc1_address, 1))
                transactions = node.mempool_transactions()
                self.wait_until(lambda: node.chainstate_best_block_id() != tip_id, timeout = 5)
                block_height = node.chainstate_best_block_height()
                block_id = node.chainstate_block_id_at_height(block_height)
                assert_in("Success", await wallet.sync())

                delegations = await wallet.list_delegation_ids()
                assert_equal(len(delegations), 1)
                assert_greater_than(float(delegations[0].balance), float(last_delegation_balance))
                last_delegation_balance = delegations[0].balance
                block_ids.append((block_id, block_height))


            # stake to acc1 delegation from acc 0
            assert_in("Success", await wallet.select_account(DEFAULT_ACCOUNT_INDEX))
            assert_in("Success", await wallet.stake_delegation(10, delegation_id))
            self.wait_until(lambda: node.chainstate_best_block_id() != tip_id, timeout = 5)
            block_height = node.chainstate_best_block_height()
            block_id = node.chainstate_block_id_at_height(block_height)
            assert_in("Success", await wallet.sync())
            block_ids.append((block_id, block_height))

            # check that we still don't have any delegations for this account
            delegations = await wallet.list_delegation_ids()
            assert_equal(len(delegations), 0)

            # create a delegation from acc 0 but with destination address for acc1
            delegation_id = await wallet.create_delegation(acc1_address, pool_id)
            tip_id = node.chainstate_best_block_id()
            self.wait_until(lambda: node.chainstate_best_block_id() != tip_id, timeout = 5)
            block_id = node.chainstate_block_id_at_height(block_height)
            assert_in("Success", await wallet.sync())
            block_ids.append((block_id, block_height))

            # check that we still don't have any delegations for this account
            delegations = await wallet.list_delegation_ids()
            assert_equal(len(delegations), 0)

            assert_in("Success", await wallet.select_account(1))
            delegations = await wallet.list_delegation_ids()
            assert_equal(len(delegations), 2)
            assert delegation_id in [delegation.delegation_id for delegation in delegations]
        # close the wallet and try to open it again with staking started for account 0

        wallet_path = os.path.join(node.datadir, wallet_name)
        # check that we can start the wallet with staking enabled for account 0 and 1
        async with self.wallet_controller(
                node,
                self.config,
                self.log,
                wallet_args=["--wallet-file", wallet_path, "--start-staking-for-account", "0", "--start-staking-for-account", "1"],
                chain_config_args=chain_config_args) as wallet:

            # check both accounts have staking active
            assert_equal("Staking", (await wallet.staking_status()).splitlines()[-1])
            assert_in("Success", await wallet.select_account(1))
            assert_equal("Staking", await wallet.staking_status())
            assert_in("Success", await wallet.stop_staking())
            assert_in("Not staking", await wallet.staking_status())

            # stop staking and decommission the stake pool for acc 0
            assert_in("Success", await wallet.select_account(DEFAULT_ACCOUNT_INDEX))
            assert_in("Success", await wallet.stop_staking())
            assert_in("Not staking", await wallet.staking_status())
            address = await wallet.new_address()
            assert_in("The transaction was submitted successfully", await wallet.decommission_stake_pool(pool_id, address))

            assert_in("Success", await wallet.select_account(1))
            assert_in("Staking started successfully", await wallet.start_staking())
            tip_id = node.chainstate_best_block_id()
            self.wait_until(lambda: node.chainstate_best_block_id() != tip_id, timeout = 5)
            assert_in("Success", await wallet.select_account(DEFAULT_ACCOUNT_INDEX))

            assert_in("Success", await wallet.sync())

            # the acc0 pool has been decommissioned so there are non left
            pools = await wallet.list_pool_ids()
            assert_equal(len(pools), 0)

            # but since acc1's pool has the decommissioning address from acc0
            pools = await wallet.list_pools_for_decommission()
            assert_equal(len(pools), 1)

            balance = await wallet.get_balance("locked")
            pattern = r"Coins amount: (\d{5,})"
            result = re.search(pattern, balance)
            assert(result)
            g = result.group(1)
            self.log.info(f"balance {balance}, extracted group {g}")
            assert_greater_than(int(g), 40000)

            created_block_ids = await wallet.list_created_blocks_ids()

            self.log.info(created_block_ids)
            for block_id, block_height in block_ids:
                self.log.info(f"{block_id} {block_height}")
                def same_with_current(block: CreatedBlockInfo):
                    return block.block_id == block_id and str(block.block_height) == str(block_height) and block.pool_id == pool_id

                assert(any([same_with_current(block) for block in created_block_ids]))

            # check even though decommission_address is from acc0 it will list the created blocks for acc1's pool
            assert_in("Success", await wallet.select_account(1))
            created_block_ids = await wallet.list_created_blocks_ids()
            assert_greater_than(len(created_block_ids), 0)


if __name__ == '__main__':
    WalletDelegationsCLI().main()
