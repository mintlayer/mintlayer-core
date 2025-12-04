#!/usr/bin/env python3
#  Copyright (c) 2023-2025 RBB S.r.l
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
"""A test that creates a pool using a staker key and vrf pub key from another wallet

1. Create a pool using a decommission address from the 'pool_creator' wallet and the staker key
and vrf pub key from the 'staker' wallet.
2. Ensure that 'staker' can stake.
3. Ensure that 'pool_creator' can decommission the pool and that the resulting balance is correct.
"""

from decimal import Decimal
from test_framework.mintlayer import (ATOMS_PER_COIN, make_tx, reward_input)
from test_framework.util import assert_equal, assert_in
from test_framework.wallet_cli_controller import WalletCliController
from wallet_pos_test_base import WalletPOSTestBase

import re


class WalletCreatePoolForAnotherWalletCLI(WalletPOSTestBase):
    def set_test_params(self):
        super().set_test_params()
        self.wallet_controller = WalletCliController

    # Assert that the wallet's coin balance equals the specified value minus some portion of a coin
    # (which is assumed to have been spent on fees).
    def assert_approximate_balance(self, balance, expected_balance_without_fee):
        assert expected_balance_without_fee - 1 <= balance <= expected_balance_without_fee

    async def async_test(self):
        node = self.nodes[0]
        chain_config_args = self.wallet_chain_config_args()

        decommission_address = ""
        staker_pub_key_address = ""
        initial_balance = 50000
        pool_pledge = 40000
        block_reward = 202

        async with self.wallet_controller(node, self.config, self.log, chain_config_args=chain_config_args) as wallet:
            await wallet.create_wallet("staker")

            staker_address = await wallet.new_address()
            staker_pub_key_address = await wallet.reveal_public_key_as_address(staker_address)
            staker_vrf_pub_key = await wallet.new_vrf_public_key()

        async with self.wallet_controller(node, self.config, self.log, chain_config_args=chain_config_args) as wallet:
            await wallet.create_wallet("pool_creator")
            decommission_address = await wallet.new_address()

            best_block_height = await wallet.get_best_block_height()
            assert_equal(best_block_height, '0')

            pub_key_bytes_to_send_coins_to = await wallet.new_public_key()
            assert_equal(len(pub_key_bytes_to_send_coins_to), 33)

            tip_id = node.chainstate_best_block_id()

            output = {
                'Transfer': [
                    { 'Coin': initial_balance * ATOMS_PER_COIN },
                    { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': pub_key_bytes_to_send_coins_to}}} }
                ],
            }
            encoded_tx, tx_id = make_tx([reward_input(tip_id)], [output], 0)
            self.setup_pool_and_transfer([encoded_tx])

            assert_in("Success", await wallet.sync())
            best_block_height = await wallet.get_best_block_height()
            assert_in(best_block_height, '1')

            balance = await wallet.get_coins_balance('any')
            assert_equal(balance, initial_balance)

            result = await wallet.create_stake_pool(pool_pledge, 0, 0.5, decommission_address, staker_pub_key_address, staker_vrf_pub_key)
            assert_in("The transaction was submitted successfully", result)

            self.gen_pos_block(node.mempool_transactions(), 2)
            assert_in("Success", await wallet.sync())

            balance = await wallet.get_coins_balance('any')
            self.assert_approximate_balance(balance, initial_balance - pool_pledge)

            # No pools in the creating wallet.
            pools = await wallet.list_pool_ids()
            assert_equal(len(pools), 0)

        pool_id = ""
        total_staking_reward = Decimal(0)
        tip_id_with_genesis_pool = node.chainstate_best_block_id()

        async with self.wallet_controller(node, self.config, self.log, chain_config_args=chain_config_args) as wallet:
            await wallet.open_wallet("staker")
            assert_in("Success", await wallet.sync())

            # The staking wallet has the pool
            pools = await wallet.list_pool_ids()
            assert_equal(len(pools), 1)
            assert_equal(Decimal(pools[0].pledge), pool_pledge)
            assert_equal(Decimal(pools[0].balance), pool_pledge)

            pool_id = pools[0].pool_id

            tip_height_before_staking = int(await wallet.get_best_block_height())

            # Produce some blocks with the staking wallet.
            assert_in("Staking started successfully", await wallet.start_staking())
            assert_equal("Staking", await wallet.staking_status())
            self.wait_until(lambda: node.chainstate_best_block_id() != tip_id_with_genesis_pool, timeout = 15)
            assert_in("Success", await wallet.stop_staking())
            assert_in("Not staking", await wallet.staking_status())

            assert_in("Success", await wallet.sync())

            tip_height_after_staking = int(await wallet.get_best_block_height())

            assert tip_height_after_staking > tip_height_before_staking
            total_staking_reward = block_reward * (tip_height_after_staking - tip_height_before_staking)

            # Pool balance has increased
            pools = await wallet.list_pool_ids()
            assert_equal(len(pools), 1)
            assert_equal(pools[0].pool_id, pool_id)
            assert_equal(Decimal(pools[0].pledge), pool_pledge + total_staking_reward)
            assert_equal(Decimal(pools[0].balance), pool_pledge + total_staking_reward)

        async with self.wallet_controller(node, self.config, self.log, chain_config_args=chain_config_args) as wallet:
            await wallet.open_wallet("pool_creator")

            address = await wallet.new_address()
            assert_in("The transaction was submitted successfully", await wallet.decommission_stake_pool(pool_id, address))

            tip_height = int(await wallet.get_best_block_height())
            self.gen_pos_block(node.mempool_transactions(), tip_height + 1, self.hex_to_dec_array(tip_id_with_genesis_pool))
            assert_in("Success", await wallet.sync())

            unlocked_balance = await wallet.get_coins_balance('unlocked')
            self.assert_approximate_balance(unlocked_balance, initial_balance - pool_pledge)

            locked_balance = await wallet.get_coins_balance('locked')
            self.assert_approximate_balance(locked_balance, pool_pledge + total_staking_reward)

            total_balance = await wallet.get_coins_balance('any')
            self.assert_approximate_balance(total_balance, initial_balance + total_staking_reward)


if __name__ == '__main__':
    WalletCreatePoolForAnotherWalletCLI().main()
