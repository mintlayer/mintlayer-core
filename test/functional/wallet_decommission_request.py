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
"""Wallet decommission request test

Check that:
* We can create a new wallet,
* create 2 accounts
* generate decommission keys from account1
* create a stake pool from account0 and provide decommission keys from account1
* create a decommission request from account0
* sign decommission request from account1 and submit a tx with it
* check that the pool was decommissioned
"""

from test_framework.mintlayer import (ATOMS_PER_COIN, make_tx, reward_input)
from test_framework.util import assert_equal, assert_in
from test_framework.wallet_cli_controller import WalletCliController
from wallet_pos_test_base import WalletPOSTestBase


class WalletDecommissionRequest(WalletPOSTestBase):

    async def async_test(self):
        node = self.nodes[0]
        decommission_address = ""

        chain_config_args = self.wallet_chain_config_args()

        async with WalletCliController(node, self.config, self.log, wallet_args=["--cold-wallet"], chain_config_args=chain_config_args) as wallet:
            # new cold wallet
            await wallet.create_wallet("cold_wallet")

            decommission_address = await wallet.new_address()

        decommission_req = ""

        async with WalletCliController(node, self.config, self.log, chain_config_args=chain_config_args) as wallet:
            # new hot wallet
            await wallet.create_wallet("hot_wallet")

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
                'Transfer': [ { 'Coin': 50_000 * ATOMS_PER_COIN }, { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': pub_key_bytes}}} } ],
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
            assert_in("Coins amount: 50000", balance)

            assert_in("The transaction was submitted successfully", await wallet.create_stake_pool(40000, 0, 0.5, decommission_address))
            transactions = node.mempool_transactions()

            self.gen_pos_block(transactions, 2)
            assert_in("Success", await wallet.sync())

            pools = await wallet.list_pool_ids()
            assert_equal(len(pools), 1)
            assert_equal(pools[0].pledge, '40000')
            assert_equal(pools[0].balance, '40000')
            tip_id_with_genesis_pool = node.chainstate_best_block_id()

            if self.use_wallet_to_produce_block:
                # produce block with the wallet so that utxo of a pool changes from CreateStakePool to ProduceBlockWithStakePool
                assert_in("Staking started successfully", await wallet.start_staking())
                self.wait_until(lambda: node.chainstate_best_block_id() != tip_id_with_genesis_pool, timeout = 15)
                assert_in("Success", await wallet.stop_staking())

            # try decommission from hot wallet
            address = await wallet.new_address()
            assert (await wallet.decommission_stake_pool(pools[0].pool_id, address)).startswith("Wallet controller error: Wallet error: Failed to completely sign")

            # create decommission request
            decommission_req_output = await wallet.decommission_stake_pool_request(pools[0].pool_id, address)
            decommission_req = decommission_req_output.split('\n')[2]

            # try to sign decommission request from hot wallet
            assert_in("Not all transaction inputs have been signed",
                       await wallet.sign_raw_transaction(decommission_req))

        decommission_signed_tx = ""

        async with WalletCliController(node, self.config, self.log, wallet_args=["--cold-wallet"], chain_config_args=chain_config_args) as wallet:
            # open cold wallet
            await wallet.open_wallet("cold_wallet")

            # sign decommission request
            decommission_signed_tx_output = await wallet.sign_raw_transaction(decommission_req)
            decommission_signed_tx = decommission_signed_tx_output.split('\n')[2]

        async with WalletCliController(node, self.config, self.log, chain_config_args=chain_config_args) as wallet:
            # open hot wallet
            await wallet.open_wallet("hot_wallet")

            assert_in("The transaction was submitted successfully", await wallet.submit_transaction(decommission_signed_tx))

            transactions = node.mempool_transactions()
            assert_in(decommission_signed_tx, transactions)

            tip_height = await wallet.get_best_block_height()
            self.gen_pos_block(transactions, int(tip_height) + 1, self.hex_to_dec_array(tip_id_with_genesis_pool))
            assert_in("Success", await wallet.sync())

            pools = await wallet.list_pool_ids()
            assert_equal(len(pools), 0)

            # check the locked balance is equal to the genesis pool balance
            locked_utxos = await wallet.list_utxos('all', with_locked='locked')
            assert_equal(len(locked_utxos), 1)

# `use_wallet_to_produce_block` indicates whether a test should use a pool created by a wallet to produce block
# `exit_on_success` indicates if the process should exit or continue and run next test case
def wallet_decommission_request_test_case(use_wallet_to_produce_block, exit_on_success):
    tf = WalletDecommissionRequest()
    tf.use_wallet_to_produce_block = use_wallet_to_produce_block
    tf.main(exit_on_success)

if __name__ == '__main__':
    wallet_decommission_request_test_case(False, False)
    wallet_decommission_request_test_case(True, True)
