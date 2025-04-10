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
"""Wallet watch standalone multisig address test

Check that:
* We can create N new wallets,
* get public keys from each one
* create a multisig address from them
* send coins to the multisig address
* compose a transaction that spends from the multisig utxo
* sign the tx with min number of signatures
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import (make_tx, reward_input, ATOMS_PER_COIN)
from test_framework.util import assert_in, assert_equal, assert_not_in
from test_framework.mintlayer import block_input_data_obj
from test_framework.wallet_cli_controller import TxOutput, WalletCliController

import asyncio
import sys
import random


class WalletSubmitTransaction(BitcoinTestFramework):

    def set_test_params(self):
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
        if 'win32' in sys.platform:
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        asyncio.run(self.async_test())

    async def async_test(self):
        node = self.nodes[0]
        async with WalletCliController(node, self.config, self.log) as wallet:
            # new wallet
            await wallet.create_wallet('wallet0')

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
            encoded_tx, receive_coins_tx_id = make_tx([reward_input(tip_id)], [output], 0)

            self.log.debug(f"Encoded transaction {receive_coins_tx_id}: {encoded_tx}")

            assert_in("No transaction found", await wallet.get_transaction(receive_coins_tx_id))

            store_tx_in_wallet = random.choice([True, False])
            assert_in("The transaction was submitted successfully", await wallet.submit_transaction(encoded_tx, not store_tx_in_wallet))

            if store_tx_in_wallet:
                assert_in(f"Coins amount: {coins_to_send}", await wallet.get_balance(utxo_states=['inactive']))
            else:
                assert_in(f"Coins amount: 0", await wallet.get_balance(utxo_states=['inactive']))

            assert node.mempool_contains_tx(receive_coins_tx_id)

            self.generate_block()
            assert not node.mempool_contains_tx(receive_coins_tx_id)

            # sync the wallet
            assert_in("Success", await wallet.sync())


            # create more wallets
            num_wallets = random.randint(2, 32)
            min_required_signatures = random.randint(1, num_wallets)

            pub_key = await wallet.reveal_public_key_as_address(await wallet.new_address())
            public_keys = [pub_key]

            # empty public keys for multisig
            assert_in("Public keys vector is empty", await wallet.add_standalone_multisig_address(1, []))

            # invalid public key address
            assert_in("Provided address to create a Multisig address at index 1 is not a valid public key", await wallet.add_standalone_multisig_address(1, [pub_key, "invalid-pub-key"]))

            # min_required_signatures is 0
            assert_in("Minimum number of signatures can't be 0", await wallet.add_standalone_multisig_address(0, [pub_key]))

            # more signatures than public keys
            assert_in("More required signatures than public keys", await wallet.add_standalone_multisig_address(100, [pub_key]))

            # min_required_signatures is over 32
            assert_in("Too many public keys, more than allowed", await wallet.add_standalone_multisig_address(100, [pub_key] * 100))

            for i in range(1, num_wallets):
                await wallet.close_wallet()
                await wallet.create_wallet(f'wallet{i}')
                assert_in("Success", await wallet.sync())
                pub_key = await wallet.reveal_public_key_as_address(await wallet.new_address())
                public_keys.append(pub_key)


            # add the multisig address to all wallets
            multisig_address = ''
            for i in range(num_wallets):
                await wallet.close_wallet()
                await wallet.open_wallet(f'wallet{i}')

                label = 'some_label' if random.choice([True, False]) else None
                output = await wallet.add_standalone_multisig_address(min_required_signatures, public_keys, label)
                assert_in("Success. The following new multisig address has been added to the account", output)
                multisig_address = output.splitlines()[1]

                output = await wallet.get_standalone_addresses()
                label = label if label else ''
                assert_in(f"{multisig_address} | Multisig | {label}", output)

                new_label = 'some_new_label' if random.choice([True, False]) else None
                output = await wallet.standalone_address_label_rename(multisig_address, new_label)
                assert_in("Success, the label has been changed.", output)
                output = await wallet.get_standalone_addresses()
                new_label = new_label if new_label else ''
                assert_in(f"{multisig_address} | Multisig | {new_label}", output)

                # try to add it again should return an error that it already exists
                output = await wallet.add_standalone_multisig_address(min_required_signatures, public_keys, label)
                assert_in("Standalone address already exists", output)

            # send some coins to the multisig address
            await wallet.close_wallet()
            await wallet.open_wallet('wallet0')
            output = await wallet.send_to_address(multisig_address, 1)
            assert_in("The transaction was submitted successfully", output)
            multisig_tx_id = output.splitlines()[-1]
            self.generate_block()
            assert not node.mempool_contains_tx(multisig_tx_id)
            assert_not_in("No transaction found", await wallet.get_raw_signed_transaction(multisig_tx_id))


            wallet_to_take_coins = random.choice(range(1, num_wallets))
            await wallet.close_wallet()
            await wallet.open_wallet(f'wallet{wallet_to_take_coins}')
            assert_in("Success", await wallet.sync())

            assert_not_in("No transaction found", await wallet.get_raw_signed_transaction(multisig_tx_id))
            # compose a transaction to spend from the multisig_address
            address = await wallet.new_address()
            utxos = await wallet.list_multisig_utxos()
            coins_from_multisig = '0.1'
            outputs = [TxOutput(address, coins_from_multisig) ]
            output = await wallet.compose_transaction(outputs, utxos, True)
            assert_in("The hex encoded transaction is", output)
            encoded_tx = output.split('\n')[1]

            # sign the transaction from N random wallets
            random_wallets = random.sample(range(0, num_wallets), min_required_signatures)
            for i, wallet_id in enumerate(random_wallets[:-1]):
                await wallet.close_wallet()
                await wallet.open_wallet(f'wallet{wallet_id}')
                assert_in("Success", await wallet.sync())

                output = await wallet.sign_raw_transaction(encoded_tx)
                assert_in("Not all transaction inputs have been signed.", output)
                assert_in(f"PartialMultisig having {i+1} out of {min_required_signatures} required signatures", output)
                encoded_tx = output.split('\n')[7]

            # signing it with the last one should fully sign it
            wallet_id = random_wallets[-1]
            await wallet.close_wallet()
            await wallet.open_wallet(f'wallet{wallet_id}')
            assert_in("Success", await wallet.sync())

            output = await wallet.sign_raw_transaction(encoded_tx)
            assert_in("The transaction has been fully signed and is ready to be broadcast to network.", output)
            signed_tx = output.split('\n')[2]

            output = await wallet.get_standalone_address_details(multisig_address)
            assert_in(f"Address: {multisig_address}", output)
            assert_in(f"min_required_signatures: {min_required_signatures}", output)
            for pk in public_keys:
                assert_in(pk, output)
            assert_in(f"\nBalances:\nCoins amount: 1", output)

            assert_in("The transaction was submitted successfully", await wallet.submit_transaction(signed_tx))
            self.generate_block()

            await wallet.close_wallet()
            await wallet.open_wallet(f'wallet{wallet_to_take_coins}')
            assert_in("Success", await wallet.sync())

            # check we have received the coins from the multisig
            assert_in(f"Coins amount: {coins_from_multisig}", await wallet.get_balance())

            output = await wallet.get_standalone_address_details(multisig_address)
            assert_in(f"Address: {multisig_address}", output)
            assert_in(f"min_required_signatures: {min_required_signatures}", output)
            for pk in public_keys:
                assert_in(pk, output)
            # check we have spent from the multisig address
            assert_in(f"\nBalances:\nCoins amount: 0", output)


if __name__ == '__main__':
    WalletSubmitTransaction().main()


