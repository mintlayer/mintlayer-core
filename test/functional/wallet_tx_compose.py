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
"""Wallet transaction compose test

Check that:
* We can create a new wallet,
* get an address
* send coins to the wallet's address
* sync the wallet with the node
* check balance
* get utxos
* create a transaction using the utxo and 2 outputs
* check the fee is as expected
* sign and submit the transaction
"""

import json
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import (make_tx, reward_input, tx_input, ATOMS_PER_COIN)
from test_framework.util import assert_in, assert_equal
from test_framework.mintlayer import mintlayer_hash, block_input_data_obj
from test_framework.wallet_cli_controller import DEFAULT_ACCOUNT_INDEX, TxOutput, WalletCliController

import asyncio
import sys
import random


class WalletComposeTransaction(BitcoinTestFramework):

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
            await wallet.create_wallet()

            # check it is on genesis
            best_block_height = await wallet.get_best_block_height()
            self.log.info(f"best block height = {best_block_height}")
            assert_equal(best_block_height, '0')

            # Get chain tip
            tip_id = node.chainstate_best_block_id()
            self.log.debug(f'Tip: {tip_id}')

            coins_to_send = random.randint(2, 10)
            # new address
            addresses = []
            num_utxos = random.randint(1, 3)
            for _ in range(num_utxos):
                pub_key_bytes = await wallet.new_public_key()
                assert_equal(len(pub_key_bytes), 33)
                addresses.append(pub_key_bytes)

            # Submit a valid transaction
            def make_output(pub_key_bytes):
                return {
                    'Transfer': [
                        { 'Coin': coins_to_send * ATOMS_PER_COIN },
                        { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': pub_key_bytes}}} }
                    ],
                }
            encoded_tx, tx_id = make_tx([reward_input(tip_id)], [make_output(pk) for pk in addresses], 0)

            self.log.debug(f"Encoded transaction {tx_id}: {encoded_tx}")

            assert_in("No transaction found", await wallet.get_transaction(tx_id))

            node.mempool_submit_transaction(encoded_tx, {})
            assert node.mempool_contains_tx(tx_id)

            self.generate_block()
            assert not node.mempool_contains_tx(tx_id)

            # sync the wallet
            assert_in("Success", await wallet.sync())

            assert_in(f"Coins amount: {coins_to_send * len(addresses)}", await wallet.get_balance())

            ## create a new account and get an address
            await wallet.create_new_account()
            await wallet.select_account(1)
            acc1_address = await wallet.new_address()
            await wallet.select_account(DEFAULT_ACCOUNT_INDEX)

            change_address = await wallet.new_address()
            # transfer all except 1 coin to the new acc, and add 0.1 fee
            num_outputs = random.randint(0, len(addresses) - 1)
            outputs = [TxOutput(acc1_address, str(coins_to_send)) for _ in range(num_outputs)] + [ TxOutput(acc1_address, str(coins_to_send - 1)), TxOutput(change_address, "0.9") ]

            # check we have unspent utxos
            utxos = await wallet.list_utxos()
            assert_equal(len(utxos), len(addresses))

            # try to compose an empty transaction should error
            output = await wallet.compose_transaction([], [])
            assert_in("Can't compose a transaction without any inputs", output)

            # compose a transaction with all our utxos and n outputs to the other acc and 1 as change
            output = await wallet.compose_transaction(outputs, utxos, True)
            assert_in("The hex encoded transaction is", output)
            # check the fees include the 0.1 + any extra utxos
            assert_in(f"Coins amount: {((len(addresses) - (num_outputs + 1))*coins_to_send)}.1", output)
            encoded_tx = output.split('\n')[1]

            fees = (len(utxos) - num_outputs - 1) * coins_to_send
            output = await wallet.inspect_transaction(encoded_tx)
            assert_in(f"Transfer({acc1_address}, {coins_to_send-1})", output)
            assert_in(f"Transfer({change_address}, 0.9)", output)
            assert_in(f"Fees that will be paid by the transaction:\nCoins amount: {fees}.1", output)
            assert_in(f"Number of inputs: {len(utxos)}", output)
            assert_in(f"Valid signatures: 0", output)
            assert_in(f"Invalid signatures: 0", output)
            assert_in(f"Missing signatures: {len(utxos)}", output)

            output = await wallet.compose_transaction(outputs, utxos, False)
            assert_in("The hex encoded transaction is", output)
            # check the fees include the 0.1 + any extra utxos
            assert_in(f"Coins amount: {((len(addresses) - (num_outputs + 1))*coins_to_send)}.1", output)
            encoded_ptx = output.split('\n')[1]

            output = await wallet.inspect_transaction(encoded_ptx)
            assert_in(f"Transfer({acc1_address}, {coins_to_send-1})", output)
            assert_in(f"Transfer({change_address}, 0.9)", output)
            assert_in(f"Fees that will be paid by the transaction:\nCoins amount: {fees}.1", output)
            assert_in(f"Number of inputs: {len(utxos)}", output)
            assert_in(f"Valid signatures: 0", output)
            assert_in(f"Invalid signatures: 0", output)
            assert_in(f"Missing signatures: {len(utxos)}", output)

            # partially_signed_tx is bigger than just the tx
            assert len(encoded_tx) < len(encoded_ptx)

            output = await wallet.sign_raw_transaction(encoded_tx)
            assert_in("The transaction has been fully signed and is ready to be broadcast to network.", output)
            signed_tx = output.split('\n')[2]

            output = await wallet.inspect_transaction(signed_tx)
            assert_in(f"Transfer({acc1_address}, {coins_to_send-1})", output)
            assert_in(f"Transfer({change_address}, 0.9)", output)
            assert_in(f"Fees that will be paid by the transaction:\nCoins amount: {fees}.1", output)
            assert_in(f"Number of inputs: {len(utxos)}", output)
            assert_in(f"Valid signatures: {len(utxos)}", output)
            assert_in(f"Invalid signatures: 0", output)
            assert_in(f"Missing signatures: 0", output)
            statuses = '\n'.join(map(lambda idx: f"Signature for input {idx}: FullySigned", range(len(utxos))))
            assert_in(f"All signature statuses:\n{statuses}", output)

            assert_in("The transaction was submitted successfully", await wallet.submit_transaction(signed_tx))

            utxos = await wallet.list_utxos('all', 'unlocked', ['inactive'])
            assert_equal(1, len(utxos))

            # try to compose and sign a transaction with an inactive utxo that is not in chainstate only in the wallet
            output = await wallet.compose_transaction([TxOutput(acc1_address, "0.1")], utxos, True)
            encoded_tx = output.split('\n')[1]
            output = await wallet.sign_raw_transaction(encoded_tx)
            assert_in("The transaction has been fully signed and is ready to be broadcast to network.", output)
            signed_tx2 = output.split('\n')[2]

            transactions = node.mempool_transactions()
            assert_in(signed_tx, transactions)
            self.generate_block()

            assert_in("Success", await wallet.sync())
            # check we have the change
            assert_in(f"Coins amount: 0.9", await wallet.get_balance())
            # and 1 new utxo
            assert_equal(1, len(await wallet.list_utxos()))

            await wallet.select_account(1)
            assert_in(f"Coins amount: {num_outputs * coins_to_send + coins_to_send-1}", await wallet.get_balance())
            assert_equal(num_outputs + 1, len(await wallet.list_utxos()))

            assert_in("The transaction was submitted successfully", await wallet.submit_transaction(signed_tx2))
            self.generate_block()

            # even though the UTXOs are spent and can't be found in the Node's chainstate they can be found in the wallet's cache
            assert_in("Success", await wallet.sync())
            output = await wallet.inspect_transaction(signed_tx2)
            assert_in(f"Transfer({acc1_address}, 0.1)", output)
            assert_in(f"Could not calculate fees", output)
            assert_in(f"Number of inputs: 1", output)
            assert_in(f"Total signatures: 1", output)
            assert_in(f"The signatures could not be verified because the UTXOs were spend or not found", output)


if __name__ == '__main__':
    WalletComposeTransaction().main()

