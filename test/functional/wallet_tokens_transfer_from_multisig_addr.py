#!/usr/bin/env python3
#  Copyright (c) 2024 RBB S.r.l
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
"""Test the MakeTxToSendTokensFromMultisigAddress command."""

from test_framework.mintlayer import (block_input_data_obj, make_tx, reward_input, ATOMS_PER_COIN)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_in, assert_not_in, assert_equal
from test_framework.wallet_cli_controller import (TokenTxOutput, WalletCliController, DEFAULT_ACCOUNT_INDEX)

import asyncio
import random
import string
import sys
from typing import List, Tuple


class WalletTokensTransferFromMultisigAddr(BitcoinTestFramework):
    def set_test_params(self):
        self.wallet_controller = WalletCliController
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

    async def sync_wallet(self, wallet):
        assert_in("Success", await wallet.sync())

    def run_test(self):
        if 'win32' in sys.platform:
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        asyncio.run(self.async_test())

    # Create 2 tokens called foo and bar and mint the specified amount of each.
    # The resulting coin balance's integer part will equal coin_amount.
    async def setup_coins_and_tokens(self, node, wallet, coin_amount, foo_amount, bar_amount):
        pub_key_bytes = await wallet.new_public_key()

        tip_id = node.chainstate_best_block_id()
        self.log.debug(f'Tip: {tip_id}')

        # This function will spend 2x100 coins on issuing tokens and 2x50 on minting;
        # also, a portion of a coin will be spent for the transaction fee.
        output = {
            'Transfer': [ { 'Coin': (coin_amount + 301) * ATOMS_PER_COIN }, { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': pub_key_bytes}}} } ],
        }
        encoded_tx, tx_id = make_tx([reward_input(tip_id)], [output], 0)

        node.mempool_submit_transaction(encoded_tx, {})
        assert node.mempool_contains_tx(tx_id)

        block_id = self.generate_block()
        assert not node.mempool_contains_tx(tx_id)

        # Sync the wallet
        assert_in("Success", await wallet.sync())
        assert_equal(await wallet.get_best_block_height(), '1')
        assert_equal(await wallet.get_best_block(), block_id)

        address = await wallet.new_address()
        self.log.debug(f'Created address: {address}')

        # Create token foo.
        token_foo_id, token_foo_tx_id, err = await wallet.issue_new_token('FOO', 5, "http://uri", address)
        assert token_foo_id is not None
        assert token_foo_tx_id is not None
        assert err is None
        self.log.debug(f"token foo id: {token_foo_id}")

        # Create token bar.
        token_bar_id, token_bar_tx_id, err = await wallet.issue_new_token('BAR', 10, "http://uri", address)
        assert token_bar_id is not None
        assert token_bar_tx_id is not None
        assert err is None
        self.log.debug(f"token bar id: {token_bar_id}")

        self.generate_block()

        # Mint some foo.
        await wallet.mint_tokens_or_fail(token_foo_id, address, foo_amount)
        # Mint some bar.
        await wallet.mint_tokens_or_fail(token_bar_id, address, bar_amount)

        self.generate_block()
        await self.sync_wallet(wallet)

        return (token_foo_id, token_bar_id)

    async def setup_multisig_addresses(self, wallet, another_pub_key_as_addr, tokens_amounts: List[Tuple[str, int, int]]):
        addr = await wallet.new_address()
        pubkey_as_addr = await wallet.reveal_public_key_as_address(addr)

        ms_addr_1_of_2 = await wallet.add_standalone_multisig_address_get_result(1, [pubkey_as_addr, another_pub_key_as_addr], None, True)
        ms_addr_2_of_2 = await wallet.add_standalone_multisig_address_get_result(2, [pubkey_as_addr, another_pub_key_as_addr], None, True)

        for token, amount1, amount2 in tokens_amounts:
            await wallet.send_tokens_to_address_or_fail(token, ms_addr_1_of_2, amount1)
            await wallet.send_tokens_to_address_or_fail(token, ms_addr_2_of_2, amount2)

        self.generate_block()
        await self.sync_wallet(wallet)

        return (ms_addr_1_of_2, ms_addr_2_of_2)

    async def switch_to_wallet(self, wallet, wallet_name):
        await wallet.close_wallet()
        await wallet.open_wallet(wallet_name)

    async def async_test(self):
        node = self.nodes[0]

        async with self.wallet_controller(node, self.config, self.log) as wallet:
            await wallet.create_wallet('cosigner_wallet')
            cosigner_wallet_addr = await wallet.new_address()
            cosigner_wallet_pub_key_as_addr = await wallet.reveal_public_key_as_address(cosigner_wallet_addr)

            await wallet.close_wallet()
            await wallet.create_wallet('another_wallet')

            another_wallet_addr = await wallet.new_address()

            await wallet.close_wallet()
            await wallet.create_wallet('main_wallet')

            coin_amount = random.randint(10000, 20000)
            foo_amount = random.randint(10000, 20000)
            bar_amount = random.randint(10000, 20000)
            (token_foo_id, token_bar_id) = await self.setup_coins_and_tokens(node, wallet, coin_amount, foo_amount, bar_amount)

            async def assert_balances(coin, foo, bar):
                await self.sync_wallet(wallet)
                balances = await wallet.get_balance()
                assert_in(f"Coins amount: {coin}", balances)

                if foo:
                    assert_in(f"Token: {token_foo_id} amount: {foo}", balances)
                else:
                    assert_not_in(token_foo_id, balances)

                if bar:
                    assert_in(f"Token: {token_bar_id} amount: {bar}", balances)
                else:
                    assert_not_in(token_bar_id, balances)

            await assert_balances(coin=coin_amount, foo=foo_amount, bar=bar_amount)

            main_wlt_rem_foo = foo_amount
            main_wlt_rem_bar = bar_amount

            foos_to_send1 = random.randint(1000, 2000)
            foos_to_send2 = random.randint(1000, 2000)
            (ms_addr_1_of_2_with_foo, ms_addr_2_of_2_with_foo) = await self.setup_multisig_addresses(
                wallet, cosigner_wallet_pub_key_as_addr, [(token_foo_id, foos_to_send1, foos_to_send2)])

            main_wlt_rem_foo -= foos_to_send1 + foos_to_send2

            await assert_balances(coin=coin_amount, foo=main_wlt_rem_foo, bar=main_wlt_rem_bar)

            foos_to_send1 = random.randint(1000, 2000)
            foos_to_send2 = random.randint(1000, 2000)
            bars_to_send1 = random.randint(1000, 2000)
            bars_to_send2 = random.randint(1000, 2000)
            (ms_addr_1_of_2_with_foo_bar, ms_addr_2_of_2_with_foo_bar) = await self.setup_multisig_addresses(
                wallet, cosigner_wallet_pub_key_as_addr,
                [(token_foo_id, foos_to_send1, foos_to_send2), (token_bar_id, bars_to_send1, bars_to_send2)])

            main_wlt_rem_foo -= foos_to_send1 + foos_to_send2
            main_wlt_rem_bar -= bars_to_send1 + bars_to_send2

            await assert_balances(coin=coin_amount, foo=main_wlt_rem_foo, bar=main_wlt_rem_bar)

            # Now start creating transactions to send tokens from the multisig address to another_wallet_addr,

            dest_addr = another_wallet_addr

            # Sanity check - another_wallet has zero balances.
            await self.switch_to_wallet(wallet, 'another_wallet')
            await assert_balances(coin=0, foo=0, bar=0)
            await self.switch_to_wallet(wallet, 'main_wallet')

            dest_wallet_foos = 0
            dest_wallet_bars = 0

            foos_to_send = random.randint(100, 200)
            fully_signed_tx_with_foo = await wallet.make_tx_to_send_tokens_from_multisig_address_expect_fully_signed(
                ms_addr_1_of_2_with_foo, [TokenTxOutput(token_foo_id, dest_addr, str(foos_to_send))], None)

            assert_in("The transaction was submitted successfully", await wallet.submit_transaction(fully_signed_tx_with_foo))
            self.generate_block()

            dest_wallet_foos += foos_to_send

            await self.switch_to_wallet(wallet, 'another_wallet')
            await assert_balances(coin=0, foo=dest_wallet_foos, bar=dest_wallet_bars)
            await self.switch_to_wallet(wallet, 'main_wallet')

            foos_to_send = random.randint(100, 200)
            (partially_signed_tx_with_foo, siginfo) = await wallet.make_tx_to_send_tokens_from_multisig_address_expect_partially_signed(
                ms_addr_2_of_2_with_foo, [TokenTxOutput(token_foo_id, dest_addr, str(foos_to_send))], None)
            assert len(siginfo) == 1
            assert {(s.num_signatures, s.required_signatures) for s in siginfo} == {(1, 2)}

            await self.switch_to_wallet(wallet, 'cosigner_wallet')
            fully_signed_tx_with_foo2 = await wallet.sign_raw_transaction_expect_fully_signed(partially_signed_tx_with_foo)
            await self.switch_to_wallet(wallet, 'main_wallet')

            assert_in("The transaction was submitted successfully", await wallet.submit_transaction(fully_signed_tx_with_foo2))
            self.generate_block()

            dest_wallet_foos += foos_to_send

            await self.switch_to_wallet(wallet, 'another_wallet')
            await assert_balances(coin=0, foo=dest_wallet_foos, bar=dest_wallet_bars)
            await self.switch_to_wallet(wallet, 'main_wallet')

            foos_to_send = random.randint(100, 200)
            bars_to_send = random.randint(100, 200)
            fully_signed_tx_with_foo_bar = await wallet.make_tx_to_send_tokens_from_multisig_address_expect_fully_signed(
                ms_addr_1_of_2_with_foo_bar, [TokenTxOutput(token_foo_id, dest_addr, str(foos_to_send)),
                    TokenTxOutput(token_bar_id, dest_addr, str(bars_to_send))], None)

            assert_in("The transaction was submitted successfully", await wallet.submit_transaction(fully_signed_tx_with_foo_bar))
            self.generate_block()

            dest_wallet_foos += foos_to_send
            dest_wallet_bars += bars_to_send

            await self.switch_to_wallet(wallet, 'another_wallet')
            await assert_balances(coin=0, foo=dest_wallet_foos, bar=dest_wallet_bars)
            await self.switch_to_wallet(wallet, 'main_wallet')

            foos_to_send = random.randint(100, 200)
            bars_to_send = random.randint(100, 200)
            (partially_signed_tx_with_foo_bar, siginfo) = await wallet.make_tx_to_send_tokens_from_multisig_address_expect_partially_signed(
                ms_addr_2_of_2_with_foo_bar, [TokenTxOutput(token_foo_id, dest_addr, str(foos_to_send)),
                    TokenTxOutput(token_bar_id, dest_addr, str(bars_to_send))], None)
            assert len(siginfo) == 2
            assert {(s.num_signatures, s.required_signatures) for s in siginfo} == {(1, 2)}

            await self.switch_to_wallet(wallet, 'cosigner_wallet')
            fully_signed_tx_with_foo_bar2 = await wallet.sign_raw_transaction_expect_fully_signed(partially_signed_tx_with_foo_bar)
            await self.switch_to_wallet(wallet, 'main_wallet')

            assert_in("The transaction was submitted successfully", await wallet.submit_transaction(fully_signed_tx_with_foo_bar2))
            self.generate_block()

            dest_wallet_foos += foos_to_send
            dest_wallet_bars += bars_to_send

            await self.switch_to_wallet(wallet, 'another_wallet')
            await assert_balances(coin=0, foo=dest_wallet_foos, bar=dest_wallet_bars)
            await self.switch_to_wallet(wallet, 'main_wallet')

            # The main wallet still the same balances
            await assert_balances(coin=coin_amount, foo=main_wlt_rem_foo, bar=main_wlt_rem_bar)

            # Now create one more tx, this time sending the fee change to dest_addr as well.
            # Note that since all coins belong to a single utxo, this will move all coins to dest_addr.

            foos_to_send = random.randint(100, 200)
            bars_to_send = random.randint(100, 200)
            (partially_signed_tx_with_foo_bar2, siginfo) = await wallet.make_tx_to_send_tokens_from_multisig_address_expect_partially_signed(
                ms_addr_2_of_2_with_foo_bar, [TokenTxOutput(token_foo_id, dest_addr, str(foos_to_send)),
                    TokenTxOutput(token_bar_id, dest_addr, str(bars_to_send))], dest_addr)
            assert len(siginfo) == 2
            assert {(s.num_signatures, s.required_signatures) for s in siginfo} == {(1, 2)}

            await self.switch_to_wallet(wallet, 'cosigner_wallet')
            fully_signed_tx_with_foo_bar3 = await wallet.sign_raw_transaction_expect_fully_signed(partially_signed_tx_with_foo_bar2)
            await self.switch_to_wallet(wallet, 'main_wallet')

            assert_in("The transaction was submitted successfully", await wallet.submit_transaction(fully_signed_tx_with_foo_bar3))
            self.generate_block()

            dest_wallet_foos += foos_to_send
            dest_wallet_bars += bars_to_send

            await assert_balances(coin=0, foo=main_wlt_rem_foo, bar=main_wlt_rem_bar)

            await self.switch_to_wallet(wallet, 'another_wallet')
            await assert_balances(coin=coin_amount, foo=dest_wallet_foos, bar=dest_wallet_bars)


if __name__ == '__main__':
    WalletTokensTransferFromMultisigAddr().main()
