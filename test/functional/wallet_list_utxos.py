#!/usr/bin/env python3
#  Copyright (c) 2025 RBB S.r.l
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
"""Wallet utxo listing test.

* Issue and mint two tokens with non-default decimals.
* Send some amounts of the tokens and coins to normal addresses and to a multisig address
  inside the wallet.
* Check the result of account-utxos and standalone-multisig-utxos; in particular, check that
  the returned decimal amounts are correct.
"""

import asyncio
import random
from decimal import Decimal

from test_framework.mintlayer import (
    ATOMS_PER_COIN, COINS_NUM_DECIMALS,
    block_input_data_obj, make_tx, reward_input, random_decimal_amount
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_in
from test_framework.wallet_cli_controller import WalletCliController
from test_framework.wallet_rpc_controller import WalletRpcController

class WalletListUtxos(BitcoinTestFramework):
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

        # Create a new block, taking transactions from mempool
        block = node.blockprod_generate_block(block_input_data, [], [], "FillSpaceFromMempool")
        node.chainstate_submit_block(block)
        block_id = node.chainstate_best_block_id()

        # Wait for mempool to sync
        self.wait_until(lambda: node.mempool_local_best_block_id() == block_id, timeout = 5)

        return block_id

    async def switch_to_wallet(self, wallet, wallet_name):
        await wallet.close_wallet()
        await wallet.open_wallet(wallet_name)

    def run_test(self):
        asyncio.run(self.async_test())

    async def issue_and_mint_tokens(
        self, wallet: WalletCliController | WalletRpcController, dest_addr: str, num_decimals: int, to_mint: int
    ) -> str:
        ticker = f"TKN{num_decimals}"
        token_id, _, _ = await wallet.issue_new_token(ticker, num_decimals, "http://uri", dest_addr)
        assert token_id is not None
        self.log.info(f"New token issued: {token_id}")

        self.generate_block()
        assert_in("Success", await wallet.sync())

        await wallet.mint_tokens_or_fail(token_id, dest_addr, to_mint)
        self.log.info(f"Minted {to_mint} of {token_id}")

        self.generate_block()
        assert_in("Success", await wallet.sync())

        return token_id

    async def async_test(self):
        node = self.nodes[0]

        async with self.wallet_controller(node, self.config, self.log) as wallet:
            await wallet.create_wallet()

            genesis_id = node.chainstate_best_block_id()

            address0 = await wallet.new_address()
            address1 = await wallet.new_address()
            address2 = await wallet.new_address()

            pub_key_bytes = await wallet.new_public_key(address0)

            outputs = [{
                'Transfer': [
                    { 'Coin': random.randint(1000, 2000) * ATOMS_PER_COIN },
                    { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': pub_key_bytes}}} }
                ],
            }]
            encoded_tx, _ = make_tx([reward_input(genesis_id)], outputs, 0)
            await wallet.submit_transaction(encoded_tx)

            self.generate_block()
            assert_in("Success", await wallet.sync())

            multisig_pub_keys = []
            for _ in range(0, 2):
                pub_key = await wallet.reveal_public_key_as_address(await wallet.new_address())
                multisig_pub_keys.append(pub_key)

            multisig_address = await wallet.add_standalone_multisig_address_get_result(1, multisig_pub_keys, "label")

            token1_decimals = 2
            token1_total_amount = random.randint(1000, 2000)
            token1_id = await self.issue_and_mint_tokens(wallet, address0, token1_decimals, token1_total_amount)

            token2_decimals = 18
            token2_total_amount = random.randint(1000, 2000)
            token2_id = await self.issue_and_mint_tokens(wallet, address0, token2_decimals, token2_total_amount)

            atoms_per_token1 = 10**token1_decimals
            atoms_per_token2 = 10**token2_decimals

            ########################################################################################
            # Send tokens and coins to various addresses

            coins_on_ms_addr = random_decimal_amount(100, 200, COINS_NUM_DECIMALS)
            await wallet.send_to_address(multisig_address, coins_on_ms_addr)

            token1_on_ms_addr = random_decimal_amount(100, 200, token1_decimals)
            await wallet.send_tokens_to_address(token1_id, multisig_address, token1_on_ms_addr)
            token1_on_addr1 = random_decimal_amount(100, 200, token1_decimals)
            await wallet.send_tokens_to_address(token1_id, address1, token1_on_addr1)
            token1_on_change_addr = token1_total_amount - token1_on_ms_addr - token1_on_addr1

            token2_on_ms_addr = random_decimal_amount(100, 200, token2_decimals)
            await wallet.send_tokens_to_address(token2_id, multisig_address, token2_on_ms_addr)
            token2_on_addr2 = random_decimal_amount(100, 200, token2_decimals)
            await wallet.send_tokens_to_address(token2_id, address2, token2_on_addr2)
            token2_on_change_addr = token2_total_amount - token2_on_ms_addr - token2_on_addr2

            # Note: this must be the last tx to ensure that this coins UTXO is not spent.
            coins_on_addr0 = random_decimal_amount(100, 200, COINS_NUM_DECIMALS)
            await wallet.send_to_address(address0, coins_on_addr0)

            self.generate_block()
            assert_in("Success", await wallet.sync())

            # There should be 2 normal UTXOs for coins - one on addr0 (coins_on_addr0) and one
            # on a change address (the rest)
            coins_balance = await wallet.get_coins_balance()
            coins_on_change_addr = coins_balance - coins_on_addr0

            atoms_per_asset = {
                "coin": ATOMS_PER_COIN,
                token1_id: atoms_per_token1,
                token2_id: atoms_per_token2
            }

            # Return a list of tuples (asset_name, dest, decimal_amount), where asset_name is "coin"
            # or a token id.
            # Check that the decimal amount is consistent with the amount of atoms.
            def check_and_simplify_utxos(utxos):
                simplified_utxo = []
                for utxo in utxos:
                    assert_equal(utxo["output"]["type"], "Transfer")

                    dest = utxo["output"]["content"]["destination"]
                    asset_type = utxo["output"]["content"]["value"]["type"]
                    amount = utxo["output"]["content"]["value"]["content"]["amount"]
                    asset_name = "coin" if asset_type == "Coin" else utxo["output"]["content"]["value"]["content"]["id"]

                    decimal_amount = Decimal(amount["decimal"])
                    atoms_amount = int(amount["atoms"])
                    assert_equal(decimal_amount * atoms_per_asset[asset_name], atoms_amount)

                    simplified_utxo.append((asset_name, dest, decimal_amount))
                return simplified_utxo

            ########################################################################################
            # Check normal UTXOs

            utxos = await wallet.list_utxos_raw()
            utxos = check_and_simplify_utxos(utxos)
            assert_equal(len(utxos), 6)

            # Check normal coin UTXOs
            coin_utxos = [utxo for utxo in utxos if utxo[0] == "coin"]
            assert_equal(len(coin_utxos), 2)
            coin_addr0_utxo = next(utxo for utxo in coin_utxos if utxo[1] == address0)
            coin_change_utxo = next(utxo for utxo in coin_utxos if utxo[1] != address0)
            assert_equal(coin_addr0_utxo[2], coins_on_addr0)
            assert_equal(coin_change_utxo[2], coins_on_change_addr)

            # Check normal token1 UTXOs
            token1_utxos = [utxo for utxo in utxos if utxo[0] == token1_id]
            assert_equal(len(token1_utxos), 2)
            token1_addr1_utxo = next(utxo for utxo in token1_utxos if utxo[1] == address1)
            token1_change_utxo = next(utxo for utxo in token1_utxos if utxo[1] != address1)
            assert_equal(token1_addr1_utxo[2], token1_on_addr1)
            assert_equal(token1_change_utxo[2], token1_on_change_addr)

            # Check normal token2 UTXOs
            token2_utxos = [utxo for utxo in utxos if utxo[0] == token2_id]
            assert_equal(len(token2_utxos), 2)
            token2_addr2_utxo = next(utxo for utxo in token2_utxos if utxo[1] == address2)
            token2_change_utxo = next(utxo for utxo in token2_utxos if utxo[1] != address2)
            assert_equal(token2_addr2_utxo[2], token2_on_addr2)
            assert_equal(token2_change_utxo[2], token2_on_change_addr)

            ########################################################################################
            # Check multisig UTXOs

            ms_utxos = await wallet.list_multisig_utxos_raw()
            ms_utxos = check_and_simplify_utxos(ms_utxos)
            assert_equal(len(ms_utxos), 3)

            # Check multisig coin UTXOs
            coin_utxos = [utxo for utxo in ms_utxos if utxo[0] == "coin"]
            assert_equal(len(coin_utxos), 1)
            assert_equal(coin_utxos[0][1], multisig_address)
            assert_equal(coin_utxos[0][2], coins_on_ms_addr)

            # Check multisig token1 UTXOs
            token1_utxos = [utxo for utxo in ms_utxos if utxo[0] == token1_id]
            assert_equal(len(token1_utxos), 1)
            assert_equal(token1_utxos[0][1], multisig_address)
            assert_equal(token1_utxos[0][2], token1_on_ms_addr)

            # Check multisig token2 UTXOs
            token2_utxos = [utxo for utxo in ms_utxos if utxo[0] == token2_id]
            assert_equal(len(token2_utxos), 1)
            assert_equal(token2_utxos[0][1], multisig_address)
            assert_equal(token2_utxos[0][2], token2_on_ms_addr)


if __name__ == '__main__':
    WalletListUtxos().main()
