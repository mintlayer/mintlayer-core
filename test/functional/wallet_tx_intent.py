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
"""Wallet tx intent test
Create a transaction with intent and check
* that the signed message is correct;
* that that the message is signed by prvate keys corresponding to the transaction's input destinations;
* the signatures are correct;
"""

import re
import scalecodec
from scalecodec.base import ScaleBytes, ScaleDecoder
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import (make_tx, reward_input, ATOMS_PER_COIN)
from test_framework.util import assert_in, assert_equal, assert_not_in
from test_framework.mintlayer import block_input_data_obj
from test_framework.wallet_cli_controller import WalletCliController

import asyncio
import sys
import random


class WalletTxIntent(BitcoinTestFramework):
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

        block_input_data = {"PoW": {"reward_destination": "AnyoneCanSpend"}}
        block_input_data = block_input_data_obj.encode(
            block_input_data).to_hex()[2:]

        # create a new block, taking transactions from mempool
        block = node.blockprod_generate_block(
            block_input_data, [], [], "FillSpaceFromMempool")
        node.chainstate_submit_block(block)
        block_id = node.chainstate_best_block_id()

        # Wait for mempool to sync
        self.wait_until(lambda: node.mempool_local_best_block_id()
                        == block_id, timeout=5)

        return block_id

    async def sync_wallet(self, wallet):
        assert_in("Success", await wallet.sync())

    def run_test(self):
        if 'win32' in sys.platform:
            asyncio.set_event_loop_policy(
                asyncio.WindowsProactorEventLoopPolicy())
        asyncio.run(self.async_test())

    # Create a token and mint the specified amount of it spread across several utxos.
    # The resulting coin balance's integer part will equal coin_amount.
    async def setup_currency(self, node, wallet, coin_amount, min_token_amount_per_utxo, max_token_amount_per_utxo, token_utxo_count):
        pub_key_bytes = await wallet.new_public_key()

        tip_id = node.chainstate_best_block_id()
        self.log.debug(f'Tip: {tip_id}')

        # This function will spend 100 coins on issuing the token and 50 times token_utxo_count on minting;
        # also, a portion of a coin will be spent for the transaction fee.
        output = {
            'Transfer': [
                {'Coin': (coin_amount + 100 + token_utxo_count * 50 + 1) * ATOMS_PER_COIN},
                {'PublicKey': {'key': {'Secp256k1Schnorr': {'pubkey_data': pub_key_bytes}}}}
            ],
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

        token_issuer_address = await wallet.new_address()
        self.log.debug(f'token_issuer_address = {token_issuer_address}')

        # Create the token.
        token_id, tx_id, err = await wallet.issue_new_token('FOO', 5, "http://uri", token_issuer_address)
        assert token_id is not None
        assert tx_id is not None
        assert err is None
        self.log.debug(f"token id: {token_id}")

        self.generate_block()

        token_amount = 0
        for i in range(token_utxo_count):
            token_amount_for_utxo = random.randint(min_token_amount_per_utxo, max_token_amount_per_utxo)
            token_amount += token_amount_for_utxo

            token_owner_address = await wallet.new_address()
            self.log.debug(f'token_owner_address #{i} = {token_owner_address}')
            await wallet.mint_tokens_or_fail(token_id, token_owner_address, token_amount_for_utxo)

        self.generate_block()
        await self.sync_wallet(wallet)

        return (token_id, token_amount)

    async def get_tx_inputs(self, wallet, tx):
        inspect_tx_result = await wallet.inspect_transaction(tx)

        pattern = r"=== BEGIN OF INPUTS ===\n(.*)=== END OF INPUTS ==="
        inputs_str = re.search(pattern, inspect_tx_result, re.DOTALL).group(1)

        input_re = re.compile(r"- Transaction\(0x([0-9a-fA-F]+), (\d+)\)")
        inputs = []
        for input_str in inputs_str.splitlines():
            match = input_re.search(input_str)
            inputs.append((match.group(1), int(match.group(2))))

        return inputs

    async def async_test(self):
        node = self.nodes[0]

        async with WalletCliController(node, self.config, self.log) as wallet:
            await wallet.create_wallet('some_wallet')
            dest_addr = await wallet.new_address()
            await wallet.close_wallet()
            await wallet.create_wallet('test_wallet')

            coin_amount = random.randint(100, 200)
            token_utxos_count = random.randint(5, 10)
            (token_id, token_amount) = await self.setup_currency(node, wallet, coin_amount, 50, 250, token_utxos_count)

            async def assert_balances(coin, token):
                await self.sync_wallet(wallet)
                balances = await wallet.get_balance()
                assert_in(f"Coins amount: {coin}", balances)

                if token:
                    assert_in(f"Token: {token_id} amount: {token}", balances)
                else:
                    assert_not_in(token_id, balances)

            await assert_balances(coin=coin_amount, token=token_amount)

            tokens_to_send = random.randint(100, 200)

            utxos = await wallet.list_utxos_raw()

            utxos = [
                (item["outpoint"]["source_id"]["content"]["tx_id"],
                 int(item["outpoint"]["index"]),
                 item["output"]["content"]["destination"]
                ) for item in utxos
            ]

            intent_str = "the_intent"
            (tx, tx_id, signed_intent) = await wallet.make_tx_to_send_tokens_with_intent(token_id, dest_addr, tokens_to_send, intent_str)
            self.generate_block()

            tx_inputs = await self.get_tx_inputs(wallet, tx)

            # Nothing was sent yet
            await assert_balances(coin=coin_amount, token=token_amount)

            tx_input_destinations = []
            for (tx_id_in_input, idx_in_input) in tx_inputs:
                dest = next(dest for (tx_id, idx, dest) in utxos if tx_id == tx_id_in_input and idx_in_input == idx)
                tx_input_destinations.append(dest)

            # Send the tx
            tx_id_when_submitting = await wallet.submit_transaction_return_id(tx)
            assert tx_id == tx_id_when_submitting
            self.generate_block()
            await assert_balances(coin=coin_amount, token=token_amount-tokens_to_send)

            await self.check_signed_intent(intent_str, signed_intent, tx_id, tx_input_destinations)

    async def check_signed_intent(self, intent_str, signed_intent, tx_id, tx_input_destinations):
        node = self.nodes[0]

        self.log.debug(f"tx_id = {tx_id}")
        self.log.debug(f"tx_input_destinations = {tx_input_destinations}")

        byte_vec_encoder = scalecodec.base.RuntimeConfiguration().create_scale_object('Vec<u8>')
        pub_key_encoder = scalecodec.base.RuntimeConfiguration().create_scale_object('PublicKey')
        signature_encoder = scalecodec.base.RuntimeConfiguration().create_scale_object('Signature')
        signed_tx_intent_decoder = ScaleDecoder.get_decoder_class('SignedTransactionIntent')
        pub_key_hash_spend_decoder = ScaleDecoder.get_decoder_class('AuthorizedPublicKeyHashSpend')

        decoded_signed_intent = signed_tx_intent_decoder.decode(ScaleBytes(bytearray.fromhex(signed_intent)))

        signed_message = decoded_signed_intent['signed_message']
        assert signed_message == f"<tx_id:{tx_id};intent:{intent_str}>"

        signed_message_as_hex_encoded_vec = byte_vec_encoder.encode(signed_message.encode()).to_hex().removeprefix('0x')

        message_for_sig_verification = node.test_functions_produce_message_challenge_for_arbitrary_message_signature(
            signed_message_as_hex_encoded_vec)

        signatures = decoded_signed_intent['signatures']
        assert len(signatures) == len(tx_input_destinations)

        for (sig, tx_input_dest) in zip(signatures, tx_input_destinations):
            pub_key_hash_spend = pub_key_hash_spend_decoder.decode(ScaleBytes(bytearray.fromhex(sig.removeprefix('0x'))))

            pub_key = pub_key_hash_spend['public_key']
            pub_key_hex = pub_key_encoder.encode(pub_key).to_hex().removeprefix('0x')

            signature = pub_key_hash_spend['signature']
            signature_hex = signature_encoder.encode(signature).to_hex().removeprefix('0x')

            pubkey_addr = node.test_functions_public_key_to_public_key_address(pub_key_hex)
            pubkeyhash_addr = node.test_functions_public_key_to_public_key_hash_address(pub_key_hex)

            assert tx_input_dest == pubkey_addr or tx_input_dest == pubkeyhash_addr

            sig_valid = node.test_functions_verify_message_with_public_key(pub_key_hex, message_for_sig_verification, signature_hex)
            assert sig_valid

if __name__ == '__main__':
    WalletTxIntent().main()
