#!/usr/bin/env python3
#  Copyright (c) 2026 RBB S.r.l
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
"""Wallet utxo spend test.
"""

from scalecodec import ScaleBytes
from test_framework.script import hash160
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import make_tx, reward_input, ATOMS_PER_COIN, signed_tx_obj
from test_framework.util import assert_in, assert_equal
from test_framework.mintlayer import  block_input_data_obj
from test_framework.wallet_cli_controller import WalletCliController
from test_framework.wallet_rpc_controller import UtxoOutpoint

import asyncio
import random


class WalletUtxoSpend(BitcoinTestFramework):
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

    def run_test(self):
        asyncio.run(self.async_test())

    async def async_test(self):
        node = self.nodes[0]

        async with self.wallet_controller(node, self.config, self.log) as wallet:
            await wallet.create_wallet()

            # Fund the wallet from genesis.
            pub_key = await wallet.new_public_key()
            genesis_id = node.chainstate_best_block_id()

            funding_amount = random.randint(2000, 4000)
            output = {
                "Transfer": [
                    { "Coin": funding_amount * ATOMS_PER_COIN },
                    { "PublicKey": { "key": { "Secp256k1Schnorr": { "pubkey_data": pub_key } } } },
                ],
            }
            funding_tx, funding_tx_id = make_tx([reward_input(genesis_id)], [output], 0)
            node.mempool_submit_transaction(funding_tx, {})
            assert node.mempool_contains_tx(funding_tx_id)

            self.generate_block()
            assert_in("Success", await wallet.sync())

            assert_in("Success", await wallet.create_new_account())
            assert_in("Success", await wallet.select_account(1))
            acc1_address = await wallet.new_address()
            assert_in("Success", await wallet.select_account(0))

            address = await wallet.new_address()

            token_decimals = random.randint(2, 10)
            atoms_per_token = 10**token_decimals
            token_id, _, output = await wallet.issue_new_token("TKN", token_decimals, "http://uri", address)
            assert token_id is not None, f"Error issuing a token: {output}"

            self.generate_block()
            assert_in("Success", await wallet.sync())

            token_amount = random.randint(1000, 2000)
            await wallet.mint_tokens_or_fail(token_id, address, token_amount)

            self.generate_block()
            assert_in("Success", await wallet.sync())

            # Fund account1 with coins, so that it can spend htlcs later.
            await wallet.send_to_address_return_tx_id(acc1_address, 100)

            self.generate_block()
            assert_in("Success", await wallet.sync())

            async def spend_utxo_check_tx(
                utxo: UtxoOutpoint,
                output_address: str,
                htlc_secret: str | None,
                is_token: bool,
                expected_amount: int
            ):
                output_address_as_pubkeyhash_hex = node.test_functions_address_to_destination(output_address)

                tx_id = await wallet.spend_utxo_return_tx_id(utxo, output_address, htlc_secret)
                assert node.mempool_contains_tx(tx_id)

                self.generate_block()
                assert_in("Success", await wallet.sync())

                assert not node.mempool_contains_tx(tx_id)

                tx = await wallet.get_raw_signed_transaction(tx_id)
                decoded_tx = signed_tx_obj.decode(ScaleBytes(f"0x{tx}"))

                tx_inputs = decoded_tx["transaction"]["inputs"]
                tx_outputs = decoded_tx["transaction"]["outputs"]

                if is_token:
                    # When spending a token utxo, there should be a coin input to pay fees from.
                    assert_equal(len(tx_inputs), 2)
                    # A coin change output may not be present if the entire coin amount was spent
                    # to pay fees (though in this test this is unlikely to happen).
                    assert(len(tx_outputs) <= 2)
                else:
                    # When spending a coin utxo, no additional inputs or outputs should be needed.
                    assert_equal(len(tx_inputs), 1)
                    assert_equal(len(tx_outputs), 1)

                spent_utxo_input = tx_inputs[0]["Utxo"]
                assert_equal(spent_utxo_input["id"]["Transaction"], f"0x{utxo.id}")
                assert_equal(spent_utxo_input["index"], utxo.index)

                new_utxo_xfer = tx_outputs[0]["Transfer"]

                if is_token:
                    xfer_token_id_hex = new_utxo_xfer[0]["TokenV1"][0]
                    xfer_amount = new_utxo_xfer[0]["TokenV1"][1]

                    xfer_token_id = node.test_functions_dehexify_all_addresses(
                        f"HexifiedTokenId{{{xfer_token_id_hex}}}"
                    )

                    assert_equal(xfer_token_id, token_id)
                    assert_equal(xfer_amount, expected_amount * atoms_per_token)
                else:
                    xfer_amount = new_utxo_xfer[0]["Coin"]
                    expected_amount_atoms = expected_amount * ATOMS_PER_COIN
                    assert \
                        xfer_amount >= expected_amount_atoms - ATOMS_PER_COIN and xfer_amount <= expected_amount_atoms, \
                        f"Unexpected transfer amount {xfer_amount}, should be {expected_amount_atoms} or slightly less"

                # Note: "Address" means PubKeyHash.
                new_utxo_xfer_addr = new_utxo_xfer[1]["Address"].removeprefix("0x")
                assert_equal(f"01{new_utxo_xfer_addr}", output_address_as_pubkeyhash_hex)

            utxos_output_address = await wallet.new_address()

            ############################################################################################################
            # Create and spend non-htlc utxos

            xfer_amount = random.randint(100, 200)
            tx_id = await wallet.send_to_address_return_tx_id(address, xfer_amount)
            await spend_utxo_check_tx(UtxoOutpoint(tx_id, 0), utxos_output_address, None, False, xfer_amount)

            xfer_amount = random.randint(100, 200)
            tx_id = await wallet.send_tokens_to_address_return_tx_id(token_id, address, xfer_amount)
            await spend_utxo_check_tx(UtxoOutpoint(tx_id, 0), utxos_output_address, None, True, xfer_amount)

            ############################################################################################################
            # Creeate and spend htlc utxos

            async def make_htlc_secret():
                # If using wallet-cli, also check the secret generating and hash calculating commands.
                if wallet.is_cli():
                    (secret, hash) = await wallet.generate_htlc_secret()
                    hash_from_secret = await wallet.calc_htlc_secret_hash(secret)
                    assert_equal(hash, hash_from_secret)

                    # Just in case, check hash calculation for a manually generated secret.
                    another_secret_bytes = bytes([random.randint(0, 255) for _ in range(32)])
                    another_hash = hash160(another_secret_bytes).hex()
                    another_hash_from_secret = await wallet.calc_htlc_secret_hash(another_secret_bytes.hex())
                    assert_equal(another_hash, another_hash_from_secret)

                    return (secret, hash)
                else:
                    secret_bytes = bytes([random.randint(0, 255) for _ in range(32)])
                    hash_bytes = hash160(secret_bytes)
                    return (secret_bytes.hex(), hash_bytes.hex())

            mempool_future_timelock_tolerance_blocks = 5

            # The spend address belongs to account 1 and the refund address to account 0.
            # The htlc output will be the first output of the produced tx.
            # The refund timelock is chosen such that when we get to the point of testing the refunding,
            # the tip height is too low for the refund txs to be even accepted to the mempool,
            # but after `mempool_future_timelock_tolerance_blocks` blocks they can be included
            # in a block.
            async def create_htlc(amount: int, token_id: str | None):
                # We'll be generating 3 blocks before attempting the refund - one that icnludes
                # the htlcs creation and one in each call to spend_utxo_check_tx that spends
                # an htlc from account 1.
                htlc_refund_lock_for_blocks = 3 + mempool_future_timelock_tolerance_blocks

                (secret, secret_hash) = await make_htlc_secret()
                result = await wallet.create_htlc_transaction(
                    amount,
                    token_id,
                    secret_hash,
                    acc1_address,
                    address,
                    htlc_refund_lock_for_blocks,
                )
                submit_result = await wallet.submit_transaction(result["tx"])
                assert_in("The transaction was submitted successfully", submit_result)

                return (result["tx_id"], secret)

            coin_htlc1_amount = random.randint(100, 200)
            (coin_htlc1_tx_id, coin_htlc1_secret) = await create_htlc(coin_htlc1_amount, None)

            coin_htlc2_amount = random.randint(100, 200)
            (coin_htlc2_tx_id, coin_htlc2_secret) = await create_htlc(coin_htlc2_amount, None)

            token_htlc1_amount = random.randint(100, 200)
            (token_htlc1_tx_id, token_htlc1_secret) = await create_htlc(token_htlc1_amount, token_id)

            token_htlc2_amount = random.randint(100, 200)
            (token_htlc2_tx_id, token_htlc2_secret) = await create_htlc(token_htlc2_amount, token_id)

            self.generate_block()
            assert_in("Success", await wallet.sync())

            # Try spending the htlcs from account 0, which doesn't own the spend key.
            for (tx_id, htlc_secret) in [
                (coin_htlc1_tx_id, coin_htlc1_secret),
                (coin_htlc2_tx_id, coin_htlc2_secret),
                (token_htlc1_tx_id, token_htlc1_secret),
                (token_htlc2_tx_id, token_htlc2_secret)
            ]:
                error = None
                try:
                    await wallet.spend_utxo_return_tx_id(UtxoOutpoint(tx_id, 0), utxos_output_address, htlc_secret)
                except Exception as e:
                    error = str(e)

                assert_in("This account doesn't have the keys necessary to sign the transaction", error)

            # Switch to account 1
            assert_in("Success", await wallet.select_account(1))
            assert_in("Success", await wallet.sync())

            # Try refunding the htlcs from account 1, which doesn't own the refund key.
            for tx_id in [
                coin_htlc1_tx_id,
                coin_htlc2_tx_id,
                token_htlc1_tx_id,
                token_htlc2_tx_id
            ]:
                error = None
                try:
                    await wallet.spend_utxo_return_tx_id(UtxoOutpoint(tx_id, 0), utxos_output_address, None)
                except Exception as e:
                    error = str(e)

                assert_in("This account doesn't have the keys necessary to sign the transaction", error)

            # Spend coin_htlc2 and token_htlc2 from account 1
            await spend_utxo_check_tx(
                UtxoOutpoint(coin_htlc2_tx_id, 0), utxos_output_address, coin_htlc2_secret, False, coin_htlc2_amount)
            await spend_utxo_check_tx(
                UtxoOutpoint(token_htlc2_tx_id, 0), utxos_output_address, token_htlc2_secret, True, token_htlc2_amount)

            # Switch to account 0
            assert_in("Success", await wallet.select_account(0))
            assert_in("Success", await wallet.sync())

            tip_height = node.chainstate_best_block_height()
            mempool_effective_tip_height = tip_height + mempool_future_timelock_tolerance_blocks

            # Try refunding coin_htlc1 and token_htlc1 from account 0, this should fail because the txs
            # can't be accepted by mempool yet.
            for tx_id in [
                coin_htlc1_tx_id,
                token_htlc1_tx_id
            ]:
                error = None
                try:
                    await wallet.spend_utxo_return_tx_id(UtxoOutpoint(tx_id, 0), utxos_output_address, None)
                except Exception as e:
                    error = str(e)

                assert_in(
                    f"Mempool error: Error verifying input #0: Spending at height {mempool_effective_tip_height}, " +
                    f"locked until height {mempool_effective_tip_height + 1}",
                    error
                )

            # Generate enough blocks so that the txs can be included in the next block.
            for _ in range(0, mempool_future_timelock_tolerance_blocks):
                self.generate_block()
                assert_in("Success", await wallet.sync())

            # Refund coin_htlc1 and token_htlc1 from account 0, this time it should succeed.
            await spend_utxo_check_tx(
                UtxoOutpoint(coin_htlc1_tx_id, 0), utxos_output_address, None, False, coin_htlc1_amount)
            await spend_utxo_check_tx(
                UtxoOutpoint(token_htlc1_tx_id, 0), utxos_output_address, None, True, token_htlc1_amount)

            self.generate_block()
            assert_in("Success", await wallet.sync())


if __name__ == '__main__':
    WalletUtxoSpend().main()
