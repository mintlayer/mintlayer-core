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
"""Wallet cold wallet send request test

Check that:
* We can create a new cold wallet,
* issue a new address
* send some coins to that address
* create a new hot wallet
* from the hot wallet create a send request using the cold wallet's utxo
* sign the new tx with the cold wallet
* send it with the hot wallet
"""

import base64
from random import choice, randint
import scalecodec
from scalecodec.base import ScaleBytes
from test_framework.authproxy import JSONRPCException
from test_framework.mintlayer import (
    block_input_data_obj,
    signed_tx_obj,
    ATOMS_PER_COIN,
)
from test_framework.segwit_addr import bech32_decode
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import (make_tx, reward_input)
from test_framework.util import assert_equal, assert_greater_than_or_equal, assert_in
from test_framework.wallet_cli_controller import UtxoOutpoint, WalletCliController

import asyncio
import sys
import time

def bech32_decode2(bech32_string):
    # Constants for the Bech32 encoding
    CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    BECH32_SEPARATOR = '1'

    # Helper function to convert between integers and base32 characters
    def char_to_int(char):
        return CHARSET.find(char)

    def int_to_char(integer):
        return CHARSET[integer]

    # Ensure the string is lowercase for compatibility
    bech32_string = bech32_string.lower()

    # Check for the presence of separator '1'
    if BECH32_SEPARATOR not in bech32_string:
        raise ValueError("Missing separator '1' in Bech32 string")

    # Split the Bech32 string into human-readable part and data part
    hrp, data_part = bech32_string.split(BECH32_SEPARATOR, 1)

    for char in data_part:
        if char not in CHARSET:
            raise ValueError(f"Invalid characters in Bech32 string '{char}'")

    # Check for valid characters in the string
    if any(char not in CHARSET for char in data_part):
        raise ValueError("Invalid characters in Bech32 string")

    # Ensure the human-readable part and data part are not empty
    if not hrp or not data_part:
        raise ValueError("Invalid Bech32 string format")

    # Convert the human-readable part and data part to integers
    hrp_int = [char_to_int(char) for char in hrp]
    data_int = [char_to_int(char) for char in data_part]

    # Verify the checksum
    # if not bech32_verify_checksum(hrp_int, data_int):
    #     raise ValueError("Invalid Bech32 checksum")

    # Remove the checksum from the data part
    data_int = data_int[:-6]

    # Convert the data part to bytes
    data_bytes = bytes(data_int)

    return hrp, data_bytes


def bech32_verify_checksum(hrp_int, data_int):
    """Verify the checksum of a Bech32 string."""
    GENERATOR_POLYNOMIAL = 0x3D6E6AED9EB10A99

    # Concatenate the human-readable part and data part
    values = hrp_int + data_int

    # Calculate the checksum
    checksum = bech32_polymod(values) ^ GENERATOR_POLYNOMIAL

    # Verify that the checksum is zero
    return checksum == 0


def bech32_polymod(values):
    """Calculate the Bech32 polymod."""
    GENERATOR = [
        0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd,
        0x2a1462b3, 0x362a7a0d, 0x2e8be413, 0x28e9b7f0,
        0x36d5ebe9, 0x2b60a476, 0x383929a7, 0x3c4a37e3,
    ]

    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= (top >> i) & 1 if (value >> i) & 1 else 0
            chk ^= GENERATOR[i]

    return chk



"""
[
    {'Transfer': (
        {'Coin': 100000000000},
        {'Address': '0x8b87696b633ceb51f10fa9c334f42fec6f85780e'}
        )
     },
    {'Transfer': (
        {'Coin': 4999899999999805},
        {'PublicKey': {'key': {'Secp256k1Schnorr':
                               {'pubkey_data': '0x02cdee206d3fd4b770a6489877e85fcf580401207e43a8508a121f5e58b0ea3bc8'}
                               }}}
        )
     }
]
"""
def get_destination(dest):
    if 'Address' in dest:
        return dest['Address']
    return dest['PublicKey']['key']['Secp256k1Schnorr']['pubkey_data']

def get_transfer_coins_and_address(output):
    transfer = output['Transfer']
    coins = transfer[0]['Coin']
    dest = transfer[1]
    return (coins, get_destination(dest))

class WalletColdSend(BitcoinTestFramework):

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

        block_input_data = { "PoW": { "reward_destination": "AnyoneCanSpend" } }
        block_input_data = block_input_data_obj.encode(block_input_data).to_hex()[2:]

        # create a new block, taking transactions from mempool
        block = node.blockprod_generate_block(block_input_data, [], [], "FillSpaceFromMempool")
        node.chainstate_submit_block(block)
        block_id = node.chainstate_best_block_id()

        # Wait for mempool to sync
        self.wait_until(lambda: node.mempool_local_best_block_id() == block_id, timeout = 5)

        return block_id

    def hex_to_dec_array(self, hex_string):
        return [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)]

    def previous_block_id(self):
        previous_block_id = self.nodes[0].chainstate_best_block_id()
        return self.hex_to_dec_array(previous_block_id)

    def run_test(self):
        if 'win32' in sys.platform:
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        asyncio.run(self.async_test())

    async def async_test(self):
        node = self.nodes[0]
        cold_wallet_pk = b""

        async with WalletCliController(node, self.config, self.log, chain_config_args=["--chain-pos-netupgrades", "true", "--cold-wallet"]) as wallet:
            # new cold wallet
            await wallet.create_wallet("cold_wallet")

            cold_wallet_address = await wallet.new_address()
            cold_wallet_pk = await wallet.new_public_key(cold_wallet_address)
            assert_equal(len(cold_wallet_pk), 33)
            use_different_change = choice([True, False])

            if use_different_change:
                cold_wallet_new_change = await wallet.new_address()
                dest = node.test_functions_address_to_destination(cold_wallet_new_change)
                dest_obj = scalecodec.base.RuntimeConfiguration().create_scale_object('Destination', ScaleBytes("0x"+dest))
                dest_obj.decode()
                expected_change_dest = get_destination(dest_obj.value)
            else:
                cold_wallet_new_change = None
                expected_change_dest = f'0x{cold_wallet_pk.hex()}'

        total_cold_wallet_coins = 50_000
        to_send = randint(1, 100)

        async with WalletCliController(node, self.config, self.log, chain_config_args=["--chain-pos-netupgrades", "true"]) as wallet:
            # new hot wallet
            await wallet.create_wallet("hot_wallet")

            # check it is on genesis
            best_block_height = await wallet.get_best_block_height()
            self.log.info(f"best block height = {best_block_height}")
            assert_equal(best_block_height, '0')

            # Get chain tip
            tip_id = node.chainstate_best_block_id()
            self.log.debug(f'Tip: {tip_id}')

            # Submit a valid transaction
            output = {
                    'Transfer': [ { 'Coin': total_cold_wallet_coins * ATOMS_PER_COIN }, { 'PublicKey': {'key': {'Secp256k1Schnorr' : {'pubkey_data': cold_wallet_pk}}} } ],
            }
            encoded_tx, tx_id = make_tx([reward_input(tip_id)], [output], 0)
            self.log.debug(f"Encoded transaction {tx_id}: {encoded_tx}")

            node.mempool_submit_transaction(encoded_tx, {})
            assert node.mempool_contains_tx(tx_id)

            self.generate_block()

            balance = await wallet.get_balance()
            assert_in("Coins amount: 0", balance)

            hot_wallet_address = await wallet.new_address()

            if cold_wallet_new_change:
                output = await wallet.send_from_cold_address(hot_wallet_address, to_send, UtxoOutpoint(tx_id, 0), cold_wallet_new_change)
            else:
                output = await wallet.send_from_cold_address(hot_wallet_address, to_send, UtxoOutpoint(tx_id, 0))

            assert_in("Send transaction created", output)
            send_req = output.split("\n")[2]

            # try to sign decommission request from hot wallet
            assert_in("Wallet error: Wallet error: Input cannot be signed",
                       await wallet.sign_raw_transaction(send_req))

        signed_tx = ""

        async with WalletCliController(node, self.config, self.log, chain_config_args=["--chain-pos-netupgrades", "true", "--cold-wallet"]) as wallet:
            # open cold wallet
            await wallet.open_wallet("cold_wallet")

            # sign decommission request
            signed_tx_output = await wallet.sign_raw_transaction(send_req)
            signed_tx = signed_tx_output.split('\n')[2]

        async with WalletCliController(node, self.config, self.log, chain_config_args=["--chain-pos-netupgrades", "true"]) as wallet:
            # open hot wallet
            await wallet.open_wallet("hot_wallet")

            output = await wallet.submit_transaction(signed_tx)
            assert_in("The transaction was submitted successfully", output)
            tx_id = output.split('\n')[1]

            transactions = node.mempool_transactions()
            assert_in(signed_tx, transactions)

            self.generate_block()
            assert_in("Success", await wallet.sync())

            balance = await wallet.get_balance()
            assert_in(f"Coins amount: {to_send}", balance)

            signed_tx_obj = scalecodec.base.RuntimeConfiguration().create_scale_object('SignedTransaction', ScaleBytes("0x"+signed_tx))
            signed_tx_obj.decode()
            outputs = signed_tx_obj['transaction']['outputs']

            dest = node.test_functions_address_to_destination(hot_wallet_address)
            dest_obj = scalecodec.base.RuntimeConfiguration().create_scale_object('Destination', ScaleBytes("0x"+dest))
            dest_obj.decode()

            for out in outputs:
                coins, addr = get_transfer_coins_and_address(out.value)
                if coins == to_send * ATOMS_PER_COIN:
                    hot_wallet_dest = get_destination(dest_obj.value)
                    assert_equal(addr, hot_wallet_dest)
                else:
                    assert_greater_than_or_equal(coins, total_cold_wallet_coins - to_send - 1)
                    assert_equal(addr, expected_change_dest)


if __name__ == '__main__':
    WalletColdSend().main()
