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
"""Wallet sign arbitrary message test

Check that:
* We can create a new cold wallet,
* generate an address
* sign a random message
* open a different wallet and verify the signature
"""

from random import choice, randint
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_in
from test_framework.wallet_cli_controller import WalletCliController

import asyncio
import string

class WalletSignMessage(BitcoinTestFramework):

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

    def run_test(self):
        asyncio.run(self.async_test())

    async def async_test(self):
        node = self.nodes[0]
        use_hex = choice([True, False])
        message = "".join([choice(string.digits + string.ascii_letters) for _ in range(randint(20, 40))])
        if use_hex:
            message = message.encode().hex()

        async with self.wallet_controller(node, self.config, self.log, wallet_args=["--cold-wallet"], chain_config_args=["--chain-pos-netupgrades", "1"]) as wallet:
            # new cold wallet
            await wallet.create_wallet("cold_wallet")

            destination = await wallet.new_address()
            if use_hex:
                output = await wallet.sign_challenge_hex(message, destination)
            else:
                output = await wallet.sign_challenge_plain(message, destination)
            assert_in("The generated hex-encoded signature is", output)
            signature = output.split('\n')[2]

            await wallet.close_wallet()

            # new hot wallet
            await wallet.create_wallet("another_cold_wallet")

            # try to sign the message with the new wallet should fail
            if use_hex:
                output = await wallet.sign_challenge_hex(message, destination)
            else:
                output = await wallet.sign_challenge_plain(message, destination)
            assert_in("Destination does not belong to this wallet", output)

            if use_hex:
                output = await wallet.verify_challenge_hex(message, signature, destination)
            else:
                output = await wallet.verify_challenge_plain(message, signature, destination)
            assert_in("The provided signature is correct", output)

            # try to verify with wrong message
            different_message = "".join([choice(string.digits + string.ascii_letters) for _ in range(randint(20, 40))])
            if use_hex:
                different_message = different_message.encode().hex()
            if use_hex:
                output = await wallet.verify_challenge_hex(different_message, signature, destination)
            else:
                output = await wallet.verify_challenge_plain(different_message, signature, destination)
            assert_in("Signature verification failed", output)

if __name__ == '__main__':
    WalletSignMessage().main()

