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
"""Test listing own orders via CLI
"""

from test_framework.util import assert_in, assert_equal
from test_framework.wallet_cli_controller import WalletCliController
from wallet_order_listing_test_utils import *

import asyncio
from decimal import Decimal


class WalletOrderListOwnCli(WalletOrdersListingTestBase):
    def run_test(self):
        asyncio.run(self.async_test())

    async def async_test(self):
        node = self.nodes[0]

        async with WalletCliController(node, self.config, self.log) as wallet:
            await self.setup_wallets([wallet])

            tokens_info = await self.issue_and_mint_tokens(wallet, [
                TokenInfo(16, "FOO"),
                TokenInfo(6, "BAR"),
            ])
            (token1_id, token2_id) = tuple(tokens_info.keys())

            address = await wallet.new_address()

            # Ask for token1, give coins.
            order1_init_data = InitialOrderData(token1_id, 200, None, 100, address)
            order1_id = await self.create_order(wallet, order1_init_data)
            order1_expected_data = ExpectedCliOwnOrderData(
                order1_id, order1_init_data, None, "Unconfirmed")

            # Same, but the price is different.
            order2_init_data = InitialOrderData(token1_id, 200, None, 111, address)
            order2_id = await self.create_order(wallet, order2_init_data)
            order2_expected_data = ExpectedCliOwnOrderData(
                order2_id, order2_init_data, None, "Unconfirmed")

            expected_own_orders = make_expected_cli_own_order_datas(
                [order1_expected_data, order2_expected_data],
                tokens_info
            )
            actual_own_orders = await wallet.list_own_orders()
            assert_equal(actual_own_orders, expected_own_orders)

            # Generate a block; after this, both orders are on the chain and existing_order_data
            # is not None anymore.
            self.generate_block()
            assert_in("Success", await wallet.sync())

            order12_timestamp = self.best_block_timestamp()

            order1_expected_data.existing_data = ExpectedExistingOwnOrderData(
                order1_init_data.ask_amount, order1_init_data.give_amount,
                order12_timestamp, False
            )
            order1_expected_data.status_in_cli = "Active"

            order2_expected_data.existing_data = ExpectedExistingOwnOrderData(
                order2_init_data.ask_amount, order2_init_data.give_amount,
                order12_timestamp, False
            )
            order2_expected_data.status_in_cli = "Active"

            # Create one more order, asking for token2 and giving coins.
            order3_init_data = InitialOrderData(token2_id, 200, None, 222, address)
            order3_id = await self.create_order(wallet, order3_init_data)
            order3_expected_data = ExpectedCliOwnOrderData(
                order3_id, order3_init_data, None, "Unconfirmed")

            expected_own_orders = make_expected_cli_own_order_datas(
                [order1_expected_data, order2_expected_data, order3_expected_data],
                tokens_info
            )
            actual_own_orders = await wallet.list_own_orders()
            assert_equal(actual_own_orders, expected_own_orders)

            # Generate a block; after this, order3 is also on the chain.
            self.generate_block()
            assert_in("Success", await wallet.sync())

            order3_timestamp = self.best_block_timestamp()
            order3_expected_data.existing_data = ExpectedExistingOwnOrderData(
                order3_init_data.ask_amount, order3_init_data.give_amount,
                order3_timestamp, False
            )
            order3_expected_data.status_in_cli = "Active"

            expected_own_orders = make_expected_cli_own_order_datas(
                [order1_expected_data, order2_expected_data, order3_expected_data],
                tokens_info
            )
            actual_own_orders = await wallet.list_own_orders()
            assert_equal(actual_own_orders, expected_own_orders)

            # Fill order3
            result = await wallet.fill_order(order3_id, 10, address)
            assert_in("The transaction was submitted successfully", result)

            # The fill tx hasn't been mined yet, so the expected order data remains the same.
            actual_own_orders = await wallet.list_own_orders()
            assert_equal(actual_own_orders, expected_own_orders)

            # Generate a block, now the fill should take effect.
            self.generate_block()
            assert_in("Success", await wallet.sync())

            order3_expected_data.existing_data.ask_balance = 190
            order3_expected_data.existing_data.give_balance = Decimal("210.9")

            expected_own_orders = make_expected_cli_own_order_datas(
                [order1_expected_data, order2_expected_data, order3_expected_data],
                tokens_info
            )
            actual_own_orders = await wallet.list_own_orders()
            assert_equal(actual_own_orders, expected_own_orders)

            # Freeze order3
            result = await wallet.freeze_order(order3_id)
            assert_in("The transaction was submitted successfully", result)

            # For now, order3 is just marked as frozen in the wallet
            order3_expected_data.status_in_cli = "Frozen (unconfirmed)"

            expected_own_orders = make_expected_cli_own_order_datas(
                [order1_expected_data, order2_expected_data, order3_expected_data],
                tokens_info
            )
            actual_own_orders = await wallet.list_own_orders()
            assert_equal(actual_own_orders, expected_own_orders)

            # Generate a block, now the freeze should take effect.
            self.generate_block()
            assert_in("Success", await wallet.sync())

            # Now order3 is actually frozen
            order3_expected_data.status_in_cli = "Frozen"

            expected_own_orders = make_expected_cli_own_order_datas(
                [order1_expected_data, order2_expected_data, order3_expected_data],
                tokens_info
            )
            actual_own_orders = await wallet.list_own_orders()
            assert_equal(actual_own_orders, expected_own_orders)

            # Conclude order3
            result = await wallet.conclude_order(order3_id)
            assert_in("The transaction was submitted successfully", result)

            # For now, order3 is just marked as concluded in the wallet
            order3_expected_data.status_in_cli = "Frozen, Concluded (unconfirmed)"

            expected_own_orders = make_expected_cli_own_order_datas(
                [order1_expected_data, order2_expected_data, order3_expected_data],
                tokens_info
            )
            actual_own_orders = await wallet.list_own_orders()
            assert_equal(actual_own_orders, expected_own_orders)

            # Generate a block, now the conclusion should take effect.
            self.generate_block()
            assert_in("Success", await wallet.sync())

            # Order3 is no longer there
            expected_own_orders = make_expected_cli_own_order_datas(
                [order1_expected_data, order2_expected_data],
                tokens_info
            )
            actual_own_orders = await wallet.list_own_orders()
            assert_equal(actual_own_orders, expected_own_orders)

            # Conclude order2
            result = await wallet.conclude_order(order2_id)
            assert_in("The transaction was submitted successfully", result)

            # Freeze and conclude order1
            result = await wallet.freeze_order(order1_id)
            assert_in("The transaction was submitted successfully", result)
            result = await wallet.conclude_order(order1_id)
            assert_in("The transaction was submitted successfully", result)

            # Check the orders without generating a block, both "frozen" and "concluded"
            # status should be unconfirmed.
            order2_expected_data.status_in_cli = "Concluded (unconfirmed)"
            order1_expected_data.status_in_cli = "Frozen (unconfirmed), Concluded (unconfirmed)"

            expected_own_orders = make_expected_cli_own_order_datas(
                [order1_expected_data, order2_expected_data],
                tokens_info
            )
            actual_own_orders = await wallet.list_own_orders()
            assert_equal(actual_own_orders, expected_own_orders)


if __name__ == "__main__":
    WalletOrderListOwnCli().main()
