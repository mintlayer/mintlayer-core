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
"""Test listing all actrive orders, both RPC and CLI
"""

from test_framework.util import assert_in, assert_equal
from test_framework.wallet_cli_controller import WalletCliController
from test_framework.wallet_rpc_controller import WalletRpcController
from wallet_order_listing_test_utils import *

import asyncio
import itertools
import random
from decimal import Decimal
from typing import Callable


class WalletOrderListAllActive(WalletOrdersListingTestBase):
    def run_test(self):
        asyncio.run(self.async_test())

    async def async_test(self):
        node = self.nodes[0]

        async with (WalletRpcController(node, self.config, self.log) as wallet1,
                    WalletCliController(node, self.config, self.log) as wallet2):
            await self.setup_wallets([wallet1, wallet2])

            tokens_info1 = await self.issue_and_mint_tokens(wallet1, [
                TokenInfo(6, "XXX"),
                TokenInfo(7, "YYY"),
                TokenInfo(8, "YYY"),  # same ticker
            ])
            w1_token_ids = list(tokens_info1.keys())
            random.shuffle(w1_token_ids)
            (w1_token1_id, w1_token2_id, w1_token3_id) = tuple(w1_token_ids)

            tokens_info2 = await self.issue_and_mint_tokens(wallet2, [
                TokenInfo(16, "ABC"),
                TokenInfo(17, "ABC"),  # same ticker
                TokenInfo(18, "XYZ"),
            ])
            w2_token_ids = list(tokens_info2.keys())
            random.shuffle(w2_token_ids)
            (w2_token1_id, w2_token2_id, w2_token3_id) = tuple(w2_token_ids)

            tokens_info = tokens_info1 | tokens_info2

            w1_address = await wallet1.new_address()
            w2_address = await wallet2.new_address()

            ########################################################################################
            # Some helpers

            def mk_init1(
                ask_token_id: str | None,
                ask_amount: Decimal | int,
                give_token_id: str | None,
                give_amount: Decimal | int
            ) -> InitialOrderData:
                return InitialOrderData(ask_token_id, ask_amount, give_token_id, give_amount, w1_address)

            def mk_init2(
                ask_token_id: str | None,
                ask_amount: Decimal | int,
                give_token_id: str | None,
                give_amount: Decimal | int
            ) -> InitialOrderData:
                return InitialOrderData(ask_token_id, ask_amount, give_token_id, give_amount, w2_address)

            def rand_tkn(token_id: str) -> list[str | Decimal]:
                return [token_id, random_token_amount(token_id, 90, 110, tokens_info)]

            def rand_coins() -> list[str | Decimal]:
                return [None, random_coins_amount(90, 110)]

            def with_is_own(data: ExpectedActiveOrderData, is_own: bool) -> ExpectedActiveOrderDataWithIsOwn:
                return ExpectedActiveOrderDataWithIsOwn(
                    data.order_id, data.initial_data, data.ask_balance, data.give_balance, is_own
                )

            w1_order_ids = []
            w2_order_ids = []
            order_init_datas: dict[str, InitialOrderData] = {}
            order_expected_datas: dict[str, ExpectedActiveOrderData] = {}

            async def mk_order_impl(wallet: WalletRpcController | WalletCliController, init_data: InitialOrderData):
                order_id = await self.create_order(wallet, init_data)
                self.log.info(f"New order created: {order_id}, init_data = {init_data}")

                order_init_datas[order_id] = init_data

                exp_data = ExpectedActiveOrderData(
                    order_id, init_data, init_data.ask_amount, init_data.give_amount
                )
                order_expected_datas[order_id] = exp_data

                return order_id

            async def mk_order1(init_data: InitialOrderData):
                order_id = await mk_order_impl(wallet1, init_data)
                w1_order_ids.append(order_id)
                return order_id

            async def mk_order2(init_data: InitialOrderData):
                order_id = await mk_order_impl(wallet2, init_data)
                w2_order_ids.append(order_id)
                return order_id

            async def gen_block_and_sync():
                self.generate_block()
                assert_in("Success", await wallet1.sync())
                assert_in("Success", await wallet2.sync())

            ########################################################################################
            # Setup orders in wallet1 (2 orders for each currency pair)

            # Ask for w2_token1, give coins
            await mk_order1(mk_init1(*rand_tkn(w2_token1_id), *rand_coins()))
            await mk_order1(mk_init1(*rand_tkn(w2_token1_id), *rand_coins()))

            # Ask for w2_token2, give w1_token1
            await mk_order1(mk_init1(*rand_tkn(w2_token2_id), *rand_tkn(w1_token1_id)))
            await mk_order1(mk_init1(*rand_tkn(w2_token2_id), *rand_tkn(w1_token1_id)))

            # Ask for w2_token3, give w1_token2
            await mk_order1(mk_init1(*rand_tkn(w2_token3_id), *rand_tkn(w1_token2_id)))
            await mk_order1(mk_init1(*rand_tkn(w2_token3_id), *rand_tkn(w1_token2_id)))

            # Ask for coins, give w1_token3
            await mk_order1(mk_init1(*rand_coins(), *rand_tkn(w1_token3_id)))
            await mk_order1(mk_init1(*rand_coins(), *rand_tkn(w1_token3_id)))

            ########################################################################################
            # Setup orders in wallet2 (2 orders for each currency pair)

            # Ask for w1_token1, give coins
            await mk_order2(mk_init2(*rand_tkn(w1_token1_id), *rand_coins()))
            await mk_order2(mk_init2(*rand_tkn(w1_token1_id), *rand_coins()))

            # Ask for w1_token2, give w2_token1
            await mk_order2(mk_init2(*rand_tkn(w1_token2_id), *rand_tkn(w2_token1_id)))
            await mk_order2(mk_init2(*rand_tkn(w1_token2_id), *rand_tkn(w2_token1_id)))

            # Ask for w1_token3, give w2_token2
            await mk_order2(mk_init2(*rand_tkn(w1_token3_id), *rand_tkn(w2_token2_id)))
            await mk_order2(mk_init2(*rand_tkn(w1_token3_id), *rand_tkn(w2_token2_id)))

            # Ask for coins, give w2_token3
            await mk_order2(mk_init2(*rand_coins(), *rand_tkn(w2_token3_id)))
            await mk_order2(mk_init2(*rand_coins(), *rand_tkn(w2_token3_id)))

            ########################################################################################

            # Before the txs are mined, there are no active orders
            w1_actual_active_orders = await wallet1.list_all_active_orders(None, None)
            assert_equal(w1_actual_active_orders, [])

            w2_actual_active_orders = await wallet2.list_all_active_orders(None, None)
            assert_equal(w2_actual_active_orders, [])

            ########################################################################################
            # Some helper functions to check for specific order sets

            def mk_currency_filter(token_id: str | None) -> str:
                return "coin" if token_id is None else token_id

            async def rpc_check_orders_with_filters_impl(
                exp_data_filter: Callable[[InitialOrderData], bool],
                ask_filter: str | None,
                give_filter: str | None,
            ):
                exp_datas = [
                    with_is_own(exp_data, order_id in w1_order_ids)
                    for order_id, exp_data in order_expected_datas.items()
                    if exp_data_filter(exp_data.initial_data)
                ]

                self.log.info(
                    f"Checking orders via rpc; ask_filter = {ask_filter}, " +
                    f"give_filter = {give_filter}, expected items count: {len(exp_datas)}"
                )

                expected = make_expected_rpc_active_order_datas(exp_datas, tokens_info)
                actual = await wallet1.list_all_active_orders(ask_filter, give_filter)
                assert_equal(actual, expected)

            async def rpc_check_all_orders():
                await rpc_check_orders_with_filters_impl(lambda _: True, None, None)

            async def rpc_check_orders_with_ask_filter(ask_token_id: str | None):
                await rpc_check_orders_with_filters_impl(
                    lambda init_data: init_data.ask_token_id == ask_token_id,
                    mk_currency_filter(ask_token_id),
                    None
                )

            async def rpc_check_orders_with_give_filter(give_token_id: str | None):
                await rpc_check_orders_with_filters_impl(
                    lambda init_data: init_data.give_token_id == give_token_id,
                    None,
                    mk_currency_filter(give_token_id),
                )

            async def rpc_check_orders_with_filters(ask_token_id: str | None, give_token_id: str | None):
                await rpc_check_orders_with_filters_impl(
                    lambda init_data:
                        init_data.ask_token_id == ask_token_id and
                        init_data.give_token_id == give_token_id,
                    mk_currency_filter(ask_token_id),
                    mk_currency_filter(give_token_id),
                )

            async def cli_check_orders_with_filters_impl(
                exp_data_filter: Callable[[InitialOrderData], bool],
                ask_filter: str | None,
                give_filter: str | None,
            ):
                exp_datas = [
                    with_is_own(exp_data, order_id in w2_order_ids)
                    for order_id, exp_data in order_expected_datas.items()
                    if exp_data_filter(exp_data.initial_data)
                ]

                self.log.info(
                    f"Checking orders via cli; ask_filter = {ask_filter}, " +
                    f"give_filter = {give_filter}, expected items count: {len(exp_datas)}"
                )

                expected = make_expected_cli_active_order_datas(exp_datas, tokens_info)
                actual = await wallet2.list_all_active_orders(ask_filter, give_filter)
                assert_equal(actual, expected)

            async def cli_check_all_orders():
                await cli_check_orders_with_filters_impl(lambda _: True, None, None)

            async def cli_check_orders_with_ask_filter(ask_token_id: str | None):
                await cli_check_orders_with_filters_impl(
                    lambda init_data: init_data.ask_token_id == ask_token_id,
                    mk_currency_filter(ask_token_id),
                    None
                )

            async def cli_check_orders_with_give_filter(give_token_id: str | None):
                await cli_check_orders_with_filters_impl(
                    lambda init_data: init_data.give_token_id == give_token_id,
                    None,
                    mk_currency_filter(give_token_id),
                )

            async def cli_check_orders_with_filters(ask_token_id: str | None, give_token_id: str | None):
                await cli_check_orders_with_filters_impl(
                    lambda init_data:
                        init_data.ask_token_id == ask_token_id and
                        init_data.give_token_id == give_token_id,
                    mk_currency_filter(ask_token_id),
                    mk_currency_filter(give_token_id),
                )

            async def check_all():
                # All orders
                await rpc_check_all_orders()
                await cli_check_all_orders()

                # Orders asking for or giving a specific asset
                for filter in list(tokens_info.keys()) + [None]:
                    # Orders asking for the asset
                    await rpc_check_orders_with_ask_filter(filter)
                    await cli_check_orders_with_ask_filter(filter)

                    # Orders giving the asset
                    await rpc_check_orders_with_give_filter(filter)
                    await cli_check_orders_with_give_filter(filter)

                # Orders asking for and giving a specific asset
                for filter1, filter2 in itertools.combinations(list(tokens_info.keys()) + [None], 2):
                    await rpc_check_orders_with_filters(filter1, filter2)
                    await cli_check_orders_with_filters(filter1, filter2)

            ########################################################################################
            # Generate a block, the orders should exist now

            await gen_block_and_sync()

            await check_all()

            ########################################################################################
            # Fill some orders randomly

            fill_amounts = {}

            async def random_fill(wallet: WalletRpcController | WalletCliController, order_id: str, address: str):
                order_init = order_init_datas[order_id]
                fill_decimals = currency_decimals(order_init.ask_token_id, tokens_info)
                fill_amount = random_decimal_amount(10, 80, fill_decimals)

                self.log.info(f"Filling order {order_id} with amount {fill_amount}")
                result = await wallet.fill_order(order_id, fill_amount, address)
                assert_in("The transaction was submitted successfully", result)

                fill_amounts[order_id] = fill_amount

            # Fill some wallet2's orders via wallet1
            for order_id in random.sample(w2_order_ids, random.randint(0, len(w2_order_ids))):
                await random_fill(wallet1, order_id, w1_address)

            # Fill some wallet1's orders via wallet2
            for order_id in random.sample(w1_order_ids, random.randint(0, len(w1_order_ids))):
                await random_fill(wallet2, order_id, w2_address)

            # Before the txs have been mined, the expected values stay the same.
            await check_all()

            # Generate a block
            await gen_block_and_sync()

            # Now we can update the expected data
            for order_id, fill_amount in fill_amounts.items():
                exp_data = order_expected_datas[order_id]
                filled_amount = (
                    Decimal(exp_data.initial_data.give_amount) /
                    Decimal(exp_data.initial_data.ask_amount) *
                    fill_amount
                )
                filled_amount = round_down_currency(exp_data.initial_data.give_token_id, filled_amount, tokens_info)
                order_expected_datas[order_id].ask_balance -= fill_amount
                order_expected_datas[order_id].give_balance -= filled_amount

            # Check the orders again
            await check_all()

            ########################################################################################
            # Freeze and conclude some orders

            inactive_order_ids = set()

            async def freeze_order(wallet: WalletRpcController | WalletCliController, order_id: str):
                self.log.info(f"Freezing order {order_id}")
                result = await wallet.freeze_order(order_id)
                assert_in("The transaction was submitted successfully", result)
                inactive_order_ids.add(order_id)

            async def conclude_order(wallet: WalletRpcController | WalletCliController, order_id: str):
                self.log.info(f"Concluding order {order_id}")
                result = await wallet.conclude_order(order_id)
                assert_in("The transaction was submitted successfully", result)
                inactive_order_ids.add(order_id)

            # Freeze some orders in wallet1
            for order_id in random.sample(w1_order_ids, random.randint(0, len(w1_order_ids) // 2)):
                await freeze_order(wallet1, order_id)

            # Conclude some orders in wallet1
            for order_id in random.sample(w1_order_ids, random.randint(0, len(w1_order_ids) // 2)):
                await conclude_order(wallet1, order_id)

            # Freeze some orders in wallet2
            for order_id in random.sample(w2_order_ids, random.randint(0, len(w2_order_ids) // 2)):
                await freeze_order(wallet2, order_id)

            # Conclude some orders in wallet2
            for order_id in random.sample(w2_order_ids, random.randint(0, len(w2_order_ids) // 2)):
                await conclude_order(wallet2, order_id)

            # Before the txs have been mined, ther expected values stay the same.
            await check_all()

            # Generate a block
            await gen_block_and_sync()

            # Now we can update the expected data
            for order_id in inactive_order_ids:
                del order_expected_datas[order_id]

            # Check the orders again
            await check_all()


if __name__ == "__main__":
    WalletOrderListAllActive().main()
