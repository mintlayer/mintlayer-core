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
"""Utilities and the base class for order listing tests
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import (make_tx, reward_input, ATOMS_PER_COIN)
from test_framework.util import assert_in, assert_equal
from test_framework.mintlayer import COINS_NUM_DECIMALS, block_input_data_obj, random_decimal_amount
from test_framework.wallet_cli_controller import WalletCliController
from test_framework.wallet_rpc_controller import WalletRpcController

import random
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, ROUND_DOWN


MIN_TOKENS_TO_MINT = 10000


def random_mint_amount():
    return random.randint(MIN_TOKENS_TO_MINT, MIN_TOKENS_TO_MINT*10)


@dataclass
class TokenInfo:
    decimals: int
    ticker: str

@dataclass
class InitialOrderData:
    ask_token_id: str | None
    ask_amount: Decimal | int
    give_token_id: str | None
    give_amount: Decimal | int
    conclude_key: str

@dataclass
class ExpectedExistingOwnOrderData:
    ask_balance: Decimal | int
    give_balance: Decimal | int
    creation_timestamp: int
    is_frozen: bool

@dataclass
class ExpectedRpcOwnOrderData:
    order_id: str
    initial_data: InitialOrderData
    existing_data: ExpectedExistingOwnOrderData
    is_marked_as_frozen_in_wallet: bool
    is_marked_as_concluded_in_wallet: bool

@dataclass
class ExpectedCliOwnOrderData:
    order_id: str
    initial_data: InitialOrderData
    existing_data: ExpectedExistingOwnOrderData
    status_in_cli: str

@dataclass
class ExpectedActiveOrderData:
    order_id: str
    initial_data: InitialOrderData
    ask_balance: Decimal | int
    give_balance: Decimal | int

@dataclass
class ExpectedActiveOrderDataWithIsOwn:
    order_id: str
    initial_data: InitialOrderData
    ask_balance: Decimal | int
    give_balance: Decimal | int
    is_own: bool

class WalletOrdersListingTestBase(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

        self.extra_args = [["--blockprod-min-peers-to-produce-blocks=0"]]

    def setup_network(self):
        self.setup_nodes()
        self.sync_all(self.nodes[0:1])

        self.node = self.nodes[0]

    def generate_block(self):
        block_input_data = {"PoW": {"reward_destination": "AnyoneCanSpend"}}
        block_input_data = block_input_data_obj.encode(
            block_input_data).to_hex()[2:]

        # create a new block, taking transactions from mempool
        block = self.node.blockprod_generate_block(
            block_input_data, [], [], "FillSpaceFromMempool")
        self.node.chainstate_submit_block(block)
        block_id = self.node.chainstate_best_block_id()

        # Wait for mempool to sync
        self.wait_until(lambda: self.node.mempool_local_best_block_id()
                        == block_id, timeout=5)

        return block_id

    async def setup_wallets(
        self, wallets: list[WalletRpcController | WalletCliController]
    ):
        pub_keys_bytes = []
        for i, wallet in enumerate(wallets):
            await wallet.create_wallet(f"wallet{i}")
            assert_equal("0", await wallet.get_best_block_height())

            address = await wallet.new_address()
            pub_key_bytes = await wallet.new_public_key(address)
            assert_equal(len(pub_key_bytes), 33)
            pub_keys_bytes.append(pub_key_bytes)

        tip_id = self.node.chainstate_best_block_id()

        # Submit a valid transaction
        coins_to_send = 1000
        outputs = [
            {"Transfer": [
                {"Coin": coins_to_send * ATOMS_PER_COIN},
                {"PublicKey": {"key": {"Secp256k1Schnorr": {
                    "pubkey_data": pub_key_bytes}}}}
            ]}
            for pub_key_bytes in pub_keys_bytes
        ]
        encoded_tx, tx_id = make_tx([reward_input(tip_id)], outputs, 0)

        self.node.mempool_submit_transaction(encoded_tx, {})
        assert self.node.mempool_contains_tx(tx_id)

        block_id = self.generate_block()
        assert not self.node.mempool_contains_tx(tx_id)

        # Sync the wallets and check best block and balance
        for wallet in wallets:
            assert_in("Success", await wallet.sync())
            assert_equal(await wallet.get_best_block_height(), "1")
            assert_equal(await wallet.get_best_block(), block_id)
            balance = await wallet.get_balance()
            assert_in(f"Coins amount: {coins_to_send}", balance)

    async def issue_and_mint_tokens(
        self, wallet: WalletRpcController | WalletCliController, token_infos: list[TokenInfo]
    ) -> dict[str, TokenInfo]:
        result = {}
        address = await wallet.new_address()

        # Issue tokens
        for info in token_infos:
            token_id, _, _ = await wallet.issue_new_token(
                info.ticker, info.decimals, "http://uri", address
            )
            assert token_id is not None
            self.log.info(f"New token issued: {token_id}")
            result[token_id] = info

        self.generate_block()
        assert_in("Success", await wallet.sync())

        # Mint tokens
        minted_amounts = []
        for id, info in result.items():
            amount_to_mint = random_mint_amount()
            await wallet.mint_tokens_or_fail(id, address, amount_to_mint)
            minted_amounts.append(amount_to_mint)

        self.generate_block()
        assert_in("Success", await wallet.sync())

        # Check balances
        balance = await wallet.get_balance()
        for (id, info), minted_amount in zip(result.items(), minted_amounts):
            assert_in(f"Token: {id} ({info.ticker}), amount: {minted_amount}", balance)

        return result

    async def create_order(self, wallet: WalletRpcController | WalletCliController,  data: InitialOrderData):
        order1_id = await wallet.create_order(
            data.ask_token_id, data.ask_amount, data.give_token_id, data.give_amount, data.conclude_key)
        return order1_id

    def best_block_timestamp(self) -> int :
        tip_id = self.node.chainstate_best_block_id()
        tip = self.node.chainstate_get_block_json(tip_id)
        return tip["timestamp"]["timestamp"]


def make_expected_rpc_amount(
    token_id: str | None,
    amount: int | float | Decimal | str,
    tokens_info: dict[str, TokenInfo],
):
    num_decimals = currency_decimals(token_id, tokens_info)
    amount = Decimal(amount)
    amount_atoms = amount.scaleb(num_decimals)
    return {"atoms": f"{amount_atoms:f}", "decimal": decimal_to_str(amount)}


def make_expected_rpc_output_val(
    token_id: str | None,
    amount: int | float | Decimal | str,
    tokens_info: dict[str, TokenInfo],
):
    amount_obj = make_expected_rpc_amount(token_id, amount, tokens_info)

    if token_id is not None:
        return {"type": "Token", "content": {"id": token_id, "amount": amount_obj}}
    else:
        return {"type": "Coin", "content": {"amount": amount_obj}}


def sort_expected_own_order_datas_for_rpc(datas: list[ExpectedRpcOwnOrderData]) -> list[ExpectedRpcOwnOrderData]:
    # Own orders returned via RPC are sorted by order id
    return sorted(datas, key=lambda item: item.order_id)


def make_expected_rpc_own_order_data(
    data: ExpectedRpcOwnOrderData,
    tokens_info: dict[str, TokenInfo],
) -> dict:
    initially_asked = make_expected_rpc_output_val(
        data.initial_data.ask_token_id, data.initial_data.ask_amount, tokens_info)
    initially_given = make_expected_rpc_output_val(
        data.initial_data.give_token_id, data.initial_data.give_amount, tokens_info)

    existing_order_data = data.existing_data
    if existing_order_data is not None:
        ask_balance = make_expected_rpc_amount(
            data.initial_data.ask_token_id, existing_order_data.ask_balance, tokens_info)
        give_balance = make_expected_rpc_amount(
            data.initial_data.give_token_id, existing_order_data.give_balance, tokens_info)

        existing_order_data = {
            "ask_balance": ask_balance,
            "give_balance": give_balance,
            "creation_timestamp": {"timestamp": existing_order_data.creation_timestamp},
            "is_frozen": existing_order_data.is_frozen
        }

    return {
        "order_id": data.order_id,
        "initially_asked": initially_asked,
        "initially_given": initially_given,
        "existing_order_data": existing_order_data,
        "is_marked_as_frozen_in_wallet": data.is_marked_as_frozen_in_wallet,
        "is_marked_as_concluded_in_wallet": data.is_marked_as_concluded_in_wallet
    }


def make_expected_rpc_own_order_datas(datas: list[ExpectedRpcOwnOrderData], tokens_info: dict[str, TokenInfo]):
    sorted_datas = sort_expected_own_order_datas_for_rpc(datas)
    return [
        make_expected_rpc_own_order_data(data, tokens_info)
        for data in sorted_datas
    ]


def sort_expected_active_order_datas_for_rpc(datas: list[ExpectedActiveOrderDataWithIsOwn]) -> list[ExpectedRpcOwnOrderData]:
    # Active orders returned via RPC are sorted by order id
    return sorted(datas, key=lambda item: item.order_id)


def make_expected_rpc_active_order_data(
    data: ExpectedActiveOrderDataWithIsOwn,
    tokens_info: dict[str, TokenInfo],
) -> dict:
    initially_asked = make_expected_rpc_output_val(
        data.initial_data.ask_token_id, data.initial_data.ask_amount, tokens_info)
    initially_given = make_expected_rpc_output_val(
        data.initial_data.give_token_id, data.initial_data.give_amount, tokens_info)

    ask_balance = make_expected_rpc_amount(
        data.initial_data.ask_token_id, data.ask_balance, tokens_info)
    give_balance = make_expected_rpc_amount(
        data.initial_data.give_token_id, data.give_balance, tokens_info)

    return {
        "order_id": data.order_id,
        "initially_asked": initially_asked,
        "initially_given": initially_given,
        "ask_balance": ask_balance,
        "give_balance": give_balance,
        "is_own": data.is_own,
    }


def make_expected_rpc_active_order_datas(datas: list[ExpectedActiveOrderDataWithIsOwn], tokens_info: dict[str, TokenInfo]):
    sorted_datas = sort_expected_active_order_datas_for_rpc(datas)
    return [
        make_expected_rpc_active_order_data(data, tokens_info)
        for data in sorted_datas
    ]


def sort_expected_own_order_datas_for_cli(datas: list[ExpectedCliOwnOrderData]) -> list[ExpectedCliOwnOrderData]:
    # Own orders returned via CLI are first sorted by timestamp and then by order id.
    # Orders without timestamp (i.e. unconfirmed ones) appear last.
    def sort_key(data: ExpectedCliOwnOrderData):
        effective_ts = data.existing_data.creation_timestamp if data.existing_data is not None else 2**64
        return (effective_ts, data.order_id)

    return sorted(datas, key=sort_key)


def make_currency_name_for_cli(token_id: str | None, tokens_info: dict[str, TokenInfo]):
    if token_id is None:
        return "RML"
    else:
        return f"{token_id} ({tokens_info[token_id].ticker})"


def make_expected_cli_own_order_data(
    data: ExpectedCliOwnOrderData,
    tokens_info: dict[str, TokenInfo],
):
    ask_currency_name = make_currency_name_for_cli(data.initial_data.ask_token_id, tokens_info)
    give_currency_name = make_currency_name_for_cli(data.initial_data.give_token_id, tokens_info)

    ask_extra_info = ""
    give_extra_info = ""
    created_at = ""

    if data.existing_data is not None:
        ask_left = data.existing_data.ask_balance
        ask_can_withdraw = data.initial_data.ask_amount - ask_left
        ask_extra_info = f" [left: {decimal_to_str(ask_left)}, can withdraw: {decimal_to_str(ask_can_withdraw)}]"

        give_extra_info = f" [left: {decimal_to_str(data.existing_data.give_balance)}]"

        created_at = datetime.fromtimestamp(data.existing_data.creation_timestamp, timezone.utc)
        created_at = created_at.strftime('%Y-%m-%d %H:%M:%S UTC')
        created_at = f"Created at: {created_at}, "

    result = (
        f"Id: {data.order_id}, " +
        f"Asked: {decimal_to_str(data.initial_data.ask_amount)} {ask_currency_name}{ask_extra_info}, " +
        f"Given: {decimal_to_str(data.initial_data.give_amount)} {give_currency_name}{give_extra_info}, " +
        created_at +
        f"Status: {data.status_in_cli}"
    )
    return result


def make_expected_cli_own_order_datas(datas: list[ExpectedCliOwnOrderData], tokens_info: dict[str, TokenInfo]):
    sorted_datas = sort_expected_own_order_datas_for_cli(datas)
    return [
        make_expected_cli_own_order_data(data, tokens_info)
        for data in sorted_datas
    ]


def sort_expected_active_order_datas_for_cli(
    datas: list[ExpectedActiveOrderDataWithIsOwn], tokens_info: dict[str, TokenInfo]
) -> list[ExpectedActiveOrderDataWithIsOwn]:
    # Active orders returned via CLI are first sorted by given currency, then by asked currency,
    # then by give/ask price, then by order id.
    # Sorting by currency means: coins come first, tokens are sorted by ticker first, then by id.
    # The give/ask price sorting is in the descending order, the rest is in the ascending order.

    def make_currency_key(token_id: str | None) -> str:
        if token_id is None:
            return ("", "")
        else:
            ticker = tokens_info[token_id].ticker
            return (ticker, token_id)

    def sort_key(data: ExpectedActiveOrderDataWithIsOwn):
        ask_currency_key = make_currency_key(data.initial_data.ask_token_id)
        give_currency_key = make_currency_key(data.initial_data.give_token_id)

        give_ask_price = Decimal(data.initial_data.give_amount) / Decimal(data.initial_data.ask_amount)

        return (give_currency_key, ask_currency_key, -give_ask_price, data.order_id)

    return sorted(datas, key=sort_key)


def make_expected_cli_active_order_data(
    data: ExpectedActiveOrderDataWithIsOwn,
    tokens_info: dict[str, TokenInfo],
):
    ask_currency_name = make_currency_name_for_cli(data.initial_data.ask_token_id, tokens_info)
    give_currency_name = make_currency_name_for_cli(data.initial_data.give_token_id, tokens_info)

    own_order_marker = "* " if data.is_own else "  "

    give_ask_price = Decimal(data.initial_data.give_amount) / Decimal(data.initial_data.ask_amount)
    give_ask_price = round_down_currency(data.initial_data.give_token_id, give_ask_price, tokens_info)

    result = (
        f"{own_order_marker}" +
        f"Id: {data.order_id}, " +
        f"Given: {give_currency_name} [left: {decimal_to_str(data.give_balance)}], " +
        f"Asked: {ask_currency_name} [left: {decimal_to_str(data.ask_balance)}], " +
        f"Give/Ask: {decimal_to_str(give_ask_price)}"
    )
    return result


def make_expected_cli_active_order_datas(datas: list[ExpectedActiveOrderDataWithIsOwn], tokens_info: dict[str, TokenInfo]):
    sorted_datas = sort_expected_active_order_datas_for_cli(datas, tokens_info)
    return [
        make_expected_cli_active_order_data(data, tokens_info)
        for data in sorted_datas
    ]


def decimal_to_str(d: Decimal | int) -> str:
    # Produce a fixed-point string without trailing zeros and trailing decimal point.
    # TODO: is there a nicer way?

    result = f"{Decimal(d):f}"
    if d.as_integer_ratio()[1] == 1:
        # If it's a whole number, return it as is
        return result
    else:
        # Strip trailing zeros, then strip the dot.
        return result.rstrip('0').rstrip('.')


def random_token_amount(token_id: str, min: int, max: int, tokens_info: dict[str, TokenInfo]) -> Decimal:
    return random_decimal_amount(min, max, tokens_info[token_id].decimals)


def random_coins_amount(min: int, max: int) -> Decimal:
    return random_decimal_amount(min, max, COINS_NUM_DECIMALS)


def round_down_currency(token_id: str | None, amount: Decimal, tokens_info: dict[str, TokenInfo]) -> Decimal:
    decimals = currency_decimals(token_id, tokens_info)
    return amount.quantize(Decimal(10) ** -decimals, ROUND_DOWN)


def currency_decimals(token_id: str | None, tokens_info: dict[str, TokenInfo]) -> int:
    return COINS_NUM_DECIMALS if token_id is None else tokens_info[token_id].decimals

