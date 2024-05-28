# Copyright (c) 2021-2024 RBB S.r.l
# opensource@mintlayer.org
# SPDX-License-Identifier: MIT
# Licensed under the MIT License;
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import os
import sys
import time

SRC_ROOT_PATH = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
FUNC_TESTS_PATH = os.path.join(SRC_ROOT_PATH, "test", "functional")
sys.path.append(FUNC_TESTS_PATH)

from test_framework.authproxy import (
    JSONRPCException
)
from test_framework.mintlayer import (
    block_input_data_obj,
    make_tx,
    reward_input,
    ATOMS_PER_COIN,
    MIN_POOL_PLEDGE,
)

from common import *


log = logging.getLogger("StakingTest")


def hex_to_dec_array(hex_string):
    return [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)]


def pub_key_bytes_from_hex(hex):
    # remove the pub key enum value, the first one byte
    pub_key_bytes = bytes.fromhex(hex)[1:]
    return pub_key_bytes


def open_or_create_wallet(wallet_rpc, wallet_path, mnemonic):
    try:
        wallet_rpc.wallet_info(wallet_path)
    except JSONRPCException:
        try:
            wallet_rpc.wallet_open(wallet_path)
        except JSONRPCException:
            wallet_rpc.wallet_create(wallet_path, True, mnemonic)


def get_or_create_address(wallet_rpc):
    addrs_response = []
    try:
        addrs_response = wallet_rpc.address_show(0)
    except JSONRPCException:
        pass

    if len(addrs_response) != 0:
        address = addrs_response[0]["address"]
    else:
        addr_response = wallet_rpc.address_new(0)
        address = addr_response["address"]

    pub_key_response = wallet_rpc.address_reveal_public_key(0, address)
    pub_key = pub_key_response["public_key_hex"]

    return (address, pub_key)


class Node():
    def __init__(self, node_index, node_rpc, wallet_rpc, wallet_name, mnemonic):
        self.index = node_index
        self.node = node_rpc
        self.wallet = wallet_rpc

        open_or_create_wallet(wallet_rpc, wallet_name, mnemonic)

        (self.address, self.pub_key_hex) = get_or_create_address(wallet_rpc)

    def tx_ids_to_signed_txs(self, tx_ids):
        txs = []

        for id in tx_ids:
            tx = self.wallet.transaction_get_signed_raw(0, id)
            txs.append(tx)

        return txs

    def create_pool_and_delegate(self, amount, portion_to_pledge):
        tx_ids = []

        assert portion_to_pledge >= 0.0 and portion_to_pledge <= 1.0
        portion_to_pledge = int(portion_to_pledge * 1000) / 1000
        margin_ratio_per_thousand = portion_to_pledge

        pledge_amount = int(amount * portion_to_pledge)
        if pledge_amount < MIN_POOL_PLEDGE:
            pledge_amount = MIN_POOL_PLEDGE

        response = self.wallet.staking_create_pool(
            0, { "atoms": f"{pledge_amount}" }, { "atoms": "0" }, f"{margin_ratio_per_thousand}", self.address, { "in_top_x_mb" : None })
        tx_id = response["tx_id"]
        tx_ids.append(tx_id)

        tx_json = self.wallet.transaction_get(0, tx_id)
        pool_id = tx_json[0]["V1"]["outputs"][0]["CreateStakePool"][0]

        delegate_amount = amount - pledge_amount

        if delegate_amount > 0:
            response = self.wallet.delegation_create(0, self.address, pool_id, { "in_top_x_mb" : None })
            tx_id = response["tx_id"]
            tx_ids.append(tx_id)

            delegation_id = response["delegation_id"]

            response = self.wallet.delegation_stake(0, { "atoms": f"{delegate_amount}" }, delegation_id, { "in_top_x_mb" : None })
            tx_id = response["tx_id"]
            tx_ids.append(tx_id)

        log.info(f"Node {self.index}: pool {pool_id} created; pledge amount = {pledge_amount / ATOMS_PER_COIN}, delegation amount = {delegate_amount / ATOMS_PER_COIN}")

        return self.tx_ids_to_signed_txs(tx_ids)


class Helper():
    def __init__(self):
        self.nodes = []

        for i in range(NODES_COUNT):
            log.info(f"Creating node {i}")

            node_rpc = make_node_rpc(i)
            wallet_rpc = make_wallet_rpc(i)

            node = Node(i, node_rpc, wallet_rpc, f"wallet{i:02d}", WALLET_MNEMONICS[i])
            self.nodes.append(node)

    def generate_block(self, node_idx, block_input_data, transactions):
        block_hex = self.nodes[node_idx].node.blockprod_generate_block(
            block_input_data, transactions, [], "LeaveEmptySpace")
        self.nodes[node_idx].node.chainstate_submit_block(block_hex)

    def create_initial_block(self, node_idx, transactions):
        best_block_id = self.nodes[node_idx].node.chainstate_best_block_id()
        best_block_id = hex_to_dec_array(best_block_id)

        block_input_data = block_input_data_obj.encode({"None": ()}).to_hex()[2:]

        self.generate_block(node_idx, block_input_data, transactions)

    def give_coins_to_nodes(self):
        tip_id = self.nodes[0].node.chainstate_best_block_id()

        outputs = []

        for node in self.nodes:
            pub_key_bytes = pub_key_bytes_from_hex(node.pub_key_hex)
            output = {
                "Transfer": [
                    {"Coin": COINS_PER_NODE * ATOMS_PER_COIN},
                    {"PublicKey": {"key": {"Secp256k1Schnorr": {"pubkey_data": pub_key_bytes}}}}
                ],
            }
            outputs.append(output)

        encoded_tx, tx_id = make_tx([reward_input(tip_id)], outputs, 0)

        self.create_initial_block(0, [encoded_tx])

    def create_pools(self):
        all_txs = []

        for node in self.nodes:
            log.info(f"Creating pools for node {node.index}")

            coins_per_node = BASE_COINS_AT_STAKE_PER_NODE * (node.index % 3 + 1)
            coins_per_pool = coins_per_node / 3
            amount_per_pool = int(coins_per_pool) * ATOMS_PER_COIN

            txs = node.create_pool_and_delegate(amount_per_pool, 0)
            all_txs.extend(txs)

            txs = node.create_pool_and_delegate(amount_per_pool, 0.5)
            all_txs.extend(txs)

            txs = node.create_pool_and_delegate(amount_per_pool, 1)
            all_txs.extend(txs)

        self.create_initial_block(0, all_txs)

    def wait_for_height(self, height):
        log.info(f"Waiting for nodes to reach the height {height}")
        for node in self.nodes:
            while True:
                node_mainchain_height = node.node.chainstate_best_block_height(0)
                if node_mainchain_height >= height:
                    break
                time.sleep(1)

    def start_staking(self):
        log.info("Starting staking")
        for node in self.nodes:
            node.wallet.staking_start(0)


def _main():
    logging.basicConfig(level=logging.INFO)

    helper = Helper()

    chainstate_is_empty = helper.nodes[0].node.chainstate_best_block_height() == 0

    if chainstate_is_empty:
        helper.give_coins_to_nodes()
        helper.wait_for_height(1)
        helper.create_pools()
        helper.wait_for_height(2)

    helper.start_staking()

if __name__ == "__main__":
    sys.exit(_main())
