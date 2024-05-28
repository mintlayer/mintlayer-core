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

import os
import sys

SRC_ROOT_PATH = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
FUNC_TESTS_PATH = os.path.join(SRC_ROOT_PATH, "test", "functional")
sys.path.append(FUNC_TESTS_PATH)

from test_framework.authproxy import (
    AuthServiceProxy,
)

from test_framework.mintlayer import (
    DEFAULT_INITIAL_MINT,
)


NODES_COUNT = 9

# The amount of coins to send to each node's wallet.
COINS_PER_NODE = 10_000_000

assert COINS_PER_NODE * NODES_COUNT < DEFAULT_INITIAL_MINT

# Some nodes will stake this amount, others twice this amount, some other ones 3 times this amount.
# The rest of the coins can be used for manual staking, if it's needed.
BASE_COINS_AT_STAKE_PER_NODE = 3_000_000

# Note: node index will be added to each of these numbers to form the actual port number,
# so make sure the ranges don't overlap.
# These values are also hard-coded in the .env file.
NODE_RPC_PORT_BASE = 40000
WALLET_RPC_PORT_BASE = 40100

# RPC username and password for node-daemon and wallet-rpc-daemon".
# These values are also hard-coded in the .env file.
NODE_RPC_USER = "user"
NODE_RPC_PWD = "password"
WALLET_RPC_USER = "user"
WALLET_RPC_PWD = "password"

WALLET_MNEMONICS = [
    "art " * 23 + "advance",
    "bar " * 23 + "anxiety",
    "cat " * 23 + "blanket",
    "dog " * 23 + "cable",
    "egg " * 23 + "area",
    "fox " * 23 + "awake",
    "gun " * 23 + "atom",
    "hen " * 23 + "apology",
    "ice " * 23 + "afford",
]


def make_node_rpc(node_index):
    node_rpc_port = NODE_RPC_PORT_BASE + node_index
    node_rpc = AuthServiceProxy(f"http://{NODE_RPC_USER}:{NODE_RPC_PWD}@127.0.0.1:{node_rpc_port}")
    return node_rpc


def make_wallet_rpc(node_index):
    wallet_rpc_port = WALLET_RPC_PORT_BASE + node_index
    wallet_rpc = AuthServiceProxy(f"http://{WALLET_RPC_USER}:{WALLET_RPC_PWD}@127.0.0.1:{wallet_rpc_port}")
    return wallet_rpc
