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

from datetime import datetime
import os
import sys

from common import *

SRC_ROOT_PATH = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
FUNC_TESTS_PATH = os.path.join(SRC_ROOT_PATH, "test", "functional")
sys.path.append(FUNC_TESTS_PATH)

from test_framework.authproxy import (
    AuthServiceProxy,
)


node00_rpc = make_node_rpc(0)

node00_cs_info = node00_rpc.chainstate_info()
bb_height = node00_cs_info['best_block_height']
bb_timestamp = node00_cs_info['best_block_timestamp']['timestamp']
bb_time = datetime.fromtimestamp(bb_timestamp)
print(f"Chainstate info at node 0: best block height = {bb_height}, best block time = {bb_time}")

for i in range(NODES_COUNT):
    wallet_rpc = make_wallet_rpc(i)
    pools = wallet_rpc.staking_list_pools(0)

    print(f"Node {i} pools:")
    for pool in pools:
        print(f"id = {pool['pool_id']}; balances (staker, total) = {pool['pledge']['decimal']}, {pool['balance']['decimal']}")
