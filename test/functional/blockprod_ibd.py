#!/usr/bin/env python3
#  Copyright (c) 2023 RBB S.r.l
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

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error
from test_framework.mintlayer import *

import time

# Default max tip age of 24hrs
MAX_TIP_AGE = 24 * 60 * 60
IBD_ERR = "Wait for chainstate to sync before producing blocks"

class BlockprodIBDTest(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            "--blockprod-min-peers-to-produce-blocks=0",
            "--max-tip-age={}".format(MAX_TIP_AGE),
        ]]

    def advance_mock_time(self, delta):
        self.mock_time += delta
        self.nodes[0].node_set_mock_time(self.mock_time)

    def submit_block(self, block):
        node = self.nodes[0]
        node.chainstate_submit_block(block)
        block_id = node.chainstate_best_block_id()
        self.wait_until(lambda: node.mempool_local_best_block_id() == block_id, timeout = 5)
        return block_id

    def run_test(self):
        self.mock_time = int(time.time())
        self.advance_mock_time(0)

        node = self.nodes[0]

        block_input_data = block_input_data_obj.encode(
            {
                "PoW": {
                    "reward_destination": "AnyoneCanSpend",
                }
            }
        ).to_hex()[2:]

        genesis_id = node.chainstate_best_block_id()

        # Blockprod should fail because we're currently in initial block download

        assert_raises_rpc_error(
            None,
            IBD_ERR,
            node.blockprod_generate_block,
            block_input_data,
            [],
            [],
            'FillSpaceFromMempool',
        )

        # Advance the blockchain but wait, which should still cause blockprod to fail

        (block1, block1_id) = mine_pow_block(genesis_id, timestamp = self.mock_time)

        self.advance_mock_time(MAX_TIP_AGE + 5)
        self.submit_block(block1)

        assert_raises_rpc_error(
            None,
            IBD_ERR,
            node.blockprod_generate_block,
            block_input_data,
            [],
            [],
            'FillSpaceFromMempool',
        )

        # Advance the blockchain but this time succeed in producing a block

        self.advance_mock_time(MAX_TIP_AGE - 15)

        (block2, block2_id) = mine_pow_block(block1_id, timestamp = self.mock_time)
        self.submit_block(block2)

        node.blockprod_generate_block(block_input_data, [], [], 'FillSpaceFromMempool')

if __name__ == '__main__':
    BlockprodIBDTest().main()

