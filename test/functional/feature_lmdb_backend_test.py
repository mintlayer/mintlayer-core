#!/usr/bin/env python3
#  Copyright (c) 2022 RBB S.r.l
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

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)

import scalecodec

block_input_data_obj = scalecodec.base.RuntimeConfiguration().create_scale_object('GenerateBlockInputData')

class ExampleTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            "--blockprod-min-peers-to-produce-blocks=0",
        ]]

    def setup_network(self):
        self.setup_nodes()
        self.sync_all([self.nodes[0]])

    def block_height(self):
        tip = self.nodes[0].chainstate_best_block_id()
        return self.nodes[0].chainstate_block_height_in_main_chain(tip)

    def assert_tip(self, expected):
        tip = self.nodes[0].chainstate_best_block_id()
        block = self.nodes[0].chainstate_get_block(tip)
        assert_equal(block, expected)

    def restart_node(self):
        self.stop_node(0)
        self.start_node(0)

    def run_test(self):
        blocks = []

        node = self.nodes[0]

        # get current tip hash
        assert_equal(self.block_height(), 0)

        block_input_data = block_input_data_obj.encode(
            {
                "PoW": {
                    "reward_destination": "AnyoneCanSpend",
                }
            }
        ).to_hex()[2:]

        # add two blocks
        block = node.blockprod_generate_block(block_input_data, [], [], "LeaveEmptySpace")
        blocks.append(block)
        node.chainstate_submit_block(blocks[0])
        self.wait_until(lambda: node.mempool_local_best_block_id() == node.chainstate_best_block_id(), timeout = 5)

        block = node.blockprod_generate_block(block_input_data, [], [], "LeaveEmptySpace")
        blocks.append(block)
        node.chainstate_submit_block(blocks[1])
        self.wait_until(lambda: node.mempool_local_best_block_id() == node.chainstate_best_block_id(), timeout = 5)

        assert_equal(self.block_height(), 2)
        self.assert_tip(blocks[1])

        # Restart the node
        self.restart_node()

        # Check the most up-to-date tip has survived the shutdown/start cycle
        assert_equal(self.block_height(), 2)
        self.assert_tip(blocks[1])

        # Add three more blocks
        for i in range(2, 5):
            block = node.blockprod_generate_block(block_input_data, [], [], "LeaveEmptySpace")
            blocks.append(block)
            node.chainstate_submit_block(blocks[i])
            self.wait_until(lambda: node.mempool_local_best_block_id() == node.chainstate_best_block_id(), timeout = 5)
        assert_equal(self.block_height(), 5)
        self.assert_tip(blocks[4])

        # Restart the node
        self.restart_node()

        # Check the most up-to-date tip has survived the shutdown/start cycle
        self.assert_tip(blocks[4])

if __name__ == '__main__':
    ExampleTest().main()
