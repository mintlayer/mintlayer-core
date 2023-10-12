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

class SyncingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [
            ["--blockprod-min-peers-to-produce-blocks=0"],
            ["--blockprod-min-peers-to-produce-blocks=0"],
        ]

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)
        self.sync_all(self.nodes[0:2])

    def block_height(self, n):
        tip = self.nodes[n].chainstate_best_block_id()
        return self.nodes[n].chainstate_block_height_in_main_chain(tip)

    def assert_tip(self, n, expected):
        tip = self.nodes[n].chainstate_best_block_id()
        block = self.nodes[n].chainstate_get_block(tip)
        assert_equal(block, expected)

    def submit_block(self, block):
        node = self.nodes[0]
        node.chainstate_submit_block(block)
        self.wait_until(lambda: node.mempool_local_best_block_id() == node.chainstate_best_block_id(), timeout = 5)

    def run_test(self):
        # get current tip hash
        node0_tip = self.nodes[0].chainstate_best_block_id()
        node1_tip = self.nodes[1].chainstate_best_block_id()
        assert_equal(node0_tip, node1_tip)
        assert_equal(self.block_height(0), 0)
        assert_equal(self.block_height(1), 0)

        # disconnect nodes
        self.disconnect_nodes(0, 1)

        blocks = []

        block_input_data = block_input_data_obj.encode(
            {
                "PoW": {
                    "reward_destination": "AnyoneCanSpend",
                }
            }
        ).to_hex()[2:]

        # add first block
        block = self.nodes[0].blockprod_generate_block(block_input_data, [], [], "LeaveEmptySpace")
        blocks.append(block)
        self.submit_block(blocks[0])
        assert_equal(self.block_height(0), 1)
        assert_equal(self.block_height(1), 0)
        self.assert_tip(0, blocks[0])

        # add second block
        block = self.nodes[0].blockprod_generate_block(block_input_data, [], [], "LeaveEmptySpace")
        blocks.append(block)
        self.submit_block(blocks[1])
        assert_equal(self.block_height(0), 2)
        assert_equal(self.block_height(1), 0)
        self.assert_tip(0, blocks[1])

        # connect nodes
        self.connect_nodes(0, 1)
        self.sync_all(self.nodes[0:2])

        node0_tip = self.nodes[0].chainstate_best_block_id()
        node1_tip = self.nodes[1].chainstate_best_block_id()
        assert_equal(node0_tip, node1_tip)

        # node0 hasn't downloaded any blocks but node1 has two new blocks
        assert_equal(self.block_height(0), 2)
        assert_equal(self.block_height(1), 2)

        self.assert_tip(0, blocks[1])
        self.assert_tip(1, blocks[1])

        # submit third block
        block = self.nodes[0].blockprod_generate_block(block_input_data, [], [], "LeaveEmptySpace")
        blocks.append(block)
        self.submit_block(blocks[2])
        assert_equal(self.block_height(0), 3)
        self.assert_tip(0, blocks[2])

        # submit final block
        block = self.nodes[0].blockprod_generate_block(block_input_data, [], [], "LeaveEmptySpace")
        blocks.append(block)
        self.submit_block(blocks[3])
        assert_equal(self.block_height(0), 4)
        self.assert_tip(0, blocks[3])

        # verify that they are in sync
        self.sync_all(self.nodes[0:2])
        node0_tip = self.nodes[0].chainstate_best_block_id()
        node1_tip = self.nodes[1].chainstate_best_block_id()
        assert_equal(node0_tip, node1_tip)
        assert_equal(self.block_height(0), 4)
        assert_equal(self.block_height(1), 4)
        self.assert_tip(1, blocks[3])

if __name__ == '__main__':
    SyncingTest().main()
