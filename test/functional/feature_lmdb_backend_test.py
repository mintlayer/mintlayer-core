#!/usr/bin/env python3
# Copyright (c) 2017-2021 The Bitcoin Core developers
# Copyright (c) 2022 RBB S.r.l
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

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
        block = self.nodes[0].blockprod_generate_block(block_input_data, [])
        blocks.append(block)
        node.chainstate_submit_block(blocks[0])
        block = self.nodes[0].blockprod_generate_block(block_input_data, [])
        blocks.append(block)
        node.chainstate_submit_block(blocks[1])
        assert_equal(self.block_height(), 2)
        self.assert_tip(blocks[1])

        # Restart the node
        self.restart_node()

        # Check the most up-to-date tip has survived the shutdown/start cycle
        assert_equal(self.block_height(), 2)
        self.assert_tip(blocks[1])

        # Add three more blocks
        for i in range(2, 5):
            block = self.nodes[0].blockprod_generate_block(block_input_data, [])
            blocks.append(block)
            node.chainstate_submit_block(blocks[i])
        assert_equal(self.block_height(), 5)
        self.assert_tip(blocks[4])

        # Restart the node
        self.restart_node()

        # Check the most up-to-date tip has survived the shutdown/start cycle
        self.assert_tip(blocks[4])

if __name__ == '__main__':
    ExampleTest().main()
