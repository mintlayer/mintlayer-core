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

from scalecodec.base import RuntimeConfiguration
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)

block_input_data_obj = RuntimeConfiguration().create_scale_object('GenerateBlockInputData')


class RestartWithDifferentMagicBytes(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            "--blockprod-min-peers-to-produce-blocks=0"
        ]]

    def run_test(self):
        # generate and process block to update chainstate db
        block_input_data = block_input_data_obj.encode(
            {"PoW": {"reward_destination": "AnyoneCanSpend"}}
        ).to_hex()[2:]

        block = self.nodes[0].blockprod_generate_block(block_input_data, [], [], "LeaveEmptySpace")
        self.nodes[0].chainstate_submit_block(block)

        tip_height = self.nodes[0].chainstate_best_block_height()
        assert_equal(1, tip_height)

        # restart the node and check that the db hasn't changed
        self.restart_node(0)
        tip_height = self.nodes[0].chainstate_best_block_height()
        assert_equal(1, tip_height)

        # restart the node with different magic bytes and check that db was cleaned up
        self.restart_node(0, extra_args=["--chain-magic-bytes=ffff"])
        tip_height = self.nodes[0].chainstate_best_block_height()
        assert_equal(0, tip_height)


if __name__ == '__main__':
    RestartWithDifferentMagicBytes().main()
