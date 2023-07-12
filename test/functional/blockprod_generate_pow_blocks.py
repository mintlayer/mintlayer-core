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
from test_framework.util import (
    assert_equal,
)

import random, scalecodec

block_input_data_obj = scalecodec.base.RuntimeConfiguration().create_scale_object('GenerateBlockInputData')

class GeneratePoWBlocksTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def block_height(self, n):
        tip = self.nodes[n].chainstate_best_block_id()
        return self.nodes[n].chainstate_block_height_in_main_chain(tip)

    def assert_tip(self, expected):
        tip = self.nodes[0].chainstate_best_block_id()
        block = self.nodes[0].chainstate_get_block(tip)
        assert_equal(block, expected)

    def generate_block(self, block_input_data, transactions):
        old_block_height = self.block_height(0)

        block = self.nodes[0].blockprod_generate_block(block_input_data, transactions)
        self.nodes[0].chainstate_submit_block(block)

        assert_equal(self.block_height(0), old_block_height + 1)
        self.assert_tip(block)

    def run_test(self):
        block_input_data = block_input_data_obj.encode(
            {
                "PoW": {
                    "reward_destination": "AnyoneCanSpend",
                }
            }
        ).to_hex()[2:]

        for i in range(random.randint(100, 1000)):
            self.nodes[0].blockprod_generate_block(block_input_data, [])

if __name__ == '__main__':
    GeneratePoWBlocksTest().main()
