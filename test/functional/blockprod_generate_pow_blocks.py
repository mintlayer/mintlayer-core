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

from scalecodec.base import ScaleBytes, ScaleDecoder
from test_framework.authproxy import JSONRPCException
from test_framework.mintlayer import block_input_data_obj
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)

import random, time

class GeneratePoWBlocksTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            "--blockprod-min-peers-to-produce-blocks=0",
        ]]

    def assert_chain(self, block, previous_tip):
        assert_equal(block["header"]["header"]["prev_block_id"][2:], previous_tip)

    def assert_height(self, expected_height, expected_block):
        block_id = self.nodes[0].chainstate_block_id_at_height(expected_height)
        block = self.nodes[0].chainstate_get_block(block_id)
        assert_equal(block, expected_block)

    def assert_pow_consensus(self, block):
        if block["header"]["header"]["consensus_data"].get("PoW") is None:
            raise AssertionError("Block {} was not PoS".format(block))

    def assert_tip(self, expected):
        tip = self.nodes[0].chainstate_best_block_id()
        block = self.nodes[0].chainstate_get_block(tip)
        assert_equal(block, expected)

    def block_height(self, n):
        tip = self.nodes[n].chainstate_best_block_id()
        return self.nodes[n].chainstate_block_height_in_main_chain(tip)

    def generate_block(self, expected_height, block_input_data, transactions):
        node = self.nodes[0]
        previous_block_id = node.chainstate_best_block_id()

        # Block production may fail if the Job Manager found a new tip, so try and sleep
        for _ in range(5):
            try:
                block_hex = node.blockprod_generate_block(block_input_data, transactions, [], "LeaveEmptySpace")
                break
            except JSONRPCException:
                block_hex = node.blockprod_generate_block(block_input_data, transactions, [], "LeaveEmptySpace")
                time.sleep(1)

        block_hex_array = bytearray.fromhex(block_hex)
        block = ScaleDecoder.get_decoder_class('BlockV1', ScaleBytes(block_hex_array)).decode()

        node.chainstate_submit_block(block_hex)
        self.wait_until(lambda: node.mempool_local_best_block_id() == node.chainstate_best_block_id(), timeout = 5)

        self.assert_tip(block_hex)
        self.assert_height(expected_height, block_hex)
        self.assert_pow_consensus(block)
        self.assert_chain(block, previous_block_id)

    def hex_to_dec_array(self, hex_string):
        return [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)]

    def run_test(self):
        block_input_data = block_input_data_obj.encode(
            {
                "PoW": {
                    "reward_destination": "AnyoneCanSpend",
                }
            }
        ).to_hex()[2:]

        for i in range(random.randint(10, 100)):
            self.generate_block(i + 1, block_input_data, [])

if __name__ == '__main__':
    GeneratePoWBlocksTest().main()
