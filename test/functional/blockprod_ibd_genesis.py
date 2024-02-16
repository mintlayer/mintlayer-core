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

MAX_TIP_AGE = 24 * 60 * 60
IBD_ERR = "Wait for chainstate to sync before producing blocks"

class BlockprodIBDGenesisFailsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            "--blockprod-min-peers-to-produce-blocks=0",
            "--max-tip-age={}".format(MAX_TIP_AGE),
            "--chain-genesis-block-timestamp=0",
        ]]

    def run_test(self):
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
            "FillSpaceFromMempool",
        )

class BlockprodIBDGenesisFailsButSkipSucceedsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            "--blockprod-min-peers-to-produce-blocks=0",
            "--max-tip-age={}".format(MAX_TIP_AGE),
            "--chain-genesis-block-timestamp=0",
            "--blockprod-skip-ibd-check",
        ]]

    def run_test(self):
        node = self.nodes[0]

        block_input_data = block_input_data_obj.encode(
            {
                "PoW": {
                    "reward_destination": "AnyoneCanSpend",
                }
            }
        ).to_hex()[2:]

        genesis_id = node.chainstate_best_block_id()

        # Blockprod should succeed because we're skipping the initial block download check

        block = node.blockprod_generate_block(block_input_data, [], [], "FillSpaceFromMempool")

        assert(genesis_id != node.chainstate_best_block_id())

class BlockprodIBDGenesisSucceedsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            "--blockprod-min-peers-to-produce-blocks=0",
            "--max-tip-age={}".format(MAX_TIP_AGE),
            "--chain-genesis-block-timestamp={}".format(int(time.time())),
        ]]

    def run_test(self):
        node = self.nodes[0]

        block_input_data = block_input_data_obj.encode(
            {
                "PoW": {
                    "reward_destination": "AnyoneCanSpend",
                }
            }
        ).to_hex()[2:]

        genesis_id = node.chainstate_best_block_id()

        # Blockprod should succeed because we're no longer in initial block download

        block = node.blockprod_generate_block(block_input_data, [], [], "FillSpaceFromMempool")
        node.chainstate_submit_block(block)

        assert(genesis_id != node.chainstate_best_block_id())

if __name__ == '__main__':
    BlockprodIBDGenesisFailsTest().main()
    BlockprodIBDGenesisFailsButSkipSucceedsTest().main()
    BlockprodIBDGenesisSucceedsTest().main()
