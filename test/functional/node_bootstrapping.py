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
"""Test node bnootstrapping, both via RPC and the command line option.
"""

import os
import shutil
import tempfile

from scalecodec.base import RuntimeConfiguration
from test_framework.authproxy import JSONRPCException
from test_framework.mintlayer import make_tx, reward_input
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import assert_equal, assert_in


BLOCK_INPUT_DATA = RuntimeConfiguration().create_scale_object('GenerateBlockInputData').encode(
    {"PoW": {"reward_destination": "AnyoneCanSpend"}}
).to_hex()[2:]


class NodeBootstrappingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [
            ["--blockprod-min-peers-to-produce-blocks=0"]
        ]

    # Create the specified number of blocks; the first block will contain a transaction that
    # transfers the specified amount to AnyoneCanSpend.
    def create_blocks(self, blocks_count: int, initial_transfer_amount_atoms: int) -> list[str]:
        node = self.nodes[0]
        tip_id = node.chainstate_best_block_id()
        tx_outputs = [
            {'Transfer': [
                {'Coin': initial_transfer_amount_atoms},
                "AnyoneCanSpend"
            ]}
        ]
        encoded_tx, _ = make_tx([reward_input(tip_id)], tx_outputs, 0)

        block_ids = []
        for i in range(blocks_count):
            txs = [encoded_tx] if i == 0 else []

            block = node.blockprod_generate_block(
                BLOCK_INPUT_DATA, txs, [], "LeaveEmptySpace")
            node.chainstate_submit_block(block)

            tip_height = node.chainstate_best_block_height()
            assert_equal(tip_height, i + 1)

            block_id = node.chainstate_best_block_id()
            block_ids.append(block_id)

        return block_ids

    def run_test(self):
        node = self.nodes[0]
        stale_blocks_count = 5
        blocks_count = 10

        bogus_file = os.path.join(self.options.tmpdir, 'bogus.bin')
        with open(bogus_file, 'w') as f:
            f.write('bogus data')

        # Create the shorter chain (which will be the stale one) and invalidate it immediately,
        # so that the next chain starts from generis as well.
        stale_block_ids = self.create_blocks(stale_blocks_count, 111)
        node.chainstate_invalidate_block(stale_block_ids[0])
        # Sanity check
        tip_height = node.chainstate_best_block_height()
        assert_equal(tip_height, 0)

        # Create the longer chain.
        block_ids = self.create_blocks(blocks_count, 222)

        # Reset the failure flags on the shorter chain, just in case.
        node.chainstate_reset_block_failure_flags(stale_block_ids[0])

        # Export all blocks to a file.
        bootstrap_file_full = os.path.join(
            self.options.tmpdir, 'bootstrap_full.bin')
        node.chainstate_export_bootstrap_file(
            file_path=bootstrap_file_full, include_stale_blocks=True)

        # Export mainchain blocks to a file.
        bootstrap_file_mainchain = os.path.join(
            self.options.tmpdir, 'bootstrap_mainchain.bin')
        node.chainstate_export_bootstrap_file(
            file_path=bootstrap_file_mainchain, include_stale_blocks=False)

        def assert_blocks_exist(node: TestNode, block_ids: list[str]):
            for block_id in block_ids:
                block = node.chainstate_get_block(block_id)
                assert block is not None

        def assert_blocks_missing(node: TestNode, block_ids: list[str]):
            for block_id in block_ids:
                block = node.chainstate_get_block(block_id)
                assert block is None

        # Reset the node's data directory. The previous directory is backed up, just in case
        # it's needed for debugging later.
        def reset_datadir(backup_suffix: str):
            data_dir = self.get_node_datadir(0)
            shutil.move(data_dir, data_dir + backup_suffix)
            self.init_node_datadir(0)

        ############################################################################################
        # Test importing via RPC.

        self.stop_node(0)
        reset_datadir('.bak0')
        self.start_node(0)

        assert_blocks_missing(node, block_ids)
        assert_blocks_missing(node, stale_block_ids)
        node.chainstate_import_bootstrap_file(file_path=bootstrap_file_full)
        assert_blocks_exist(node, block_ids)
        assert_blocks_exist(node, stale_block_ids)

        self.stop_node(0)
        reset_datadir('.bak1')
        self.start_node(0)

        assert_blocks_missing(node, block_ids)
        assert_blocks_missing(node, stale_block_ids)
        node.chainstate_import_bootstrap_file(
            file_path=bootstrap_file_mainchain)
        assert_blocks_exist(node, block_ids)
        assert_blocks_missing(node, stale_block_ids)

        # Try importing bogus_file; the RPC call should fail and the chainstate should remain
        # in the same state.
        try:
            node.chainstate_import_bootstrap_file(file_path=bogus_file)
        except JSONRPCException as e:
            assert_in("Bootstrap error", str(e))

        assert_blocks_exist(node, block_ids)
        assert_blocks_missing(node, stale_block_ids)

        ############################################################################################
        # Test importing via the command line argument.
        # Note that in this case the node will exit immediately after importing, so we can't
        # call `self.start_node`, because it also waits for the RPC to come up.
        # Instead, we call `start` on the node object directly and wait for the process to finish.

        self.stop_node(0)
        reset_datadir('.bak2')

        # Import bootstrap_file_full
        node.start(extra_top_level_args=["--import-bootstrap-file", bootstrap_file_full])
        node_ret_code = node.process.wait(timeout=10)
        assert node_ret_code == 0

        # Start the node normally and check the blocks.
        self.start_node(0)
        assert_blocks_exist(node, block_ids)
        assert_blocks_exist(node, stale_block_ids)

        self.stop_node(0)
        reset_datadir('.bak3')

        # Import bootstrap_file_mainchain
        node.start(extra_top_level_args=["--import-bootstrap-file", bootstrap_file_mainchain])
        node_ret_code = node.process.wait(timeout=10)
        assert node_ret_code == 0

        # Start the node normally and check the blocks.
        self.start_node(0)
        assert_blocks_exist(node, block_ids)
        assert_blocks_missing(node, stale_block_ids)

        self.stop_node(0)

        # Try importing bogus_file; the node should exit with non-zero code and the chainstate
        # should remain in the same state.
        # Just in case, specify stderr_file explicitly, to make sure it's not re-used from
        # previous runs (though `start` would create a new file anyway).
        stderr_file = tempfile.NamedTemporaryFile(dir=node.stderr_dir, mode='w+', delete=False)
        node.start(extra_top_level_args=["--import-bootstrap-file", bogus_file], stderr=stderr_file)
        node_ret_code = node.process.wait(timeout=10)
        assert node_ret_code != 0

        stderr_file.seek(0)
        stderr = stderr_file.read()
        assert_in("Node bootstrapping failed", stderr)

        # Start the node normally and check the blocks.
        self.start_node(0)
        assert_blocks_exist(node, block_ids)
        assert_blocks_missing(node, stale_block_ids)


if __name__ == '__main__':
    NodeBootstrappingTest().main()
