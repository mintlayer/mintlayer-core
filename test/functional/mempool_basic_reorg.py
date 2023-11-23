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
"""Mempool reorg test

Check that:
* Transactions are collected into blocks when a new block is issued.
* Transactions are correctly put back into mempool when the block is reorged out.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import *

class MempoolTxSubmissionTest(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            "--blockprod-min-peers-to-produce-blocks=0",
        ]]

    def setup_network(self):
        self.setup_nodes()
        self.sync_all(self.nodes[0:1])

    def run_test(self):
        node = self.nodes[0]

        # Get chain tip
        genesis_id = node.chainstate_best_block_id()
        self.log.debug('Initial tip: {}'.format(genesis_id))

        # Prepare three transactions, each spending the previous one in sequence
        (tx1, tx1_id) = make_tx([ reward_input(genesis_id) ], [ 1_000_000 ] )
        self.log.debug("Encoded tx1 {}: {}".format(tx1_id, tx1))
        (tx2, tx2_id) = make_tx([ tx_input(tx1_id) ], [ 900_000 ] )
        self.log.debug("Encoded tx2 {}: {}".format(tx2_id, tx2))
        (tx3, tx3_id) = make_tx([ tx_input(tx2_id) ], [ 800_000 ] )
        self.log.debug("Encoded tx3 {}: {}".format(tx3_id, tx3))

        # Submit the first transaction
        node.mempool_submit_transaction(tx1, {})
        assert node.mempool_contains_tx(tx1_id)
        assert not node.mempool_contains_tx(tx2_id)
        assert not node.mempool_contains_tx(tx3_id)

        block_input_data = block_input_data_obj.encode(
            {
                "PoW": {
                    "reward_destination": "AnyoneCanSpend",
                }
            }
        ).to_hex()[2:]

        # create a new block, not taking transactions from mempool
        block1 = node.blockprod_generate_block(block_input_data, [tx1], [], "LeaveEmptySpace")
        node.chainstate_submit_block(block1)
        block1_id = node.chainstate_best_block_id()
        self.wait_until(lambda: node.mempool_local_best_block_id() == block1_id, timeout = 5)
        assert not node.mempool_contains_tx(tx1_id)
        assert not node.mempool_contains_tx(tx2_id)
        assert not node.mempool_contains_tx(tx3_id)

        # Submit the other two transactions
        node.mempool_submit_transaction(tx2, {})
        node.mempool_submit_transaction(tx3, {})
        assert not node.mempool_contains_tx(tx1_id)
        assert node.mempool_contains_tx(tx2_id)
        assert node.mempool_contains_tx(tx3_id)

        # Submit a block with the other two transactions
        block2 = node.blockprod_generate_block(block_input_data, [tx2, tx3], [], "LeaveEmptySpace")
        node.chainstate_submit_block(block2)
        block2_id = node.chainstate_best_block_id()
        self.wait_until(lambda: node.mempool_local_best_block_id() == block2_id, timeout = 5)
        assert not node.mempool_contains_tx(tx1_id)
        assert not node.mempool_contains_tx(tx2_id)
        assert not node.mempool_contains_tx(tx3_id)

        # Create two new blocks on top of block1
        (block2a, block2a_id) = mine_pow_block(block1_id)
        (block3a, block3a_id) = mine_pow_block(block2a_id)
        self.log.debug("Encoded block2a {}: {}".format(block2a_id, block2a))
        self.log.debug("Encoded block3a {}: {}".format(block3a_id, block3a))

        # Submit the two blocks and verify block3a in the new tip
        node.chainstate_submit_block(block2a)
        node.chainstate_submit_block(block3a)
        self.wait_until(lambda: node.mempool_local_best_block_id() == block3a_id, timeout = 5)

        # Check transactions from disconnected blocks are back in the mempool
        assert not node.mempool_contains_tx(tx1_id)
        assert node.mempool_contains_tx(tx2_id)
        assert node.mempool_contains_tx(tx3_id)

if __name__ == '__main__':
    MempoolTxSubmissionTest().main()
