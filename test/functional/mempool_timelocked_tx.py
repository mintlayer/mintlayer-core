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

""" Time-locked transaction handling test """

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import *
from test_framework.util import (assert_raises_rpc_error)

class MempoolTimelockedTxTest(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            "--blockprod-min-peers-to-produce-blocks=0",
        ]]

    def setup_network(self):
        self.setup_nodes()
        self.sync_all(self.nodes[0:1])

    def generate_block(self):
        node = self.nodes[0]

        block_input_data = { "PoW": { "reward_destination": "AnyoneCanSpend" } }
        block_input_data = block_input_data_obj.encode(block_input_data).to_hex()[2:]

        # create a new block, taking transactions from mempool
        block = node.blockprod_generate_block(block_input_data, [], [], "FillSpaceFromMempool")
        node.chainstate_submit_block(block)
        block_id = node.chainstate_best_block_id()

        # Wait for mempool to sync
        self.wait_until(lambda: node.mempool_local_best_block_id() == block_id, timeout = 5)

        return block_id

    def run_test(self):
        node = self.nodes[0]

        # Get chain tip
        genesis_id = node.chainstate_best_block_id()

        # Prepare a transaction with a bunch of time locked outputs
        (tx0, tx0_id) = make_tx(
                [ reward_input(genesis_id) ],
                [
                    tx_output(1_000_000, timelock = { 'UntilHeight': 3 }),
                    tx_output(1_000_000, timelock = { 'ForBlockCount': 4 }),
                    1_000_000,
                ],
            )
        self.log.debug("Encoded tx0 {}: {}".format(tx0_id, tx0))

        # Prepare transactions spending the outputs
        (tx1, tx1_id) = make_tx([ tx_input(tx0_id, 0) ], [ 900_000 ] )
        self.log.debug("Encoded tx1 {}: {}".format(tx1_id, tx1))

        (tx2, tx2_id) = make_tx([ tx_input(tx0_id, 1) ], [ 900_000 ] )
        self.log.debug("Encoded tx2 {}: {}".format(tx2_id, tx2))

        (tx3, tx3_id) = make_tx([ tx_input(tx0_id, 2) ], [ 900_000 ] )
        self.log.debug("Encoded tx3 {}: {}".format(tx3_id, tx3))

        # Submit the transactions
        node.mempool_submit_transaction(tx0, {})
        node.mempool_submit_transaction(tx1, {})
        node.mempool_submit_transaction(tx3, {})
        # Cannot submit tx2 yet, it spends and unconfirmed time-locked output
        assert_raises_rpc_error(None, "locked until height", node.mempool_submit_transaction, tx2, {})

        assert node.mempool_contains_tx(tx0_id)
        assert node.mempool_contains_tx(tx1_id)
        assert not node.mempool_contains_tx(tx2_id)
        assert node.mempool_contains_tx(tx3_id)

        # tx0 should make it into a block now, and also tx3 that spends the unconstrained output
        self.generate_block() # Block 1
        assert not node.mempool_contains_tx(tx0_id)
        assert node.mempool_contains_tx(tx1_id)
        assert not node.mempool_contains_tx(tx2_id)
        assert not node.mempool_contains_tx(tx3_id)

        # We can now submit tx2
        node.mempool_submit_transaction(tx2, {})
        assert not node.mempool_contains_tx(tx0_id)
        assert node.mempool_contains_tx(tx1_id)
        assert node.mempool_contains_tx(tx2_id)
        assert not node.mempool_contains_tx(tx3_id)

        self.generate_block() # Block 2
        assert not node.mempool_contains_tx(tx0_id)
        assert node.mempool_contains_tx(tx1_id)
        assert node.mempool_contains_tx(tx2_id)
        assert not node.mempool_contains_tx(tx3_id)

        # tx1 now should be included in the block as time lock is now ready
        self.generate_block() # Block 3
        assert not node.mempool_contains_tx(tx0_id)
        assert not node.mempool_contains_tx(tx1_id)
        assert node.mempool_contains_tx(tx2_id)
        assert not node.mempool_contains_tx(tx3_id)

        self.generate_block() # Block 4
        assert not node.mempool_contains_tx(tx0_id)
        assert not node.mempool_contains_tx(tx1_id)
        assert node.mempool_contains_tx(tx2_id)
        assert not node.mempool_contains_tx(tx3_id)

        # tx2 time lock is now released
        self.generate_block() # Block 5
        assert not node.mempool_contains_tx(tx0_id)
        assert not node.mempool_contains_tx(tx1_id)
        assert not node.mempool_contains_tx(tx2_id)
        assert not node.mempool_contains_tx(tx3_id)

        # Check each transaction is included in appropriate block
        for ht in range(1, 6):
            block = node.chainstate_get_block(node.chainstate_block_id_at_height(ht))
            for (tx, where) in [ (tx0, 1), (tx1, 3), (tx2, 5), (tx3, 1) ]:
                should_be_here = where == ht
                is_here = tx in block
                assert should_be_here == is_here

if __name__ == '__main__':
    MempoolTimelockedTxTest().main()
