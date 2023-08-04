#!/usr/bin/env python3
"""Mempool initial block download test

Check that:
* Transactions are rejected during IBD
* Transactions are accepted after IBD is finished
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error
from test_framework.mintlayer import *
import time

# Default max tip age of 24hrs
MAX_TIP_AGE = 24 * 60 * 60
IBD_ERR = "Transaction added during initial block download"

class MempoolTxSubmissionTest(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            "--blockprod-min-peers-to-produce-blocks=0",
            "--max-tip-age={}".format(MAX_TIP_AGE),
        ]]

    def setup_network(self):
        self.setup_nodes()
        self.sync_all(self.nodes[0:1])

    def advance_mock_time(self, delta):
        self.mock_time += delta
        self.nodes[0].node_set_mock_time(self.mock_time)

    def submit_block(self, block):
        node = self.nodes[0]
        node.chainstate_submit_block(block)
        block_id = node.chainstate_best_block_id()
        self.wait_until(lambda: node.mempool_local_best_block_id() == block_id, timeout = 5)
        return block_id

    def run_test(self):
        self.mock_time = int(time.time())
        self.advance_mock_time(0)

        node = self.nodes[0]

        # Get chain tip
        genesis_id = node.chainstate_best_block_id()
        self.log.debug('Initial tip: {}'.format(genesis_id))

        # Prepare three transactions, each spending the previous one in sequence
        (tx1, tx1_id) = make_tx([ reward_input(genesis_id) ], [ 1_000_000 ] )
        self.log.debug("Encoded tx1 {}: {}".format(tx1_id, tx1))

        # The transaction should be rejected because of IBD
        assert_raises_rpc_error(None, IBD_ERR, node.mempool_submit_transaction, tx1)
        assert not node.mempool_contains_tx(tx1_id)

        # Produce a block but wait over a day to submit it
        (block1, block1_id) = mine_pow_block(genesis_id, timestamp = self.mock_time)
        self.advance_mock_time(MAX_TIP_AGE + 5)
        self.submit_block(block1)

        # The transaction should still be rejected because of IBD
        assert_raises_rpc_error(None, IBD_ERR, node.mempool_submit_transaction, tx1)
        assert not node.mempool_contains_tx(tx1_id)

        # Produce a block but don't wait too long before submission
        (block2, block2_id) = mine_pow_block(block1_id, timestamp = self.mock_time)
        self.advance_mock_time(MAX_TIP_AGE - 15)
        self.log.debug("Chain info 1: {}".format(node.chainstate_info()))
        self.submit_block(block2)
        self.log.debug("Chain info 2: {}".format(node.chainstate_info()))

        # The transaction should now be accepted
        node.mempool_submit_transaction(tx1)
        assert node.mempool_contains_tx(tx1_id)

if __name__ == '__main__':
    MempoolTxSubmissionTest().main()

