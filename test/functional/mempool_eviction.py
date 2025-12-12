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
"""Mempool tx eviction test

Check that:
* Transactions are properly evicted from mempool if size limit is reached
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error
from test_framework.mintlayer import *

class MempoolTxEvictionTest(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[]]

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
        (tx2, tx2_id) = make_tx([ tx_input(tx1_id) ], [ 900_000 ] )
        (tx3, tx3_id) = make_tx([ tx_input(tx2_id) ], [ 800_000 ] )

        # Submit the transactions
        node.mempool_submit_transaction(tx1, {})
        node.mempool_submit_transaction(tx2, {})
        node.mempool_submit_transaction(tx3, {})
        assert node.mempool_contains_tx(tx1_id)
        assert node.mempool_contains_tx(tx2_id)
        assert node.mempool_contains_tx(tx3_id)

        # Set the mempool limit to evict the last transaction
        node.mempool_set_size_limit(node.mempool_memory_usage() - 1)
        assert node.mempool_contains_tx(tx1_id)
        assert node.mempool_contains_tx(tx2_id)
        assert not node.mempool_contains_tx(tx3_id)

        # Try to re-add the transaction, check it failed
        assert_raises_rpc_error(None, "fee threshold not met", node.mempool_submit_transaction, tx3, {})

        # Set the mempool limit to evict the second last transaction too
        node.mempool_set_size_limit(str(node.mempool_memory_usage() - 1))
        assert node.mempool_contains_tx(tx1_id)
        assert not node.mempool_contains_tx(tx2_id)
        assert not node.mempool_contains_tx(tx3_id)

        # Reset the mempool size to fit all transactions. Submit the missing transactions again
        # in the opposite order, check they both make their way in.
        node.mempool_set_size_limit(300_000_000)
        assert_raises_rpc_error(None, "Orphans not supported", node.mempool_submit_transaction, tx3, {})
        node.mempool_submit_transaction(tx2, {})
        assert node.mempool_contains_tx(tx1_id)
        assert node.mempool_contains_tx(tx2_id)
        assert not node.mempool_contains_tx(tx3_id)

        # Evict all transactions and reset the size afterwards
        node.mempool_set_size_limit("20")
        node.mempool_set_size_limit(str(300_000_000))
        assert not node.mempool_contains_tx(tx1_id)

        # Add a transaction that pays two outputs
        (tx1, tx1_id) = make_tx([ reward_input(genesis_id) ], [ 100_000_000, 100_000_000 ])
        node.mempool_submit_transaction(tx1, {})

        # Add two transactions with CPFP semantics
        (tx2a, tx2a_id) = make_tx([ tx_input(tx1_id) ], [ 99_000_000 ])
        (tx3a, tx3a_id) = make_tx([ tx_input(tx2a_id) ], [ 90_000_000 ])
        node.mempool_submit_transaction(tx2a, {})
        node.mempool_submit_transaction(tx3a, {})

        # Limit the mempool size so no more transactions fit
        node.mempool_set_size_limit(str(node.mempool_memory_usage()))
        assert node.mempool_contains_tx(tx1_id)
        assert node.mempool_contains_tx(tx2a_id)
        assert node.mempool_contains_tx(tx3a_id)

        # Add a transaction that pays higher fees than the previous two, so both need to be evicted
        (tx2b, tx2b_id) = make_tx([ tx_input(tx1_id, index = 1) ], [ 50_000_000, 5_000_000 ])
        node.mempool_submit_transaction(tx2b, {})
        assert node.mempool_contains_tx(tx1_id)
        assert node.mempool_contains_tx(tx2b_id)
        assert not node.mempool_contains_tx(tx2a_id)
        assert not node.mempool_contains_tx(tx3a_id)


if __name__ == '__main__':
    MempoolTxEvictionTest().main()

