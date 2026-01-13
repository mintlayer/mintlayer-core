#!/usr/bin/env python3
#  Copyright (c) 2023 RBB S.r.l
#  Copyright (c) 2017-2021 The Bitcoin Core developers
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
"""Mempool orphan submission test

Check that:
* Orphans transactions are rejected if submitted locally to mempool.
* The initial rejection does not prevent resubmission once the dependencies are resolved.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import (make_tx, reward_input, tx_input)
from test_framework.util import assert_raises_rpc_error


class MempoolLocalOrphanSubmissionTest(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[]]

    def setup_network(self):
        self.setup_nodes()
        self.sync_all(self.nodes[0:1])

    def run_test(self):
        node = self.nodes[0]

        # Get genesis ID
        genesis_id = node.chainstate_best_block_id()

        (tx1, tx1_id) = make_tx([ reward_input(genesis_id) ], [ 1_000_000 ] )
        (tx2, tx2_id) = make_tx([ tx_input(tx1_id) ], [ 900_000 ] )

        # Submit tx2 first, check it is rejected since local txs should not be orphans
        assert_raises_rpc_error(None, 'originating at local node', node.mempool_submit_transaction, tx2, {})
        assert not node.mempool_contains_tx(tx2_id)
        self.wait_until(lambda: not node.mempool_contains_orphan_tx(tx2_id), timeout = 5)

        # Submit the first transaction now
        node.mempool_submit_transaction(tx1, {})
        assert node.mempool_contains_tx(tx1_id)
        assert not node.mempool_contains_tx(tx2_id)
        self.wait_until(lambda: not node.mempool_contains_orphan_tx(tx1_id), timeout = 5)
        self.wait_until(lambda: not node.mempool_contains_orphan_tx(tx2_id), timeout = 5)

        # Check local submission of the second transaction has not been blocked
        node.mempool_submit_transaction(tx2, {})
        assert node.mempool_contains_tx(tx2_id)


if __name__ == '__main__':
    MempoolLocalOrphanSubmissionTest().main()
