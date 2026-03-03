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

"""Mempool orphan from disconnected peer

Check that:
* A peer sees an orphan transaction
* When the originator disconnects, the orphan is removed
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import (make_tx, reward_input, tx_input)

class MempoolOrphanFromDisconnectedPeerTest(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [[], []]

    def setup_network(self):
        self.setup_nodes()
        self.sync_all(self.nodes[0:1])
        self.connect_nodes(0, 1)

    def run_test(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]

        # Get genesis ID
        genesis_id = node0.chainstate_best_block_id()

        (tx1, tx1_id) = make_tx([ reward_input(genesis_id) ], [ 1_000_000 ] )
        (tx2, tx2_id) = make_tx([ tx_input(tx1_id) ], [ 900_000 ] )

        # Submit two transactions that build on top of each other but only propagate the second one
        node0.mempool_submit_transaction(tx1, {})
        node0.p2p_submit_transaction(tx2, {})

        # Check the node gets the orphan transaction
        self.wait_until(lambda: node1.mempool_contains_orphan_tx(tx2_id), timeout = 60)

        # Now disconnect the nodes and check the orphan is gone
        self.disconnect_nodes(0, 1)
        self.wait_until(lambda: not node1.mempool_contains_orphan_tx(tx2_id), timeout = 5)

        # Some final sanity checks
        assert node0.mempool_contains_tx(tx1_id)
        assert node0.mempool_contains_tx(tx2_id)
        assert not node1.mempool_contains_tx(tx1_id)
        assert not node1.mempool_contains_tx(tx2_id)
        assert not node1.mempool_contains_orphan_tx(tx1_id)
        assert not node1.mempool_contains_orphan_tx(tx2_id)


if __name__ == '__main__':
    MempoolOrphanFromDisconnectedPeerTest().main()
