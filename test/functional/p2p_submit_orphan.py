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
* After submitting a transaction with a missing input UTXO, it ends up in the orphan pool
* After submitting a transaction that defines the UTXO, both are in non-orphan mempool
"""

from test_framework.p2p import (P2PInterface, P2PDataStore)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import (make_tx_dict, reward_input, tx_input, calc_tx_id)
import scalecodec
import time


class MempoolOrphanSubmissionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = self.num_nodes * [['--p2p-disable-noise']]

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)
        self.connect_nodes(1, 2)
        self.sync_all(self.nodes[0:3])

    def run_test(self):
        # Spin up our node, connect it to the rest via node0
        my_node = P2PDataStore()
        node0 = self.nodes[0]
        node0.add_p2p_connection(my_node)

        # Get genesis ID
        genesis_id = node0.chainstate_block_id_at_height(0)
        tx1 = make_tx_dict([ reward_input(genesis_id) ], [ 1_000_000 ] )
        tx1_id = calc_tx_id(tx1)
        tx2 = make_tx_dict([ tx_input(tx1_id) ], [ 900_000 ] )
        tx2_id = calc_tx_id(tx2)

        # Submit the dependent transaction first, check it is in node0's orphan pool
        my_node.submit_tx(tx2)
        self.wait_until(lambda: node0.mempool_contains_orphan_tx(tx2_id), timeout = 5)

        # Wait for a while to give enough time for the transactions to propagate through the
        # network. It should not happen, the submitted transaction should be held up in node0's
        # orphan pool for now.
        time.sleep(2)
        for node in self.nodes[1:3]:
            assert not node.mempool_contains_tx(tx2_id)
            assert not node.mempool_contains_orphan_tx(tx2_id)

        # Submit the first transaction, resolving the sequence
        my_node.submit_tx(tx1)

        # Check both transactions have propagated to the last peer
        for node in self.nodes:
            has_txs = lambda: all(node.mempool_contains_tx(tx_id) for tx_id in [tx1_id, tx2_id])
            # there is random delay when relaying txs so we need to wait for a while
            self.wait_until(has_txs, timeout = 60)


if __name__ == '__main__':
    MempoolOrphanSubmissionTest().main()
