#!/usr/bin/env python3
#  Copyright (c) 2017-2021 The Bitcoin Core developers
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
"""Mempool orphan submission test

Check that:
* After submitting a transaction with a missing input UTXO, it ends up in the orphan pool
* After submitting a transaction that defines the UTXO, both are in non-orphan mempool
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import (make_tx, reward_input, tx_input)
import scalecodec

class MempoolOrphanSubmissionTest(BitcoinTestFramework):

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

        # Submit the dependent transaction first, check it is in orphan pool
        node.mempool_submit_transaction(tx2)
        assert not node.mempool_contains_tx(tx2_id)
        assert node.mempool_contains_orphan_tx(tx2_id)

        # Submit the first transaction, resolving the sequence
        node.mempool_submit_transaction(tx1)
        assert node.mempool_contains_tx(tx1_id)
        assert node.mempool_contains_tx(tx2_id)
        assert not node.mempool_contains_orphan_tx(tx1_id)
        assert not node.mempool_contains_orphan_tx(tx2_id)


if __name__ == '__main__':
    MempoolOrphanSubmissionTest().main()
