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
"""Mempool transaction submission test

Check that:
* Valid transaction is accepted by the mempool and included in a block as
  appropriate.
* Invalid transaction gets properly rejected at mempool level.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (assert_raises_rpc_error)
from test_framework.mintlayer import mintlayer_hash
import scalecodec

class MempoolTxSubmissionTest(BitcoinTestFramework):

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
        tip_id = node.chainstate_best_block_id()
        self.log.debug('Tip: {}'.format(tip_id))

        signed_tx_obj = scalecodec.base.RuntimeConfiguration().create_scale_object('SignedTransaction')
        base_tx_obj = scalecodec.base.RuntimeConfiguration().create_scale_object('TransactionV1')

        # Try to submit an invalid transaction

        tx = {
            'version': 1,
            'flags': 0,
            'inputs': [],
            'outputs': [],
        }
        signed_tx = {
            'transaction': tx,
            'signatures': [],
        }
        # TODO: Use helpers for encoding (https://github.com/mintlayer/mintlayer-core/issues/849).
        encoded_tx = signed_tx_obj.encode(signed_tx).to_hex()[2:]
        tx_id = scalecodec.ScaleBytes(mintlayer_hash(base_tx_obj.encode(tx).data)).to_hex()[2:]
        self.log.debug("Encoded transaction {}: {}".format(tx_id, encoded_tx))

        assert_raises_rpc_error(None, "Transaction has no inputs", node.mempool_submit_transaction, encoded_tx, {})
        assert not node.mempool_contains_tx(tx_id)

        # Submit a valid transaction

        input = { 'Utxo': {
                'id': { 'BlockReward': '0x{}'.format(tip_id) },
                'index': 0,
            }
        }
        output = {
            'Transfer': [ { 'Coin': 1_000_000 }, { 'AnyoneCanSpend': None } ],
        }
        witness = { 'NoSignature': None }
        tx = {
            'version': 1,
            'flags': 0,
            'inputs': [input],
            'outputs': [output],
        }
        signed_tx = {
            'transaction': tx,
            'signatures': [witness],
        }
        encoded_tx = signed_tx_obj.encode(signed_tx).to_hex()[2:]
        tx_id = scalecodec.ScaleBytes(mintlayer_hash(base_tx_obj.encode(tx).data)).to_hex()[2:]
        self.log.debug("Encoded transaction {}: {}".format(tx_id, encoded_tx))

        node.mempool_submit_transaction(encoded_tx, {})
        assert node.mempool_contains_tx(tx_id)


if __name__ == '__main__':
    MempoolTxSubmissionTest().main()
