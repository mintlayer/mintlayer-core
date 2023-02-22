#!/usr/bin/env python3
# Copyright (c) 2017-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Mempool transaction submission test

Check that:
* Valid transaciton is accepted by the mempool and included in a block as
  appropriate.
* Invalid transaction gets properly rejected at mempool level.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.authproxy import JSONRPCException
import test_framework
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
            'time_lock': 0,
        }
        signed_tx = {
            'transaction': tx,
            'signatures': [],
        }
        encoded_tx = signed_tx_obj.encode(signed_tx).to_hex()[2:]
        self.log.debug("Encoded transaction: {}".format(encoded_tx))

        try:
            node.p2p_submit_transaction(encoded_tx)
        except JSONRPCException as err:
            self.log.debug("Error message: {}".format(err))
            assert 'Transaction has no inputs' in str(err)
        else:
            raise AssertionError('Expected the tx submission to fail')

        # Submit a valid transaction

        input = {
            'id': { 'BlockReward': '0x{}'.format(tip_id) },
            'index': 0,
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
            'time_lock': 0,
        }
        signed_tx = {
            'transaction': tx,
            'signatures': [witness],
        }
        encoded_tx = signed_tx_obj.encode(signed_tx).to_hex()[2:]
        self.log.debug('Encoded transaction: {}'.format(encoded_tx))

        node.p2p_submit_transaction(encoded_tx)


if __name__ == '__main__':
    MempoolTxSubmissionTest().main()
