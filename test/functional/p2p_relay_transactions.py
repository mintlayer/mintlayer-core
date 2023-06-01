#!/usr/bin/env python3
# Copyright (c) 2017-2021 The Bitcoin Core developers
# Copyright (c) 2022 RBB S.r.l
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework import mintlayer_hash
from test_framework.util import assert_raises_rpc_error
from test_framework.test_framework import BitcoinTestFramework
import scalecodec
import time

class RelayTransactions(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)
        self.sync_all(self.nodes[0:2])

    def assert_mempool_contains_tx(self, n, tx_id):
        for _ in range(5):
            if self.nodes[n].mempool_contains_tx(tx_id):
                break
            time.sleep(1)
        assert self.nodes[n].mempool_contains_tx(tx_id)

    def run_test(self):
        signed_tx_obj = scalecodec.base.RuntimeConfiguration().create_scale_object('SignedTransaction')
        base_tx_obj = scalecodec.base.RuntimeConfiguration().create_scale_object('TransactionV1')

        # Try to submit an invalid transaction.
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

        assert_raises_rpc_error(None, "Transaction has no inputs", self.nodes[0].p2p_submit_transaction, encoded_tx)
        assert not self.nodes[0].mempool_contains_tx(tx_id)
        assert not self.nodes[1].mempool_contains_tx(tx_id)

        # Submit a valid transaction.
        genesis = self.nodes[0].chainstate_block_id_at_height(0)
        input = { 'Utxo': {
                'id': { 'BlockReward': '0x{}'.format(genesis) },
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

        self.nodes[0].p2p_submit_transaction(encoded_tx)
        assert self.nodes[0].mempool_contains_tx(tx_id)
        self.assert_mempool_contains_tx(1, tx_id)


if __name__ == '__main__':
    RelayTransactions().main()
