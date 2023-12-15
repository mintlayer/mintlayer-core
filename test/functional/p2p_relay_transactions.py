#!/usr/bin/env python3
#  Copyright (c) 2022 RBB S.r.l
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

from test_framework.mintlayer import mintlayer_hash
from test_framework.util import assert_raises_rpc_error
from test_framework.test_framework import BitcoinTestFramework
import scalecodec
import time

class RelayTransactions(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [
            ["--blockprod-min-peers-to-produce-blocks=0"],
            ["--blockprod-min-peers-to-produce-blocks=0"],
        ]

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)
        self.sync_all(self.nodes[0:2])

    def assert_mempool_contains_tx(self, n, tx_id):
        # there is random delay when relaying txs so we need to wait for a while
        for _ in range(60):
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

        assert_raises_rpc_error(None, "Transaction has no inputs", self.nodes[0].p2p_submit_transaction, encoded_tx, {})
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

        self.nodes[0].p2p_submit_transaction(encoded_tx, {})
        assert self.nodes[0].mempool_contains_tx(tx_id)
        self.assert_mempool_contains_tx(1, tx_id)


if __name__ == '__main__':
    RelayTransactions().main()
