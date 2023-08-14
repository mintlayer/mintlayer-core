#!/usr/bin/env python3
"""Mempool reorg test

Check that:
* Transactions are collected into blocks when a new block is issued.
* Transactions are correctly put back into mempool when the block is reorged out.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import *

import time

class GenerateBlocksFromAllSourcesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            "--blockprod-min-peers-to-produce-blocks=0",
        ]]

    def run_test(self):
        node = self.nodes[0]

        block_input_data = block_input_data_obj.encode(
            {
                "PoW": {
                    "reward_destination": "AnyoneCanSpend",
                }
            }
        ).to_hex()[2:]

        (generate_utxos, utxo_id) = make_tx(
            [reward_input(node.chainstate_best_block_id())],
            [1000 for _ in range(12)],
        )

        block = node.blockprod_generate_block(block_input_data, [generate_utxos], [], False)
        node.chainstate_submit_block(block)
        utxos = [(utxo_id, i) for i in range(12)]

        for include_transaction in ([True, False]):
            for include_transaction_id in ([True, False]):
                for include_mempool in ([True, False]):
                    transactions = []
                    transaction_ids = []

                    if include_transaction:
                        (utxo_id, utxo_index) = utxos.pop()
                        utxo = tx_input(utxo_id, utxo_index)
                        (tx, _) = make_tx([utxo], [100])

                        transactions.append(tx)

                    if include_transaction_id:
                        (utxo_id, utxo_index) = utxos.pop()
                        utxo = tx_input(utxo_id, utxo_index)
                        (tx, tx_id) = make_tx([utxo], [100])

                        node.mempool_submit_transaction(tx)
                        transaction_ids.append(tx_id)

                    if include_mempool:
                        (utxo_id, utxo_index) = utxos.pop()
                        utxo = tx_input(utxo_id, utxo_index)
                        (tx, tx_id) = make_tx([utxo], [100])

                        node.mempool_submit_transaction(tx)

                    self.wait_until(
                        lambda: node.mempool_local_best_block_id() == node.chainstate_best_block_id(),
                        timeout = 5
                    )

                    block = node.blockprod_generate_block(block_input_data, transactions, transaction_ids, include_mempool)
                    node.chainstate_submit_block(block)

if __name__ == '__main__':
    GenerateBlocksFromAllSourcesTest().main()
