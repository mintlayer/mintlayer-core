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

from scalecodec.base import ScaleBytes, ScaleDecoder
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mintlayer import *

class GenerateBlocksFromAllSourcesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            "--blockprod-min-peers-to-produce-blocks=0",
        ]]

    def assert_transaction_in_block(self, expected_transaction, block):
        (expected_txid, expected_index) = expected_transaction

        for generated_transaction in block["body"]["transactions"]:
            for input in generated_transaction["transaction"]["inputs"]:
                if expected_txid == input["Utxo"]["id"]["Transaction"][2:] and expected_index == input["Utxo"]["index"]:
                    return True

        return False

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
            [1000 for _ in range(20)],
        )

        block = node.blockprod_generate_block(block_input_data, [generate_utxos], [], "LeaveEmptySpace")
        node.chainstate_submit_block(block)
        utxos = [(utxo_id, i) for i in range(20)]

        for include_transaction in ([True, False]):
            for include_transaction_id in ([True, False]):
                for include_mempool in ([True, False]):
                    # Clear the mempool
                    self.stop_node(0)
                    self.start_node(0)

                    transactions = []
                    transaction_ids = []
                    expected_transactions = []
                    missing_transactions = []
                    mempool_transactions = []

                    #
                    # Populate the mempool
                    #

                    (utxo_id, utxo_index) = utxos.pop()
                    utxo = tx_input(utxo_id, utxo_index)
                    (tx, tx_id) = make_tx([utxo], [100])

                    node.mempool_submit_transaction(tx, {})

                    if include_mempool:
                        missing_transactions.append(tx_id)
                    else:
                        mempool_transactions.append(tx_id)

                    #
                    # Setup transactions parameter
                    #

                    if include_transaction:
                        (utxo_id, utxo_index) = utxos.pop()
                        utxo = tx_input(utxo_id, utxo_index)
                        (tx, _) = make_tx([utxo], [100])
                        expected_transactions.append([utxo_id, utxo_index])

                        transactions.append(tx)

                    #
                    # Setup transaction Id parameter
                    #

                    if include_transaction_id:
                        (utxo_id, utxo_index) = utxos.pop()
                        utxo = tx_input(utxo_id, utxo_index)
                        (tx, tx_id) = make_tx([utxo], [100])

                        missing_transactions.append(tx_id)
                        node.mempool_submit_transaction(tx, {})
                        assert(node.mempool_contains_tx(tx_id))

                        transaction_ids.append(tx_id)
                        expected_transactions.append([utxo_id, utxo_index])

                    #
                    # Setup Mempool parameter
                    #

                    packing_strategy = "LeaveEmptySpace"

                    if include_mempool:
                        (utxo_id, utxo_index) = utxos.pop()
                        utxo = tx_input(utxo_id, utxo_index)
                        (tx, tx_id) = make_tx([utxo], [100])

                        missing_transactions.append(tx_id)
                        node.mempool_submit_transaction(tx, {})
                        assert(node.mempool_contains_tx(tx_id))

                        packing_strategy = "FillSpaceFromMempool"

                        expected_transactions.append([utxo_id, utxo_index])

                    self.wait_until(
                        lambda: node.mempool_local_best_block_id() == node.chainstate_best_block_id(),
                        timeout = 5
                    )

                    old_tip = node.chainstate_best_block_id()

                    block_hex = node.blockprod_generate_block(
                        block_input_data,
                        transactions,
                        transaction_ids,
                        packing_strategy
                    )

                    block = ScaleDecoder.get_decoder_class('BlockV1', ScaleBytes(bytearray.fromhex(block_hex))).decode()

                    for expected_transaction in expected_transactions:
                        self.assert_transaction_in_block(expected_transaction, block)

                    node.chainstate_submit_block(block_hex)
                    new_tip = node.chainstate_best_block_id()
                    assert(old_tip != new_tip)

                    self.wait_until(
                        lambda: node.mempool_local_best_block_id() == node.chainstate_best_block_id(),
                        timeout = 5
                    )

                    #
                    # Check chainstate and mempool is as expected
                    #

                    new_block_hex = node.chainstate_get_block(new_tip)
                    new_block = ScaleDecoder.get_decoder_class('BlockV1', ScaleBytes(bytearray.fromhex(new_block_hex))).decode()

                    for expected_transaction in expected_transactions:
                        self.assert_transaction_in_block(expected_transaction, new_block)

                    for missing_transaction in missing_transactions:
                        assert(not node.mempool_contains_tx(missing_transaction))

                    for mempool_transaction in mempool_transactions:
                        assert(node.mempool_contains_tx(mempool_transaction))

if __name__ == '__main__':
    GenerateBlocksFromAllSourcesTest().main()
