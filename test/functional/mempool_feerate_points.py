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
"""Mempool feerate points test

Check that:
* Can get the feerate points on empty mempool will return the min feerate
* With some transactions in the mempool will return multiple points up to 10
"""

from typing import List
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (assert_equal, assert_raises_rpc_error)
from test_framework.mintlayer import (block_input_data_obj, make_tx , reward_input, tx_input, tx_output)

import random

def generate_points(first, last, n) -> List[int]:
    if first == last:
        return [first]

    points = [first]

    for i in range(1, n - 1):
        points.append(first + (last - first) * i // (n - 1))

    points.append(last)

    return points

def interpolate_value(dictionary, key):
    if key in dictionary:
        # If the key is present, return the corresponding value
        return dictionary[key]
    else:
        # If the key is not present, find the keys immediately below and above it
        keys_below = [k for k in dictionary.keys() if k < key]
        keys_above = [k for k in dictionary.keys() if k > key]

        # Find the nearest keys below and above
        k1 = max(keys_below) if keys_below else None
        k2 = min(keys_above) if keys_above else None

        # If both keys are found, perform linear interpolation
        if k1 is not None and k2 is not None:
            v1 = dictionary[k1]
            v2 = dictionary[k2]

            # Calculate linearly interpolated value

            scaled_v1 = v1 * (k2 - key);
            scaled_v2 = v2 * (key - k1);
            total_scale = k2 - k1;

            return (scaled_v1 + scaled_v2) // total_scale;

        # If no nearby keys are found, return None
        return None

class MempoolFeeratePointsTest(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            "--blockprod-min-peers-to-produce-blocks=0",
        ]]

    def setup_network(self):
        self.setup_nodes()
        self.sync_all(self.nodes[0:1])

    def generate_block(self):
        node = self.nodes[0]

        block_input_data = { "PoW": { "reward_destination": "AnyoneCanSpend" } }
        block_input_data = block_input_data_obj.encode(block_input_data).to_hex()[2:]

        # create a new block, taking transactions from mempool
        block = node.blockprod_generate_block(block_input_data, [], [], "FillSpaceFromMempool")
        node.chainstate_submit_block(block)
        block_id = node.chainstate_best_block_id()

        # Wait for mempool to sync
        self.wait_until(lambda: node.mempool_local_best_block_id() == block_id, timeout = 5)

        return block_id

    def run_test(self):
        node = self.nodes[0]

        # Get chain tip
        tip_id = node.chainstate_best_block_id()
        self.log.debug('Tip: {}'.format(tip_id))

        feerate_points = node.mempool_get_fee_rate_points()
        self.log.info(f"out: {feerate_points}")
        assert_equal(len(feerate_points), 1)
        lowest_feerate = feerate_points[0][1]
        expected_lowest_feerate = 1000
        assert_equal(lowest_feerate['amount_per_kb']['fixed_point_integer'], expected_lowest_feerate)

        out_amount = 100_000_000_000
        output = tx_output(out_amount)
        encoded_tx, tx_id = make_tx([reward_input(tip_id)], [output] * 90, 0)
        self.log.debug("Encoded transaction {}: {}".format(tx_id, encoded_tx))

        node.mempool_submit_transaction(encoded_tx, {})
        assert node.mempool_contains_tx(tx_id)

        self.generate_block()

        feerates = {}
        accumulated_size = 0
        first = None
        tx_size = 0
        for i in reversed(range(random.randint(1, 80))):
            to_transfer = 99999999800 - (i * 100)
            output = tx_output(to_transfer)
            encoded_tx, _ = make_tx([tx_input(tx_id, i)], [output], 0)
            node.mempool_submit_transaction(encoded_tx, {})

            tx_size = len(encoded_tx) // 2
            feerate = 1000 * (out_amount - to_transfer) // tx_size
            accumulated_size = accumulated_size + tx_size
            feerates[accumulated_size] = feerate
            if first is None:
                first = accumulated_size

        accumulated_size = accumulated_size + 1
        feerates[accumulated_size] = expected_lowest_feerate
        last = accumulated_size

        if len(feerates) > 10:
            points = generate_points(first, last, 10)
        else:
            points = sorted([size for size in feerates])

        feerate_points = node.mempool_get_fee_rate_points()
        self.log.info(f"out: {feerate_points}")
        self.log.info(f"out: {feerates}")

        for (i, expected_point, (point, feerate)) in zip(range(10), points, feerate_points):
            expected_feerate = interpolate_value(feerates, point)
            assert expected_feerate is not None
            self.log.info(f"{expected_point} {expected_feerate} {point} {feerate}")
            assert_equal(expected_point, point)
            assert_equal(expected_feerate, feerate['amount_per_kb']['fixed_point_integer'])


if __name__ == '__main__':
    MempoolFeeratePointsTest().main()

