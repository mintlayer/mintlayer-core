#!/usr/bin/env python3
#  Copyright (c) 2025 RBB S.r.l
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
"""Tests that check certain things about the framework itself
"""


from test_framework.mintlayer import make_tx_dict, tx_input
from test_framework.test_framework import BitcoinTestFramework

import scalecodec


class FrameworkTests(BitcoinTestFramework):
    # Test network and test nodes are not required:

    def set_test_params(self):
        self.num_nodes = 0

    def setup_network(self):
        pass

    def run_test(self):
        self.test_ptx_encoding_roundtrip()

    def test_ptx_encoding_roundtrip(self):
        codec = scalecodec.base.RuntimeConfiguration().create_scale_object('PartiallySignedTransaction')

        tx_id_hex = "0011223344556677889900112233445566778899001122334455667788990011"
        tx = make_tx_dict([tx_input(tx_id_hex, 0), tx_input(tx_id_hex, 1)], [])
        ptx = {
            'tx': tx['transaction'],
            'witnesses': [None, None],
            'input_utxos': [None, None],
            'destinations': [None, None],
            'htlc_secrets': [None, None],
            'additional_info': {'pool_info': [], 'order_info': []}
        }
        encoded_ptx = codec.encode(ptx)

        decoded_ptx = codec.decode(encoded_ptx)
        assert(decoded_ptx == ptx)


if __name__ == '__main__':
    FrameworkTests().main()
