#!/usr/bin/env python3
# Copyright (c) 2017-2021 The Bitcoin Core developers
# Copyright (c) 2022 RBB S.r.l
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)

class ExampleTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [[], []]

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)
        self.sync_all(self.nodes[0:2])

    def block_height(self, n):
        tip = self.nodes[n].chainstate_best_block_id()
        return self.nodes[n].chainstate_block_height_in_main_chain(tip)

    def run_test(self):
        # get current tip hash
        node0_tip = self.nodes[0].chainstate_best_block_id()
        node1_tip = self.nodes[1].chainstate_best_block_id()
        assert_equal(node0_tip, node1_tip)
        assert_equal(self.block_height(0), 0)
        assert_equal(self.block_height(1), 0)

        # disconnect nodes
        self.disconnect_nodes(0, 1)

        blocks = [
            "0175e9cc345b1daf683bc4f77577c886aa8ed694942f6be04bae94b993855e455a5c16c1c8b6dcaa32bda0fdf919f4473459e6390c5c2524b0dd074f5b88d0a162ed6f9ad8d11e76886401e70f38b758fa2a97e9ea2ed536931f749c82756f4446031622ee6201ffff7f200000000000000000000000000000000000040100000000040175e9cc345b1daf683bc4f77577c886aa8ed694942f6be04bae94b993855e455a0000000000018d0145192d504f5a1e40382c6126375b0252564d423c4e573935111a0c5d0f1c332331292108163b4a044c22470a36032f27531732140d250e1051133d46051512345543632a072e3e5c301f016209483f0b592018445f5e4128241b2b541d586006494b3a04000b67d33d841640000300000000",
            "01f0858820221a47062a84125ca10fd834cdbf30c4d9d499a6b5bfbeb269ddd953b9eb2ed8bedc0a8d7f011d8f15a58d5b9067b94c5049aab041b4614838292027961b1b3652d39d2dfbeae4b1846c417309a6dfbab927b542c49be3e90ed657c5031622ee6201ffff7f2000000000000000000000000000000000000401000000000400b86c9d8b691b96c59675f060d8f67cba61dfee31e0b5f0ad49d4c870972885770000000000018d01475c104105581256082944223352382120303c4328145e1a3d073e2e2a06022f4d4c1e17462b1c3f34552523622d4a19363b270d04033a1f0c614e2650375a490e5b59545f635348394b0a51155d1d165740091b45426013310f350b3218014f242c1104000bdaa3c1a2b03b000300000000",
            "019e8e9396701ffa76fb551b77add4167c9a39aaa8cafbc771073568fd9e6fb77d3fc8896386545eaf8d5213786081ef3195f9b1bae1a8dfe49d8cdf6f42d615d8a1aab6a5cd3b6d38cc1e79f642ca2a0ddb97e7c5147c3129f1fd656e705dcaac031622ee6201ffff7f2000000000000000000000000000000000000401000000000400c5ca76c83669058f0d436d9197f2ac6ce85ca169c536e0db0304e32fc83d3cb30000000000018d01450c4132273a360d61154d563d352049525c2c4a2f284b37215e1863220a6005401e0b3f125303594c170602341c42143c196248512e1a4e55442a5d38505b261d105f46300e29165a2523581b3b543107132d082b0f1157331f3e0924014f0439474304000b84ea560cae26000300000000",
            "01bf8b501a910116e6fc6224b66ea83cf490bb77a61f87cd53d139bcab7ce81c2ef3ea024ecfa8a6e5996e014704b8ab5ea6c6a9b381b3c70ad98ca5a5e4b8f5835ddfaba84a6efe04723be5673aad94ae19b1eb4e9adbaa9b7836e56f3b80beb6031622ee6201ffff7f200000000000000000000000000000000000040100000000040007c9f5364792e1c6d5182b4d8d7139e3cd19744352354cb795bf15d3f204ca440000000000018d0145555626330b533d315936383a5e145205401b1c482e1e5a010f41034b2a37395f061a091f62233c2b574c3f0d4e0e5b634313443b0208193027162c422447584a11045c0a1d602015104f2d2f5029225d07492112610c511732353454464d3e25182804000b4fa0c8c7031c000300000000",
            "01d5ad37373c8a218f0e3b239b421430f3eac72f178ea6e49e7639493c26605d5b68a4c8ec541ab1a2de4707fa344e20d922ea65987d733cb021d3e87a4950b289188e4e2047740afaae73273aed0c62e2bd74fade4c3cd387d53da1aaa3e85c70031622ee6201ffff7f2000000000000000000000000000000000000401000000000400a7f6c274b8dc6c139860ee6dfe6b4228c4dcbfe013176fa2e04deb222cc1913b0000000000018d0144311c2b2d11260e2a6219564d424e5b3758103d2034592c530c15141329033c22230b0f1f185f3e2f40612e07351b124139575155241e28383f5c0145215a0d174930544f33064c3b4763021d27523a08045d4632430509164a361a0a254b48505e6004000bac9c16622d14000300000000",
        ]
        
        # add first block
        self.nodes[0].chainstate_submit_block(blocks[0])
        assert_equal(self.block_height(0), 1)
        assert_equal(self.block_height(1), 0)
        # TODO check that tip is blocks[0]

        # add second block
        self.nodes[0].chainstate_submit_block(blocks[1])
        assert_equal(self.block_height(0), 2)
        assert_equal(self.block_height(1), 0)
        # TODO check that tip is blocks[1]

        # connect nodes
        self.connect_nodes(0, 1)
        self.sync_all(self.nodes[0:2])

        node0_tip = self.nodes[0].chainstate_best_block_id()
        node1_tip = self.nodes[1].chainstate_best_block_id()
        assert_equal(node0_tip, node1_tip)

        # node0 hasn't downloaded any blocks but node1 has two new blocks
        assert_equal(self.block_height(0), 2)
        assert_equal(self.block_height(1), 2)

        # submit third block
        self.nodes[0].chainstate_submit_block(blocks[2])
        assert_equal(self.block_height(0), 3)
        # TODO check that tip is blocks[2]

        # submit final block
        self.nodes[0].chainstate_submit_block(blocks[3])
        assert_equal(self.block_height(0), 4)
        # TODO check that tip is blocks[3]

        # verify that they are in sync
        self.sync_all(self.nodes[0:2])
        node0_tip = self.nodes[0].chainstate_best_block_id()
        node1_tip = self.nodes[1].chainstate_best_block_id()
        assert_equal(node0_tip, node1_tip)
        assert_equal(self.block_height(0), 4)
        assert_equal(self.block_height(1), 4)

if __name__ == '__main__':
    ExampleTest().main()
