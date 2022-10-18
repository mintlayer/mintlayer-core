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

    def assert_tip(self, n, expected):
        tip = self.nodes[n].chainstate_best_block_id()
        block = self.nodes[n].chainstate_get_block(tip)
        assert_equal(block, expected)

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
            "018f9fbc068a91adf8fe157c600578ad50a6183651c698eb7a8e26b7e39345a9ce9aea86456bae82fc69862d2f7126abb9a770bac68868a256aa798f11bebf781a30e433af939e548e3178c836942aac794c78772a1f81bd0fc2556d90ad16e2190356764e6301ffff7f20020000000000000000000000000000000004010000000004018f9fbc068a91adf8fe157c600578ad50a6183651c698eb7a8e26b7e39345a9ce00000000040013966675fc4ce5371e0003000000000400018d011224051c024e071d1f52260c515943132f2d4f44323b0e3839275a1118372e4b2b190a4c3d10160f2a225b5833490436574d411e6121093c1b5f284a63402350353a031a0d205e25315c154208060153145d295455463f601756302c6248340b3e4547",
            "018c4f93e4407e0b32bc23a89ffe47ba5d97f7c6553fc1df5c91daaebef8369c4134e818e3af6e73bef8c4dc8ac2d8bf5670ab564e6adf8ccaf20d0fe9a2b3a5fdb1ae0f53bcb1f52714cae5662682b99b66604ac02400fcd892fb101eef1392ef0356764e6301ffff7f2000000000000000000000000000000000000401000000000400a641be660b6ad40111e18553b1027a7024fc4c8de223781f3ec08e6d4a4ade120000000004001344f6109a9a1b241e0003000000000400018d014c5f603b4f481f463023494056416212512f3a035e575a5c1422332d394d1159371b1c282a040d19083c24204a44273f0c5038133d2c0e1d2e065b150f17253534432921361a014232315547184e5d1e103e070a5453610b4b16580252632b26050945",
            "014e5e15b33cc9f21bdd3a75f2f5bd9d61de0ecc44667cfb6ea21e4bd31511815afd1ad662014a9392694abd810d657485a5ea39764e7338d146a1d94efdc0d1ee34e90efcb434e7b72344a1ed6e3a55fb54d7776ff1a71d781edc16805c6ce0fa0356764e6301ffff7f2000000000000000000000000000000000000401000000000400a96419b1c368d7cac11af7a715c429392d7bb50fa74f6b83a27a0b98e72000eb000000000400134853d99b34adee0c0003000000000400018d01073b1b525d1e3126553e091c4f3a1119305f39285e3d5b403f21322e295404344459382a481553615a1f234e4562570e08184b2712015c0d1a25370c064d0a1722052c2f133649030b583c474a462b5020102d16352451435641021d140f6063334c42",
            "01520ff476cf58cabe81a0e025987bbb3b343b8e0de105365dcc125eb03949216050ac30d1ba218540092cb2cf2e0e593ac9b4ee34e7ebfbbd75fa0b55ad45f8f714d85901d2d98c81f8a3d0edc331662fad8a2da1bce847bf769389408eb7c7b40356764e6301ffff7f2000000000000000000000000000000000000401000000000400e4c987d265e75da4f2af118b1a6983db98875c9fba0d94e8380e67d77624547600000000040013ce30c5c212b29a010003000000000400018d010f191f60221c4d4b1b3f2b353a231202313b334c0a062f47461d2a420556385f26032d271e2e4f613e135c52533d320b01161115432c040e183c14545a3037170944391a342951364e5562216308415b2057100c495d454a480d255028075859245e40",
            "0170bb8f03e32cfa59890217bc8986f07be4899585f1d7d7dd187a533c16aa06465ec81dce6b3ff56ecf89bb2299a3cc1db4679ce3889a788706585bbcb001b82123b19469cfd3fdf574176e557e02be7450a6e1e0ae47ade0e31eafa6723392c50356764e6301ffff7f20000000000000000000000000000000000004010000000004004e06535bd476b0ffa744b9043f8c50bbb333c45181bd6f427a5f54cdc99e35e600000000040013c3a04b328e2d46010003000000000400018d011801464d39100b4c562d2e1b3e2532550427364b09342957540f13123f62054f0a5108141e533c5e1a16412058173711035243494e5a2324153a02482c2842191d382a21502b63591c353047450e2f311f5b33070c5d5c065f3b0d22604a40263d4461",
        ]
        
        # add first block
        self.nodes[0].chainstate_submit_block(blocks[0])
        assert_equal(self.block_height(0), 1)
        assert_equal(self.block_height(1), 0)
        self.assert_tip(0, blocks[0])

        # add second block
        self.nodes[0].chainstate_submit_block(blocks[1])
        assert_equal(self.block_height(0), 2)
        assert_equal(self.block_height(1), 0)
        self.assert_tip(0, blocks[1])

        # connect nodes
        self.connect_nodes(0, 1)
        self.sync_all(self.nodes[0:2])

        node0_tip = self.nodes[0].chainstate_best_block_id()
        node1_tip = self.nodes[1].chainstate_best_block_id()
        assert_equal(node0_tip, node1_tip)

        # node0 hasn't downloaded any blocks but node1 has two new blocks
        assert_equal(self.block_height(0), 2)
        assert_equal(self.block_height(1), 2)

        self.assert_tip(0, blocks[1])
        self.assert_tip(1, blocks[1])

        # submit third block
        self.nodes[0].chainstate_submit_block(blocks[2])
        assert_equal(self.block_height(0), 3)
        self.assert_tip(0, blocks[2])

        # submit final block
        self.nodes[0].chainstate_submit_block(blocks[3])
        assert_equal(self.block_height(0), 4)
        self.assert_tip(0, blocks[3])

        # verify that they are in sync
        self.sync_all(self.nodes[0:2])
        node0_tip = self.nodes[0].chainstate_best_block_id()
        node1_tip = self.nodes[1].chainstate_best_block_id()
        assert_equal(node0_tip, node1_tip)
        assert_equal(self.block_height(0), 4)
        assert_equal(self.block_height(1), 4)
        self.assert_tip(1, blocks[3])

if __name__ == '__main__':
    ExampleTest().main()
