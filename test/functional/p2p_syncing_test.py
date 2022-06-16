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
            "0101139a3d05a89b43fb9caa30d244fe527622d073f4f1785ca51ee40516af0d7811017fea2a6b314979effd345564628bfa88b37b323789cd917661fd596a8dec311401d3577d46ce092b51b298bd154991ddef36391a04ce157e14db8df20ccadcb40003e4f5a96201ffff7f200000000000000000000000000000000000040100000000040088313f5915344ce829dd1a08f279d7f0bb038efa5e9b3eeb70fc0e4232a60d9f0000000000018d01313633012c421019093a4a544e21451e490b145e5b1d2a4c2d300c1a503e161c0e1324200d350256033b3243574f524d2308415d34554807515f1544285c294b2f53602604063f223d1f05472546393837405a1858590a612b122e1b631117623c270f040bc53d987cf1080300000000",
            "01017e8054048df1a69ca852a30513814c2076de9d39f00b59040b71d03dde5c8252019ca4dc8a09507da5301572c6dc104f715085228317e02ec0e743efcc22b1d22d01317be3e5a7561976c6c507a4ee9de796dd11f0dea5557bde9fa8bd76970e1d0d03e4f5a96201ffff7f20000000000000000000000000000000000004010000000004007fea2a6b314979effd345564628bfa88b37b323789cd917661fd596a8dec31140000000000018d01633e19522027576217410426423c12404e112c2d29614b151e3f0c39511c44302e1f4d43014a5c5821103d5b36280918370b38530314330650085a543545312a16343a5e2556484c231b1d0a47020d1a46221307323b0f5d05592b60494f5f242f550e040ba97449357f020300000000",
            "0101d47cc2b607973aea542c834971c1c1ec760efdd249f62f26624ffda1d298ec0501783e9c57b3aaef3ba10479f5c9c49a376b48a4c45e8448eb1b2f91cdf16747e501be8b4492d8da71f23c1df0f2420e52c79ce5f23ee289623a10ef75824021484103e4f5a96201ffff7f20010000000000000000000000000000000004010000000004009ca4dc8a09507da5301572c6dc104f715085228317e02ec0e743efcc22b1d22d0000000000018d014920354e3d05075e4d5b5d312827260a2a455c3a153701040650321b2c0e16173b554b543f4351522b293c121e4a24425f6057385a2f103e4f1d22400b470f6334141a212d1311564139464c1802610c4853591f365808336209441925302e030d231c040717b1a0cb090300000000",
            "010140c293d6b1e7a3a1c235410defc341711609adfdbfa8d1ec9e46255fa252eb78017cd76d4f48fd6374b173643e6d54858f497e8657118bbc16cc3a80421d0f70b8014582fb16f099a2800cb929a45c5262e80355a9459bff5b722356ad4a0deff34003e4f5a96201ffff7f2001000000000000000000000000000000000401000000000400783e9c57b3aaef3ba10479f5c9c49a376b48a4c45e8448eb1b2f91cdf16747e50000000000018d01201415030f1a010d2f113d1d09214b30394e432858413c3a471357504c2d63193e1c6045320c61564f23255c5d24464d1f0849181e36590b5331553f0444545f4a0a1033485e5a2c2e2b5140163b2a42341217520726025b623527371b220e05382906040707ba04dc080300000000"
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
