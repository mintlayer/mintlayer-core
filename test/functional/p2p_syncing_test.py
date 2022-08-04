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
            "0175e9cc345b1daf683bc4f77577c886aa8ed694942f6be04bae94b993855e455a01d29a0492ddc3a0d6213b5f8edd23dbf395f95592f28f0e13bc5a7fdc81b25eda01dd7c1ea59676e07e1dbbafb6576c17f0af8aeefcb7e629e47623be8deeb4734803b062e26201ffff7f200000000000000000000000000000000000040100000000040175e9cc345b1daf683bc4f77577c886aa8ed694942f6be04bae94b993855e455a0000000000018d01134e214d5511171409271c59584b43420c294156202f1f4f313f28360a1847573d3315385e1b2b370e0d4534631d3050465c031a486153104a2c07250f4c0439495a02243a3b06405b08511e5223442a353c5d2e3e5f1232056226190154220b162d6004000bf7153eddfe32000300000000",
            "0162753f54ae7cecab23ebca990b86002f5195aacb5f9783d3cf309d60031ab15201a2bbb61d96283fbbffc57f3e2e4ea67333b49311ea8b0438fe3277028e4aa4b2019d7a08074d66573e6aa9b553535e09e686e570e10adc8b01ff0e66b7abeeccda03b062e26201ffff7f2001000000000000000000000000000000000401000000000400d29a0492ddc3a0d6213b5f8edd23dbf395f95592f28f0e13bc5a7fdc81b25eda0000000000018d013c21245d42350e3e591b1e4728552f1c16301f57480738330c360d5e2d5c0f3a5023631a4d091346014910442b604e3f41121d2a3403055b2e4b580b3162560814522018063b2c26401754435f610a4f3937273211455a2219024a3d4c51530429152504000b7c7f09048e11000300000000",
            "010c2b3d2e72bdcd6d26faf9a55ecabb206c5db49d33d84faaef568278aecb1f6001a1c072f1e6ff9e63ff8cdf3e38c7e031eca3c03579057fc9d4dff4f509ae9c870118ee05c68f92ce966dabf2d6877b4fdfbfbebf979dd3a64adf199449e437248003b062e26201ffff7f2002000000000000000000000000000000000401000000000400a2bbb61d96283fbbffc57f3e2e4ea67333b49311ea8b0438fe3277028e4aa4b20000000000018d0117204f48415338085d43552f572737620a052a191b1839352b452833265112146121525e1f232e034b5a594a44491a4e364d503b3246403a2c313e1d2416063c42301e5c0e582d633404600c5b4c1c15220d0b56294701070f5f02251354093f3d111004000bdf4372aa6f0b000300000000",
            "01762af8ce1c27f67311879a4bef0a6f75af99ced51a3a45d5eeb31cb3c075d17b01abc1662c4ef14a5c9bc57c42f9d2e70788e1b03745aab8530c27211588133c250120180a4e6eac35d0c3043084639cac43efdb610ca4d4d179a915992af7ff9d6603b062e26201ffff7f2000000000000000000000000000000000000401000000000400a1c072f1e6ff9e63ff8cdf3e38c7e031eca3c03579057fc9d4dff4f509ae9c870000000000018d012c06162231250741374b193e533959575f0e3d303f2951561a0f140c346345334c5b0d3860580415181b351144540517423a40260150461f132d4d0b622a0803555e2b61522f3b3c4947270a481d20104a3224095d5a4f022e21121c2843231e5c4e3604000bd62c0a555a0b000300000000",
            "018fab8776c8e260214be75d80ebf4e10b66c819b7b2812c8a633e01721f33804b01dcb590c3f8e64224f23f186d51d3820f02817fe863fa78cf070ad7c68787807c0128606394ee640df534d9dbfb4cde367bc2407e55184af22d0ae69f624677f74603b062e26201ffff7f2001000000000000000000000000000000000401000000000400abc1662c4ef14a5c9bc57c42f9d2e70788e1b03745aab8530c27211588133c250000000000018d0123243a5a525f0a4a30155040252e493e4b4233040e5b451a5536354c472d5c624838061d3f391e262b1c072a4f27132f341b16014e113d0920376051124105280b21432c4d2932313c08035e545d3b19146359571018220d170f1f5661580c4653024404000b7fdf8755ab02000300000000"        
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
