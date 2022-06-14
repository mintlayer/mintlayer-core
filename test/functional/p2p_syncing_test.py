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
            "010160a60f80e4de9f5f2af95d29513d1d4301a4d94ca2800d9aea6045b64f7fd4e001f8859a60b18bf33b452413dfa9429d8c0e72d8f05e03a3a04f4030f8045f6aa301325220e4ba4b325714af6eef1ca4f22bd327f9d93ff624b7c7ad8bde9722ca9b03d9e7a96201ffff7f200000000000000000000000000000000000040100000000040088313f5915344ce829dd1a08f279d7f0bb038efa5e9b3eeb70fc0e4232a60d9f0000000000018d0126384d4608104e3e18043c5c05535e3702392f5b4f30111d146052452319493a16014b40170f2257033f612e4841331a440e0c135a622721551c31096334203d5d072b12471b560b06580a323b0d2a544c50295135361e24252d28151f424a2c59435f040b9c83899abc030300000000",
            "0101c4ae6926638ace91f1cc4125aca001507b3501913b48157ed0081dfd8252a96e018833674980208d27fe0b1bccbc58f7c9ef19f45c21d37310abaa98c2ae7183fe012cca890515ff27aa4b9f09c361ec115bc1741c81f7fb90e57f629749d0fb5ace03d9e7a96201ffff7f2000000000000000000000000000000000000401000000000400f8859a60b18bf33b452413dfa9429d8c0e72d8f05e03a3a04f4030f8045f6aa30000000000018d01425e2f4d231b3d090a513436084f0e465c33100f0b49552711041c1e3c3203281922155a2a47315244633741143a61433b131f48252e4c624054120559300c265b07563f0d025d162101204e3950356006581a182b454a244b1753295f571d2d2c383e040bb0ee4c2465030300000000",
            "0101fc8a745a41011c3b6d9a46e3810d48a3e3b300ca3b6932534a7b7ae558dd407301295de93ec520cdf89d99da18912cb5f248ed38af87eca5bb16cc21520623440d01a5741f685a23cec57744eaf6628183b71ef612aa6812069cf65d7a5cf321cf3b03d9e7a96201ffff7f20000000000000000000000000000000000004010000000004008833674980208d27fe0b1bccbc58f7c9ef19f45c21d37310abaa98c2ae7183fe0000000000018d013c5a474c190b40091e273e14134a5f3f08234f34425d3b3138372c062f4b3d171f53024d250c5210551d62330a2651206018112a542407295e36462e285b16390f3256452d61482244591b414e576330041a49585c4301122b21350550030d153a0e1c0407cda3aa51240300000000",
            "01016d1412a92d8a3813eae169cebb51269b8ea0a954dc09ff1bdf5288184b6c050f01c69e9afa50e821eb92b55afe5fd8e8258f5df1eb6e0c9258fec04e1e521559e601d3480f4b0629f474b35c429aeb8e1fa9bde22f19c40b056f8dc7ed0cf04cda8c03d9e7a96201ffff7f2000000000000000000000000000000000000401000000000400295de93ec520cdf89d99da18912cb5f248ed38af87eca5bb16cc21520623440d0000000000018d011a212c150d4d5a53403f411045144b37430f0b485c6222161e5734501b084a526047550c3e273a3363364902245b322d0e29232f3c352a2e3b515e1154392558264c311813051f4f06420a5607175f011d442838034e19045912611c09465d202b303d040709b4a4a8080300000000"
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
