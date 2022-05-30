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
            "01040152666ffa431cce31946d9fd25244646290bf096cae5ddcd1bd0960b46cdfe79d01e5672cc0f054a1e2cf993f22d777d340e7aa4e58165ad76623754e18403f0cb901b2c9f09e8c04e69e7a79acd9cf4c3c90fdddce4b5611f0e58aae9d3f2e87fec303cb998f6201ffff7f200000000000000000000000000000000000040100000000040088313f5915344ce829dd1a08f279d7f0bb038efa5e9b3eeb70fc0e4232a60d9f0000000000018d01475741105f451a194f5832032f2135594e6144204c066023423a2b0a073b111402552e363f1b260e52152d3428481d0456121c1737135a62304b63380508402709395e5024311f165b293e46494a222a540d0f530b013c2c25183d514d330c1e5c435d040bd333f9277f410300000000",
            "010401bd54a87b35c8b6de61a53ddc8bff7ebf1b42f05dedc41cde8988bebe2911397701e6ad1142d2c30f795458a5e2695e320be7fade4bbb20c064be0be590a292382901b0f1827ff73c3e0a6ea91af476b89067df638dc3ea05067127f829568275499803cb998f6201ffff7f2000000000000000000000000000000000000401000000000400e5672cc0f054a1e2cf993f22d777d340e7aa4e58165ad76623754e18403f0cb90000000000018d0157212a3d201954565f0b29272c0a3942360c2f153f351118591a5d33341f284a3108504b402b0f07020412455e3c625b47523b3e221346091b5816494d4f034453555a41434c100d38320517232e6025631d485c240e3a06142d4e30611c51011e3726040bd439118921350300000000",
            "01040132347e0016ed3308eb10a8751265ac19daba9b16733a1e280f1e0416c644c45301707742ad7b51f63bb241f4cd410730e6da50f0fbdbb8b7ceeb29996777c836cb01b8c70927b2f151cb3c65db88cee26db0389337d5b620c000d71a09477f71968103cb998f6201ffff7f2000000000000000000000000000000000000401000000000400e6ad1142d2c30f795458a5e2695e320be7fade4bbb20c064be0be590a29238290000000000018d01604b241f075d322f34042026575b1b274d4137431d475a0c5f154c180e13233c1e03611431361c2c335e0254553f3b0f0a49482d4e3a2a3851451716092b2e4f404663503e05190b563052105c4a440806255828013d3959531a62352142112912220d040b65efd2cb6d110300000000",
            "0104018e31fea064b63a60ab877ea78291e42b0c1317fb16eefbd2b9b673d6deb5171301ce56881b009ba213a7ecf315600366f126ccf5f6a8d6168c1c89b17caba2f75301109fe2b371452ba7092edbfdc12fb8708dd0df2e97761fee868c09f1decb30c103cb998f6201ffff7f2004000000000000000000000000000000000401000000000400707742ad7b51f63bb241f4cd410730e6da50f0fbdbb8b7ceeb29996777c836cb0000000000018d01174e63130b1c4f271f541e4631623730482b35033418065123073d2f3b5a243e361243020c4d321a1622604a203a5e011552475b381b111d262e3f2840095d61194159440d564b5f0f5045582139045725292c424953330a2d3c4c2a555c100514080e040b6ce88730ea040300000000",
            "010401a1b22556e351745689d0a24dce7c13f9ba5b9d09ed56a0d939117a04f7aa6b1d01ab0841549c1fba4345c9b219b0d8de30dbcf602be4aaa87c52ae48e6e532457801e0a83175c089a671d45b657b22c555034f2ceed61480f5684ee2da34b75066d703cb998f6201ffff7f2003000000000000000000000000000000000401000000000400ce56881b009ba213a7ecf315600366f126ccf5f6a8d6168c1c89b17caba2f7530000000000018d01560a194260515b3b33213735411e2838161c3a24105d1547065803445009572531324d4c225f3e0d2f2b5c631f12025e462d2740613029344a5936070e0f0b14111b4f5420451a0501233d132c43494e17551d0c5253083c5a3926483f2a6204184b2e040b2f23aeea58010300000000"
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
