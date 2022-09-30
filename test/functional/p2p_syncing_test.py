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
            "0175e9cc345b1daf683bc4f77577c886aa8ed694942f6be04bae94b993855e455af436c5217d8d6597c7f2663d961d9f40b5c3787cfecec006af46cc1a9d3eab060afaf2f97b922d931d1f118f2b65c70af46c678cc436a59a838ba6db1e82a439030f91366301ffff7f200200000000000000000000000000000000040100000000040175e9cc345b1daf683bc4f77577c886aa8ed694942f6be04bae94b993855e455a0000000004000b32d99607eb470003000000000400018d0110593058383622422a084f4b0d0e5a29130c63523f4409152c532f181e505c0b48454c062651055d27411d3e11432d3a54021b0a2e345621460f204037323d195b5e33571a3b60314d493c4e240712231c47170155395f2b1425621f61040335284a16",
            "0130f6ac897ec5ca4d3b650889cc864f7cfbabaa95cc7fa6a7e6020dd8c354136b41432e426c4b40da8fcf3679ebc9e7c75f270ab59cdfa7a0941f0d0e8b78fb2d1ef66e3c3d1f77d91d2666f5b1b8a7bd65eba999f2fcae76e02b7a0219d29304031391366301ffff7f20000000000000000000000000000000000004010000000004004c936eb511f987d23e25a1d2b382c55a9c9506c4ee382cdc51e1ca7217202baf0000000004000b71749b4352220003000000000400018d011d1058563b0b603c080e075b40265c450f501332293039385518624b145d332d241b162c200c020d5937472a44481f492f5212531a0321094a43612711350563173454255f313f0141574d42511e064e3d2e040a233a194c365e462b15284f1c5a223e",
            "019c86044314bcbf65f218c6f0887bf8e142ad1f0027ad38d0a6f856c65e58c0157f1bb5418c5b22f5e2974eadc745ff6dfbb9c561b7579fe32cbe14438f29d00048d67753661d2148803a64deab584e42f9ba0e89868b295d6d6ca800835b91e1031391366301ffff7f2002000000000000000000000000000000000401000000000400768d10cd8446e7be553fe7ab0517980f042c81dde910811d52fccf94deca0be30000000004000bb4c737bba6190003000000000400018d013b32400c48600355015b57155e4b3a0923362d5d4c0d1d300f253537170e463158242044612905113f07433d2645223e133354621402285956101f5f1b4d212b413952382f53275c04081812511e4f501c472e0b1a16060a6342343c5a4a192a2c494e",
            "01539292865e5784d9410933b38a206aac299556cf244aa802e2c2526ccdebd408024fc0daf4e0cad596ae92ee126547ba612956e8532edf3f0ff91068f7f3ff241663a7a9b90c67abcedd12df394ea4900039ef87b76d4617626e1f1325e24053031391366301ffff7f2001000000000000000000000000000000000401000000000400953bf6ba40b3e9bc600a5eb42472c883c1e48fc11e721471a948de580b165e960000000004000bdfde2507f6170003000000000400018d01570e3d5f3a4c1c100b354d14045822635012441b3317431e39454f491f2a60213401193f4623472d423b272f4a5a055c54403e380320624e2629065e2e3c555152591a0f5b37411531481d2509302c0c0a11612407532808132b4b02360d325616185d",
            "01b02e63a4a8ab958125fcd41e8a6e326c49dcfea387cda8212d79f32537d3036abb14968e23d301cbc5792ea49762e6241287185cfa4cc224700f78e0cc0230d0c7f8e6f882f62c91706d4827b2e8746f99591dfa4492bfd1609d16e793e8af9a031391366301ffff7f20000000000000000000000000000000000004010000000004004ed9e281e0e79d7dbd6be81093fdad09397aff197695669a2b733d76490929170000000004000bd1b77f19c4050003000000000400018d01334a3c0818541f490c413a254f4813243f5259583b4d2d1a31211c26015e27052b4b534261565f1707291d3611600d1b1204234e4c5a452214282e0e5b3540373d390a093850573062631e475c0f2c2f205d2a1955060b1532164310035102463e3444"     
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
