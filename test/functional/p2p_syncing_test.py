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
            "0175e9cc345b1daf683bc4f77577c886aa8ed694942f6be04bae94b993855e455a01cb17dcd28104f5e11f3c5e7a15604302fe75ae932c99cf1075db28d264c4921701716ba13dd82aff4675603fe7207c1e0efbca2ca9fb70522837ed387f7f120d1d032c70ea6201ffff7f200000000000000000000000000000000000040100000000040175e9cc345b1daf683bc4f77577c886aa8ed694942f6be04bae94b993855e455a0000000000018d015d5f51571f36033b544c3219453e224238123909585b0f43464a1005161e0b273a0d3c06352d29536163216026250c112e5a1b181a2030242a312c62415e0a3d154002491d0e47284b34593f4e04142b1c50562f174f130137084d5223485c3307554404000b38cfdf7cc528000300000000",
            "015fb0ad52170bda3c39b7db7d90f0510116bf13b89d55d4ba390e539e6e510767019ed1e1c5ee047960827ff2700a34995c0bbe757b39d763a3db448bf5908812a7016750b606508e8b7a003dc55ed2104dff53997e2963ebf36a5c139d72a5b8ed81032c70ea6201ffff7f2000000000000000000000000000000000000401000000000400cb17dcd28104f5e11f3c5e7a15604302fe75ae932c99cf1075db28d264c492170000000000018d011f42443f1a474f1d543a0b0e2f02390a285d3c182552244a5c5556572c2038433b2259133407612e235f4c4e12305b19165027171c320f26622a355e4629512b2d3645100403531b3d5a63154805112133064b09314160083e1e011440370d0c584d4904000ba96dee71dd1a000300000000",
            "01fd6271bd97299b0edecdf9a1319e25a9748312f785fbca530a4014d432198f6b01286fbb2f02bfcccb0b5d8dfb75fedd8a4a2bc9e664dbe5aeed10676357f5d5d6018adc6c1c6cfc1451d00ed5b7df5e725017dc01901de8e5fbdbe3d50718be8b84032c70ea6201ffff7f20000000000000000000000000000000000004010000000004009ed1e1c5ee047960827ff2700a34995c0bbe757b39d763a3db448bf5908812a70000000000018d011f28111c3f541046182636380f0b13174c073d5735023a213c2b0c51145824502a162e194542601e5561440a5e63303137325922334b1d295c012f474303413e045d270e2c403406155a5f1a39094a0d20255b494f6223124e534d52561b3b4808052d04000b10a9d7e4ff16000300000000",
            "01330ae1488a85d539c35de5aac195992b4ac3b16bea5f1be3122ee12cf1fe0e3b01a5413cc58c5d578f205721047ca3aa772c9dbae3baba59b8d845700cc49a20df01961bb7ce4067f368d92a963e0be75c0c82b131fdec50057131f683e6c2b6be5a032c70ea6201ffff7f2000000000000000000000000000000000000401000000000400286fbb2f02bfcccb0b5d8dfb75fedd8a4a2bc9e664dbe5aeed10676357f5d5d60000000000018d015a2e43280a4619354f113662545f4c483a091b322545502c071c0440574a5c335b4b3b151706242b5d273418051d6356415e60552059610b012f58490e30031429234d26021e381a390d0f470c130852513e3c10162a2d4237443d1f212253314e123f04000b73f277c02007000300000000",
            "011b8ca3337f8e311b89b06dc2ae4d0dad06b7ff81eafed6acf64bc5b1da303e6001220a8376296970de607db1ea9764e9e2926939345254ff8e34d9cea40d1490f101b8505ba115726cda623a0ec1d938058c84d02a874f6f89440889a66eabe6f4e5032c70ea6201ffff7f2000000000000000000000000000000000000401000000000400a5413cc58c5d578f205721047ca3aa772c9dbae3baba59b8d845700cc49a20df0000000000018d010b305a4a1a574411550258172c34434f5e0c1c3506531b22512a085b2629313d0a620304202456095d0d281d07010e40191f3c18332d4605153b4149374c455f322e5c480f3821393a2f614e3f4712504b1e6359131610544d27236036252b52143e4204000b9ec0900c7e04000300000000"
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
