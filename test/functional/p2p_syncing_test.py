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
            "01040152666ffa431cce31946d9fd25244646290bf096cae5ddcd1bd0960b46cdfe79d016077a269cfba21cfea5d340bf5608037d82e9265362be9249ee495a0035fe3e001af0a008e8fabcd513a315554575e57e5c894993992418e76e650cb8a54e8f9b7031f89956201ffff00210000000000000000000000000000000000040100000000040088313f5915344ce829dd1a08f279d7f0bb038efa5e9b3eeb70fc0e4232a60d9f0000000000018d0148584c28554e2f4a36535b5c0f033d230b1a5f564115521222323b611d11372b4706023f3405332442515744591354292e391b17601427204b63105d454018191f305a3a311e503e090c3c2a265e38461621430d07010e4f2d4d0a49081c2c62352504040b07ce2eac0a070300000000",
            "0104019514dd616d99265fa1af7f804e36dfa8998e5c2b760455ff99e63eece59706470121840e07146e1edfe221b4935dc52638120b6c100234dab2c914b428d558a38c01aef7e1f673a95ccb2e005ff63332adab101ef1880b3a1cab3f765fc615eb76c6031f89956201ffff0021000000000000000000000000000000000004010000000004006077a269cfba21cfea5d340bf5608037d82e9265362be9249ee495a0035fe3e00000000000018d0138100601170f59402616223c44342b2e3f4c1c3b5761395813375243623a031e2f63124f46186049454836550a534e230235325d1f150c09045e305f42411a210d4a25191454310708242c3d2027562d5a29115c0b052a330e4b1b511d474d3e285b500407434d6569480300000000",
            "0104018ad24bb99d1d609dc03b88da51fc3f958e79266bc661abb4dc1556f2aef7ec5201d781d8faeb60362cd21d0ab8888a9eab8722043682ca2af4880e64eb149d0b1501e6f075732f275f2f0934b95573c8d87d3385f7f07593ecf1d2b9b9df24298286031f89956201ffff00210000000000000000000000000000000000040100000000040021840e07146e1edfe221b4935dc52638120b6c100234dab2c914b428d558a38c0000000000018d01060e30443d3a1756264047390143025033134b3f16230363154d1a323b532b515f29595a110d60575b1f451e385e141855190907215210461d340f363c580b4f202825041b1c4e425c415d2e2705314c54622c2d490c2a6148352f12374a08240a223e0407c2d1846e0b0300000000",
            "010401b9aa7e241219c972baf47090a01fda721e301e44cbdb8da618a373a9dfe8420a01e0c0a89491b9ab278e5b7d27fcba1e9dad898c1364640f1284e5d146a315b326015c55964430a1c18e9338688ff4585b10811d533ffc428b8f9807e11f971f032d031f89956201ffff002100000000000000000000000000000000000401000000000400d781d8faeb60362cd21d0ab8888a9eab8722043682ca2af4880e64eb149d0b150000000000018d010b135a3c610f41042c430d115916272f07254d1d5b47123f560a4e50014b4510492a2e4063443058212d1e20140215032642335f22353b3d3446280951321c55603e1f0c245c574c48311b38360517530e1a083a394a4f2937235d180619542b62525e0407d81a6f2f050300000000"
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
