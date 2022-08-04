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
            "0175e9cc345b1daf683bc4f77577c886aa8ed694942f6be04bae94b993855e455a01f8cc15e27c90a00485d30422c02b64fde0636a42625e0e33afbb73ffd783a571019ce9d7151b4c4b8fe8f240a8bc28fdc943efcd0ebd9dd0e873a4a67a889ba7b803c80bec6201ffff7f200200000000000000000000000000000000040100000000040175e9cc345b1daf683bc4f77577c886aa8ed694942f6be04bae94b993855e455a0000000000018d012924100d0838450e03402d483e2b185d4d3336074247311f5c3a46634a585f3b17374f22091a13495950153c273214615730235e52441b1c05534c41565a3428065b1d0b4e1e350a3f43041920543d2c122f260151392e0c0f602a164b25022162115504000b4dc909229d56000300000000",
            "0180493d03cc5233b8058432e4295cc95a44fb6a6c49b4c2f9cd231619eb27b1310138fe791edca63b04fd2448d7e937a2646917ed6feec5b78255c53f619d73490a01d77d6fec4a2cb381e013ffac5d882a785831c4a8a9aed4bcb893a7b46eb04cb303c80bec6201ffff7f2001000000000000000000000000000000000401000000000400f8cc15e27c90a00485d30422c02b64fde0636a42625e0e33afbb73ffd783a5710000000000018d013c3f5c3856325d23261542315349143a214f370c1860391b43114a4803042c24361a2d610f290728461c4b250212170b5933225709470a0e014c0d2e2a50351f453e41102b3d441358624e5434064d5a0820555f5b5e1d193b05512f271e633016524004000b515e5c497645000300000000",
            "01087b72b763b43986c8403efdac91b4d50062c1609c76143b193849a917de566901a2f2e9a54982b6126e9bc5b4a9b1559a16ece6a62d741c860cc9024d5da534e601c2e2665bb91aad05071956236c3961871c5fe54a9fd6f0b9809a9b7752ca962603c80bec6201ffff7f200300000000000000000000000000000000040100000000040038fe791edca63b04fd2448d7e937a2646917ed6feec5b78255c53f619d73490a0000000000018d01450f08582406371455175f6042182a4a4e1b0e5c275e48150c41625d2b543325431d034f472d0434102f190121203b3d460b492628075b110956133a1602610a57393631320d23121c531a38223c50404c2c1e053e2e4d63595a441f4b523035513f2904000b7d4781227a16000300000000",
            "015059cc33a30b1d5068a46b2c5990c42d4a9ec8cd57440c69c8e4fc0a80f9f42b014ba0617ccc937289fc3662ae53f4f0aad6f56d24544dd6c692ef7d9e1dc1877501d1bcabb9e14b1d1d2befc6ba5196288c9b441f467b8a6be3c8bbc2bb783c8d7f03c80bec6201ffff7f2001000000000000000000000000000000000401000000000400a2f2e9a54982b6126e9bc5b4a9b1559a16ece6a62d741c860cc9024d5da534e60000000000018d013a05030457502f08135c100d2d46474d1941142752295b24074f3c2e0c593d583e2540613516604a28231106325a37361e431c01315f511d440e4c1f1862200b22020a3942552a3b09544b2617451a2c21632b5d561549385e12303f330f4834534e1b0400072379bb3728000300000000",
            "011533b57c71e9fbb16c11e9822a8fca68a515a3010bd98e4b04ff4d66163640730104140c3bc975431b91db94abd6265846b76ee2fef1b7cabcb360145648b6e9bd01923486dbe5ed8b0b75ee0ba184d5ae94e67f5e687d4fe8a7b4cad6d5a5aa6a9d03c80bec6201ffff7f20030000000000000000000000000000000004010000000004004ba0617ccc937289fc3662ae53f4f0aad6f56d24544dd6c692ef7d9e1dc187750000000000018d0145402a58290134022410253b44191e2d0b0d4153361b16511f614d503a13632138031218283e082b2062424347145b48155c051754315f09302f5d594f553960074c1a5e560e32460c5233490f3d275a573f354b4e0a11064a1d042c263c2337221c2e040007e23b799710000300000000",
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
