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
            "01511d679c8a8850ea43b5ea119f3f20a1a532ded97fbe345eca2809bfa1085c6a01230764a7408ecaaca41c31c6b372899c61ea5dea575723483c96fd1680fc97ee0124767222f1747d093f6fe0c0588ac28153f87aa60636a40c945edc4d230b9ca603ce1fd96201ffff7f2001000000000000000000000000000000000401000000000401511d679c8a8850ea43b5ea119f3f20a1a532ded97fbe345eca2809bfa1085c6a0000000000018d01041b2f484b3f3d5a3730293821415c113e5d0206523412444c42570d311425460b513b1c50622805032026601e271a1735554e2e243c63494d4a08593919430f0161330745185f2d365e2b1513231d4f1054585b0e22473a40163253090c1f0a2a562c040b6c607a6c6922000300000000",
            "01acf04f3f8538ac970aabd4d26261f38e0832c567676ca68c8c73a20610b9e963014235643a02fb9f40c192029bb870f18de7eeacfb067ed70da3ef78715ba4c09601117de21d0ecab87992d2c6460d244fdd5b5c2b247ffe70495b7e0167a1b14db303ce1fd96201ffff7f2001000000000000000000000000000000000401000000000400230764a7408ecaaca41c31c6b372899c61ea5dea575723483c96fd1680fc97ee0000000000018d0160251750081d36545e304227310e584b152a3a4a072d2f1f492c465218560d443823345516220f4e3b3557392b114c41025b260c3310611914483206401a4d450120375f3d623f5c215a05090a471213031c59510b4f283e043c29631e535d43241b2e040bf712eafa9412000300000000",
            "016f850f446e3ddaa3f7101a8cbcd571373308c3bd813e6f2f9db2571153be9f7a01823d56d64e0c68d55ffa2ee7ccec27198d0bab5b9d7a9d7796e339a086814c3901fc9115bbfca5b7bd9e281d98af35b3a82fa344a8c9f32212d4db12932b5707b603ce1fd96201ffff7f20010000000000000000000000000000000004010000000004004235643a02fb9f40c192029bb870f18de7eeacfb067ed70da3ef78715ba4c0960000000000018d01582a4d235d464a63485a52282c16416244110f3b5329263c020d5443241d01091e132f3a352d152b5012361c0a57271f4f5b2e253d2133204e18145c5908384749073e100337420b5e4c050c6145173f1a5f06320e554b2204313934511b3060194056040b88a2ff7b6d0b000300000000",
            "0192ed2b3cfbe9f4a9db012baeb9b05131bc57277d81df3f7f489dde8aa981901301f9bd5550c28c73315c1c0dc2f979fbc7549432bbf60ef3c61bfa27be129e9f9b018ac9a1c0067cca0bf7fda948d1fe9c9e02de3bd901ecc51c28ff954d588f445603ce1fd96201ffff7f2001000000000000000000000000000000000401000000000400823d56d64e0c68d55ffa2ee7ccec27198d0bab5b9d7a9d7796e339a086814c390000000000018d012c5e08305b3503184f323c0d40144305335a3953480a4721200628561617092623342a1e4c1a500445615c55022b2f510749362d19253a4a29410b2e0f244d3d58105938221c0e315f42123b574b0c13541f4e633e1d5d1b012752371115443f60466204075ab43cc3b9000300000000",
            "01c0e26fb062a7fd7b086f72c45da9138dfc91f8721719caf6253006d3d8f4b22c018c64e1faad8f57d22ba2f29f87f893ff7cc15bac9ed36853d75eaa423aa980a10155b2353f7442fa2ca15736c9b4aa8839f5e70e2be9b886e476e86c849af9f67b03ce1fd96201ffff7f2000000000000000000000000000000000000401000000000400f9bd5550c28c73315c1c0dc2f979fbc7549432bbf60ef3c61bfa27be129e9f9b0000000000018d011a635326523f4d27180b384405340428553e1b1c435f2b360c15102356122517545920032f3b161446354808313d4e581e0f49511f5e372407293a40394161210d4f223c504a4b47330a4c0232421160015a2d30452a135d09622e1d0657195c2c0e5b0407da9864de64000300000000"
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
