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
            "0101cf2d5cd425aa582c7cc242e843cdd867bd5e733d149aefa1ed81537c3aad399a015930c002f3f607e4f0b4b3cc3904017642061bd4c165af711f91d661363856dd01b49b7ceeb1acc45a94f16185a3ebc5493a8e8386055f276c0b08dba76116cf5503de88ce6201ffff7f200300000000000000000000000000000000040100000000040093ddfb73f1363ac5a54b10cc25a61c34d133a9d3421a22333a30da74e64d1df80000000000018d0127610659293445581655012e62312a304f3d510d2d0e1c2b395b3707411e42180c1a1d194a050b23334435283b46122257131b505a0238095d4d212432085f6003174e36150f2f43473f482556100a4c3a2c5314265e044920545c524b3c40633e111f04000b647424b7d919000300000000",
            "010157b3b6a1842ce74b23ca0365b13af5da2fddfe6ad1c9f888a6706201abecc44d01ce71d32045213db96c33bd5b97074253a61137ae672716e8d71ecd67cafa0afc01645ce141404ff1da5511016a70f09c494b645cbee5ac0b85fcdd6e09ee320db403de88ce6201ffff7f20020000000000000000000000000000000004010000000004005930c002f3f607e4f0b4b3cc3904017642061bd4c165af711f91d661363856dd0000000000018d01585d5c5f253b4c602a1f5412142f165e6120232133055646572b4a2c3a340941011d17350e5a30444e633f24532e114b0f522819430a484f45042d3c504d1015383926621b405106321e424936025b180d082907371c132755223e3d0b0359470c1a3104000b899a53092105000300000000",
            "0101296da343425c25f6a077272191777af982d99078282f30a8737c930e70dd77230140d4d966ecc35afccc3971493889e53e317d90d5188498e61a07ae20fd25a4b1019230345cf71bcef892ba6becf565fbafcd9faeecd4e77938168195b5483b64ec03de88ce6201ffff7f2000000000000000000000000000000000000401000000000400ce71d32045213db96c33bd5b97074253a61137ae672716e8d71ecd67cafa0afc0000000000018d015a5931232e534c4634135f15375c16502b3d4d3c625202612654510d602105253906322943632d270f562a4e3344361201571920482f350c5b2c451d085e55240a103e422214403b1f4903284f071a4b411e173a380b4a1b180e1c30113f5d4704095804000b9a08f7114a03000300000000",
            "01018817f72db60d08e667467c7ea387a5ae6d7961ac8ea12e3029dd53640da3f61d0143f6ab256a2be02b2fb8a21ed6c79713d587a050eb40edcdb7017c80da82c30b010dbcf8d35c8c8f4c542b869b7677392e52a520a061810c9f6ec6f768ddc99d1503de88ce6201ffff7f200500000000000000000000000000000000040100000000040040d4d966ecc35afccc3971493889e53e317d90d5188498e61a07ae20fd25a4b10000000000018d013127224d0e0f1d422a2439281550255c13324f1f11082d3f5103024c58534005355b17384506161b522b104e553c5a0d123e29620114435f5e3b466026563363193d305d044120590c2f07184754214a371e0a0b481c574b342c61092e1a492344363a040007601efe0d6d000300000000",
            "010152f2d59312e809b48e324d56d6c767a8d05c4199bb3c7ef48db94a760207997f01050444e05f352dceec46ef297beed462876ab42060c21ebd372728bbc5856c34011c60074a3b609d315056c216f22b32476db5364c38e9c50d20a06c0dbf629cdd03de88ce6201ffff7f200000000000000000000000000000000000040100000000040043f6ab256a2be02b2fb8a21ed6c79713d587a050eb40edcdb7017c80da82c30b0000000000018d015f294d3c014f0a4a35612c091f342718392b1b3f1c3a2f1715332105424b1447240f0d4810455002132d2a5b165626061104362351321d46385a30030b1e41436312191a49084e2844315e405d3e545c523d55572e075362200e59584c253b220c3760040007a0a6c4415c000300000000"
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
