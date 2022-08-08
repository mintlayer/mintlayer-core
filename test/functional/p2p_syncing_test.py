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
            "0175e9cc345b1daf683bc4f77577c886aa8ed694942f6be04bae94b993855e455a7cb551bd739fe470dfce82b3205611bf351ce7b8ecb8ca589006496680c0f7982617fd5548094ad6c25f827ed2831cdb3fb73d7eefb959a4ed4e2c75f8de59c9031c32f16201ffff7f200000000000000000000000000000000000040100000000040175e9cc345b1daf683bc4f77577c886aa8ed694942f6be04bae94b993855e455a0000000000018d015b23053d102a3443501c074f47462c4a3f0a39535f123a62082620455d094842061f162f2e0d3e1d1a571422403b5e5233320263544c5a59311b1817015c192b360b04254e0c583556211e3c0f11444d55602d30490e512741154b033837612913282404000b4c6518ae263f000300000000",
            "01428aebc71c26078cc19ce66c1d094833c18342780e54be2bbcfcf7b41e88584fbeb3618df1c567b3b5a1fcfcb3be22d00c4246ea588f38ee773123d010287acfa7fe53d97d4175f67dee7a7cf1aeb8cb33b140154664407cfb52082d0928c71c031c32f16201ffff7f2005000000000000000000000000000000000401000000000400198f3d140a957f0d6988c93167405e21e3eccf6c9a4f16719756280169de3f900000000000018d01194c03452a29212d163c3e2e4a504d3d0a354924130c31520e5437600b2615174863090f343a1242256204531d6146550757515c381b2c362f5f22594733301c32101a431e5a585b2b56270d1f4e4f5e1139410502143b0620011823403f44084b285d04000be7c95db8a533000300000000",
            "01fd91f1576855524fe513c583e53ca267667a66de550d3fa885bcb1d8b68a712e180b6639a6974fdf54f27135bde1ea693563595e56a96cfebdd5dcc4a56252fd98461da9b4862430b61ce0130ace31120fa65fdb9c67ae15501ae78940fd1d36031c32f16201ffff7f2001000000000000000000000000000000000401000000000400006a68e51e5775e5ae3d691ccbbf34af28f7ae4bb9cc36bb9a4fc52f275c36fc0000000000018d011b5c57483d5d593b4c35490b094560065e54144a1e4e24274d191656615a58552a4f421a47026346391d01050d030c10115b13263f17281831120f2025531c2b5f2c232240622f4b34303c410e211f32503e2908043643073a2d2e0a3338155137445204000bdae76c169c21000300000000",
            "018eadec53647e54a56db977482d7318c42ac0b1d615f9f1110350038aea10e37fcaceefbf8e680a25c195fd07a49c335ac140b1978e5ba7130e1f892a17ffd07af786261b26b97e8ae57690bc7767eda4d315e3c2e3b4d6d2f8f0fb9c6b6f70a0031c32f16201ffff7f20000000000000000000000000000000000004010000000004001c2cb10c68021f4a8ec7397f5e24fd7ca6912632538b1d2739f4ad80d2c6ec220000000000018d011630501d2c3a2e3955265945375d3b1c281a615c22271f142f54133204571e233f33103d0f3e2d4724064c44586038350d34524f425115202b4e48560a024a25400c4b625f2a1709430829630e460541185b07123c310353210b1b194d5a11495e360104000baf118d91ba05000300000000",
            "012f02fda27da6931c154aa037036cb3124444467e6ae3d6195011e9168c14877a63f7709c536105a02a03a7e9c634d60f188a8efa513154b5dafb48e92377136e498b2ed55a55ca83728dd199ceae7f1822ab7ed2ae027214609671588e305a55031c32f16201ffff7f2000000000000000000000000000000000000401000000000400679cf47a12e52601e1b983ff5a5f903bb6481a157f3c5210a8a065c0ef5fbdcf0000000000018d01443a2e19323502076014453746204d5b5257384b291c24405663213f5c4c043331581a4a414916130c301f11512c262a0d01363e2d053b420a3d546117431b234f470f39185f10481550225a0b2b09251e065d624e55531d273c2f5e34120359080e2804000be42b3a976902000300000000"     
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
