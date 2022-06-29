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
            "0101f660d6ca21f0d2ca004374a70d5fdb1c6136e26cbf486e09f541b5fc10614b3e01585ee6f5ba5d0385bba81a249e724a733e840a844bdb19c6cd4fab8b3c064cac0115d6cb4da82aefc801bd40e0fb9e8ffe601577f8a45a0316f8cb0bb9627f8db8036370bc6201ffff7f20000000000000000000000000000000000004010000000004009bf702df140fdcdb74af065fb3a45d1ea915fcbe40b691f823e6295c6bb0356e0000000000018d0143455f5b1e360e542941220f2042335601470d3e2463395d2a615716083f1714372c234a12041c2f5e07251f106258532b4851383b4d520a3d2e4e2760460c5c4b2d3c3055110906024c19321b26054049181d3534155a13440b3a31285021594f1a03040b26cfd114da29000300000000",
            "010108665aff2343e5c58487908243a56a519b7143f91f9b4d344123ede04f22dd3f01b44e12386a63c56920d7737f88670bdc1961f460b2545357d1057030dec18785014333954efaa58d493a46180f98f9fecf9f2ab26275e52e7f4d2f60e5b1d277bc036370bc6201ffff7f2002000000000000000000000000000000000401000000000400585ee6f5ba5d0385bba81a249e724a733e840a844bdb19c6cd4fab8b3c064cac0000000000018d012b2355610b213350053520343831130403376326112c4f4c2d5d5c1f3c5a423f0a30152514295b2a5e195436473a182740124a4d0210602e1b44563b17081c32455f5148522458430701461a41593d1d1e2f3e0c4b0e06280d5339090f5722624e1649040b1d1b2cc1d010000300000000",
            "01017d5359171b2db9a4a4ff8c7f4738bd6e4cacae834eb23711de5f3c256dfc4e0c01d646338c7e587d901047fc8050a77bb5269dbdb4faafb673348b36c93a98d150016c1a29d1bb065242781a3523094315c3fc2125ba8f1ee835f6b97954cbe6369c036370bc6201ffff7f2003000000000000000000000000000000000401000000000400b44e12386a63c56920d7737f88670bdc1961f460b2545357d1057030dec187850000000000018d013c2e085c2549571e1532020438060c1a272c070f56090e5f1c43446036164f503a5e33464034210b1b5b620359284d055220303d1710613f015d4e2f4c511854392a48194b45241f2341530a0d423e635a29141d3713122b223526584a553147113b2d04076aa272cba7000300000000",
            "0101ce37c06b8b70812bb66b844ea25becdebb6d801e7b3fd044ac5cc0bc539cd613012c20a9be94cf6f6b5e2a1f85d4aa69f4dc8ecad31090d6fefc1808b8a1ed980c014283836ff03fc4b9ac608549487d0b79823c8cd1eb3b54b716d432cc0fc4e5ea036370bc6201ffff7f2001000000000000000000000000000000000401000000000400d646338c7e587d901047fc8050a77bb5269dbdb4faafb673348b36c93a98d1500000000000018d011e42464a133515584d38613b0237593d194136141f264b444e4325490804242f56073a625e5b11272a6306173060010e222110092e45472c1a50525d4f201c1253343c051b57035f5a0a182351400f0d16481d330c545c2d324c3f3e295531280b2b3904077b49edd31c000300000000"
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
