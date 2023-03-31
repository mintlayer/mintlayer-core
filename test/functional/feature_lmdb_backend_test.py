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
        self.num_nodes = 1

    def setup_network(self):
        self.setup_nodes()
        self.sync_all([self.nodes[0]])

    def block_height(self):
        tip = self.nodes[0].chainstate_best_block_id()
        return self.nodes[0].chainstate_block_height_in_main_chain(tip)

    def assert_tip(self, expected):
        tip = self.nodes[0].chainstate_best_block_id()
        block = self.nodes[0].chainstate_get_block(tip)
        assert_equal(block, expected)

    def restart_node(self):
        self.stop_node(0)
        self.start_node(0)

    def run_test(self):
        blocks = [
            "01916b5099a91acadd46431d4eab261579f00b02b2ad79b69cedbd60163370b15a59029712042385c7294190649ea1e0e72bb3bce3bc7544abd891fd47c95147f3ce297058329579611c0d654705f320efa149cf62937bb47dce6c9abbfba1f20003240ac06101ffff7f2003000000000000000000000000000000000401000000000401916b5099a91acadd46431d4eab261579f00b02b2ad79b69cedbd60163370b15a0000000004000017d6acd5778fa0a7130300000000000400018d010a123029134f482d06190b045c432c3550620f5e02254d4e5d600c231f1c3d49321b474459285841013442461e08105224055107560e553b4b38111a61361d394a2b152017265314401803452254315a37093c3e63162a2e0d3a335f2f5b2721573f4c",
            "01b2a927982524f8e846a711c018f56f9b5a86e109a512bb6cb054bb1dc9ee26043bd673e4b5cc5b4291e17c4323bc32d3794b08a6710abfd2fc282a4c8fd4713da437ddd9d6028a05c5df87037d5ffa00b0c3a739619495c4213f50c407524f0e03240ac06101ffff7f20000000000000000000000000000000000004010000000004004b67c508383e511bd86b7b69acffd108ce0427b91b1893bd16da5fde260ab711000000000400001394dfde730d95905600000000000400018d0104100859335e3f3227024e0126481e13623a35114d214c1b513b50560d2f0e36243c3d072e5c0a0b252d19473816423009490f465a3141394f28341c63372c3e402a53231757145d1f054303201d4b29545861550c451812155f2206602b441a4a525b",
            "01d62b11e192f398f86f2cda6d9155faa8dda8b1eb6268e96134158e9f9b727437fbc6239997dd0bc6e8cc3dcb876d8682b7543efe5aeac6b38ddc5cb9779d45ced4800f1a6b5af4f916b6b780496e5a206349bf7cf64e3788d895ea9e35030b0b03240ac06101ffff7f2006000000000000000000000000000000000401000000000400a7fa2b0cf7b03fb29e86332c91766f2abcffc7bc53da10a8139f442da7dec06f00000000040000137240b98f7204ab3900000000000400018d010562443d38371a0f164e46135a044b0a0d59073224575b10502c255f631c603b4f2911153512185e39302f5d2709171e312126482a34034320421b4d06220c2d1f2852010e024561333f362b145551531d2e490b4756544c3a3e41584a5c081923403c",
            "01da6d966628bb6a06f19a5a670e3c0c0375dcc9bc8dbf1a8ad967f42c28456b5b5335e506f97bd2dbe3ef75ca1432382ee3b1e6d966799a0212ee50bbdc008e9d08f8f0500dd24c14da9bf3db3596e5ba427836f87a19dd4b387a2070ca5d6c3103240ac06101ffff7f2000000000000000000000000000000000000401000000000400d2bbeb01c8c7551fd49f9f5963c36c745ebaaadf3f78c9d33eeb3398a5b36b53000000000400000f7cda6416900b6e00000000000400018d010b544b15555726513143204a342342185e0358563c121f47353b10130f28504f1a39633e2e1d0a1b3853223f2a020d5c455f5d04363a090e49333d1c6244272c524861304c5b320c252124196059172d291406115a404e2f46072b08014d41051e1637",
            "01eb3f5f1ff6ec671a473bdf081b57ca6c07daac42200c5543a76c331b9b11de1fd07f5abee88300827abc8f0b9390410c15bcec7029be776b7c7f181c162e56c4793557c1baae51df6d325e6348e933598d98f7fcb16fd13374958792812e21e003240ac06101ffff7f200000000000000000000000000000000000040100000000040009acea7cbacd37171a7dd95637cf58e331ab5037868348a743a4bd55573db742000000000400000fe73deab81a9b1f00000000000400018d011e455c072c604c281c3a54203055112227170832445b3803425e4a2d401b2e1418622931492f0904263702410b505a342124585156520d535d190e3e23133906460533434b2b121f3d2a4e165f4f014d59256110470a3b150f3c1d571a0c3f35366348",
        ]

        node = self.nodes[0]

        # get current tip hash
        assert_equal(self.block_height(), 0)

        # add two blocks
        node.chainstate_submit_block(blocks[0])
        node.chainstate_submit_block(blocks[1])
        assert_equal(self.block_height(), 2)
        self.assert_tip(blocks[1])

        # Restart the node
        self.restart_node()

        # Check the most up-to-date tip has survived the shutdown/start cycle
        assert_equal(self.block_height(), 2)
        self.assert_tip(blocks[1])

        # Add three more blocks
        for block in blocks[2:]:
            node.chainstate_submit_block(block)
        assert_equal(self.block_height(), 5)
        self.assert_tip(blocks[4])

        # Restart the node
        self.restart_node()

        # Check the most up-to-date tip has survived the shutdown/start cycle
        self.assert_tip(blocks[4])

if __name__ == '__main__':
    ExampleTest().main()
