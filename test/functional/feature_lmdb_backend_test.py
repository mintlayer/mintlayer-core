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
            "01fe760cab5844216e725dd27b8bcaa79d8a3c8dfde851dbf5ae50790fc035a7dfa29ebec302d2ba3238d291955815542eeac8716d02f9045b8e933206da5c46edfea4f6c903c99ea8d42aef3485905f82d1075d969f69d805c86107f64e15c64303240ac06101ffff7f2000000000000000000000000000000000000401000000000401fe760cab5844216e725dd27b8bcaa79d8a3c8dfde851dbf5ae50790fc035a7df000000000400176eed560ffb1dc02d010000000000000400018d013c05300d431215134f2055472e2201452c3721414a071e4b173d2a111b3a03543e5a49531048560b2b42354c0c461c09191d25340a0e2940161a59513f393318585d3b085c04385f632f5b60060223274424361f260f614e572d5e504d283114523262",
            "0172109d501d682678c14e255020e9a15b84f9a30707d57347915d5d88d5e8e12b4350e4dbaab8f89b61271c8c8f43f8d3a525f2b8a797f83d39a3f99d2d4e4b796122fc79ee843c065ab3634b51e7f00d3f52cc1be680a9ebd3df0a99dd7344e803240ac06101ffff7f20000000000000000000000000000000000004010000000004002e410340bb8aa842b774d52a7edcb97c4f6f94afd37e6a16d2e8a63161e20598000000000400171bdcf10def069320010000000000000400018d013a2722524e3641140d593518345c4b4820232a0c5419622b3b6116440a06261e1260333e4c531c09514358152c5539102108131f3f013056472d175a0245034d11505e242f1a313742040b4946073c1b2e28055b5f6338324f294a400f0e1d5d573d25",
            "01a930067c8594b6900f98b31eec106237156d4b772224a9c49e7f94fdc2dd2e09da6a6f3900b1a895537ab29ff96454f49f73b4a925e2fad3dcd5fb456929795bff7af37b19956d218d9c3b9f6ad99ccdcc297fb9ea159aea03cfbecda77cb11303240ac06101ffff7f2001000000000000000000000000000000000401000000000400ab31ffbde23687d6b2e0178a6bd02d83059ef91dd4416c3095bf5ac4a0caebdb0000000004001316a4c2d5376134e60000000000000400018d011e3a371b02440449474b634a5a352c58190103542e3036260b05063109402d4d3316430a3c500f5e55481d080e573d4f132b18460c20126260294c5211100724613851532542273e3b392a3414231f5d22210d414e3245175c15593f5b5f56281a1c2f",
            "01f723d973e9a7481d6329b617c09b4f203fe6f771dc2f13fbc9904df6cf87846f21924f3a285a2c7837bdcdaa32c2278c9c97b33b704cf4ee365b6131afbd219e9771e5c55f07ee27a870e5e8fbd44a492e4fa0ae15e13c2732f2e138f0c5859f03240ac06101ffff7f2001000000000000000000000000000000000401000000000400ecac06f74a0c2d2442e9780fe502d7ce206fd5c74dcc1c5885510bdf5c57056e0000000004001340a38ca09a55e6960000000000000400018d01255f3a3509062703172e4c60365b593b3346501332311663434a0b4e026151013c2d1a5805222b0e30543f0c2347295a483e2f1519412a621c28444b20420f5e0a183d554d102456522c3908492114121f3840575d4511075c341e37040d531b4f261d",
            "0152253a98036ce633b6b3b07d48799e3e13664ce76cc32ae7442e3b6ddfa19913c266b9ddd44f774ff80d745cb0cf8b8b4381e7a75358510032e4efe7df62458d4a9975ef5e1b161781cd5471e0ab57e647439bcb7f2cffdcea390f3fdcb506c403240ac06101ffff7f20030000000000000000000000000000000004010000000004006d5d825a4c7590e11891e3f364ae8bc2e27b4dae6547d5b74ee9ecad4b26e60b000000000400138f6497535df18d430000000000000400018d01104f504b2e353a2345184720195c2c3339264c421a572f0f1f49341c054d285d12025f4a325e084e09373b29545b36383f581d2b3d1652433e150e220c1e512403530b3062553c2740256104172a56591b112106482d440a4660416301135a0d311407"
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
