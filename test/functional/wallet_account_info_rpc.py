#!/usr/bin/env python3
#  Copyright (c) 2023 RBB S.r.l
#  Copyright (c) 2017-2021 The Bitcoin Core developers
#  opensource@mintlayer.org
#  SPDX-License-Identifier: MIT
#  Licensed under the MIT License;
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
"""Wallet account info test

Check that:
* We can create a new wallet,
* get an address
* send coins to the wallet's address
* sync the wallet with the node
* check balance
* create a new account
* rename the account
* get wallet info
"""

from wallet_account_info import WalletAccountInfo
from test_framework.wallet_rpc_controller import WalletRpcController
import random

class WalletAccountInfoRpc(WalletAccountInfo):

    def set_test_params(self):
        self.wallet_controller = WalletRpcController
        self.setup_clean_chain = True
        self.num_nodes = 1
        relay_fee_rate = random.randint(1, 100_000_000)
        self.extra_args = [[
            "--blockprod-min-peers-to-produce-blocks=0",
            f"--min-tx-relay-fee-rate={relay_fee_rate}",
        ]]

    def run_test(self):
        super().run_test()


if __name__ == '__main__':
    WalletAccountInfoRpc().main()

