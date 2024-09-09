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

"""Wallet tokens change metadta uri test"""

from wallet_tokens_change_metadata_uri import WalletTokens
from test_framework.wallet_rpc_controller import WalletRpcController


class WalletTokensRpc(WalletTokens):
    def set_test_params(self):
        super().set_test_params()
        self.wallet_controller = WalletRpcController

    def run_test(self):
        super().run_test()


if __name__ == '__main__':
    WalletTokensRpc().main()