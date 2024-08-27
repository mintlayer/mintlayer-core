#!/usr/bin/env python3
#  Copyright (c) 2022-2024 RBB S.r.l
#  Copyright (c) 2014-2021 The Bitcoin Core developers
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

from dataclasses import dataclass


@dataclass
class TokenTxOutput:
    token_id: str
    address: str
    amount: str

    def __str__(self):
        return f'transfer({self.token_id},{self.address},{self.amount})'

@dataclass
class PartialSigInfo:
    input_index: int
    num_signatures: int
    required_signatures: int
