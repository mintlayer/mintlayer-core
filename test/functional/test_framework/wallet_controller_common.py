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
import re


@dataclass
class UtxoOutpoint:
    id: str
    index: int

    def __str__(self):
        return f'tx({self.id},{self.index})'

    def to_json(self):
        return { "source_id": { "type": "Transaction", "content": { "tx_id": self.id } }, "index": self.index }


def to_json(obj):
    if hasattr(obj, 'to_json'):
        return obj.to_json()
    else:
        return obj


# Note: the input is supposed to be a hex-encoded `crypto::key::PublicKey`, which is returned
# e.g. by wallet's `reveal_public_key_as_hex`. It contains the public key itself, prefixed with
# an extra zero byte (which corresponds to the SCALE-encoded enum variant `PublicKeyHolder::Secp256k1Schnorr`).
# Also note that `wallet_xxx_controller.new_public_key` removes this prefix by default.
def pub_key_hex_to_hexified_dest(pub_key_hex: str) -> str:
    pub_key_hex = pub_key_hex.removeprefix("0x")
    return f"HexifiedDestination{{0x02{pub_key_hex}}}"


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


class WalletCliControllerBase:
    async def submit_transaction_return_id(self, transaction: str, do_not_store: bool = False) -> str:
        output = await self.submit_transaction(transaction, do_not_store)
        pattern = r'The transaction was submitted successfully with ID:\n([0-9a-fA-F]+)'
        match = re.search(pattern, output)
        assert match is not None
        return match.group(1)
