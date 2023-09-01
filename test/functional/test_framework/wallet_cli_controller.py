#!/usr/bin/env python3
#  Copyright (c) 2022-2023 RBB S.r.l
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
"""A wrapper around a CLI wallet instance"""

import os
import asyncio

from typing import Optional

ONE_MB = 2**20
READ_TIMEOUT_SEC = 30

class WalletCliController:

    def __init__(self, node, config, log):
        self.log = log
        self.node = node
        self.config = config

    async def __aenter__(self):
        wallet_cli = os.path.join(self.config["environment"]["BUILDDIR"], "test_wallet"+self.config["environment"]["EXEEXT"] )
        cookie_file = os.path.join(self.node.datadir, ".cookie")
        wallet_args = ["--network", "regtest", "--rpc-address", self.node.url.split("@")[1], "--rpc-cookie-file", cookie_file]

        self.process = await asyncio.create_subprocess_exec(
            wallet_cli, *wallet_args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        self.log.debug("exiting wallet")
        await self._write_command("exit\n")
        await self.process.communicate()

    async def _read_available_output(self) -> str:
        try:
            output = await asyncio.wait_for(self.process.stdout.read(ONE_MB), timeout=READ_TIMEOUT_SEC)
            return output.decode().strip()
        except:
            return ''

    async def _write_command(self, cmd: str) -> str:
        self.process.stdin.write(cmd.encode())
        await self.process.stdin.drain()
        return await self._read_available_output()

    async def create_wallet(self) -> str:
        wallet_file = os.path.join(self.node.datadir, "wallet")
        return await self._write_command(f"createwallet {wallet_file} store-seed-phrase\n")

    async def recover_wallet(self, mnemonic: str) -> str:
        wallet_file = os.path.join(self.node.datadir, "recovered_wallet")
        return await self._write_command(f"createwallet {wallet_file} store-seed-phrase \"{mnemonic}\"\n")

    async def close_wallet(self) -> str:
        return await self._write_command("closewallet\n")

    async def show_seed_phrase(self) -> Optional[str]:
        output = await self._write_command("showseedphrase\n")
        if output.startswith("The saved seed phrase is"):
            mnemonic = output[output.find("\"") + 1:-1]
            return mnemonic
        # wallet doesn't have the seed phrase stored
        return None

    async def encrypt_private_keys(self, password: str) -> str:
        return await self._write_command(f"encryptprivatekeys {password}\n")

    async def unlock_private_keys(self, password: str) -> str:
        return await self._write_command(f"unlockprivatekeys {password}\n")

    async def lock_private_keys(self) -> str:
        return await self._write_command(f"lockprivatekeys\n")

    async def remove_private_keys_encryption(self) -> str:
        return await self._write_command(f"removeprivatekeysencryption\n")

    async def get_best_block_height(self) -> str:
        return await self._write_command("bestblockheight\n")

    async def get_best_block(self) -> str:
        return await self._write_command("bestblock\n")

    async def create_new_account(self, name: Optional[str] = '') -> str:
        return await self._write_command(f"createnewaccount {name}\n")

    async def select_account(self, account_index: int) -> str:
        return await self._write_command(f"selectaccount {account_index}\n")

    async def new_public_key(self) -> bytes:
        public_key = await self._write_command("newpublickey\n")

        # remove the pub key enum value, the first one byte
        pub_key_bytes = bytes.fromhex(public_key)[1:]
        return pub_key_bytes

    async def new_address(self) -> str:
        return await self._write_command(f"newaddress\n")

    async def send_to_address(self, address: str, amount: int) -> str:
        return await self._write_command(f"sendtoaddress {address} {amount}\n")

    async def issue_new_token(self,
                              token_ticker: str,
                              amount_to_issue: str,
                              number_of_decimals: int,
                              metadata_uri: str,
                              destination_address: str) -> str:
        return await self._write_command(f"issuenewtoken {token_ticker} {amount_to_issue} {number_of_decimals} {metadata_uri} {destination_address}\n")

    async def issue_new_nft(self,
                            destination_address: str,
                            media_hash: str,
                            name: str,
                            description: str,
                            ticker: str,
                            creator: Optional[str] = '',
                            icon_uri: Optional[str] = '',
                            media_uri: Optional[str] = '',
                            additional_metadata_uri: Optional[str] = '') -> str:
        return await self._write_command(f"issuenewnft {destination_address} {media_hash} {name} {description} {ticker} {creator} {icon_uri} {media_uri} {additional_metadata_uri}\n")

    async def create_stake_pool(self,
                                amount: str,
                                cost_per_block: str,
                                margin_ratio_per_thousand: str,
                                decommission_key: Optional[str] = '') -> str:
        return await self._write_command(f"createstakepool {amount} {cost_per_block} {margin_ratio_per_thousand} {decommission_key}\n")

    async def sync(self) -> str:
        return await self._write_command("syncwallet\n")

    async def get_balance(self) -> str:
        return await self._write_command("getbalance\n")
