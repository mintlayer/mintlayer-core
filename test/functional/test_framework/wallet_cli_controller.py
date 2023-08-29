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

import subprocess
import os
from threading import Event, Thread
from queue import SimpleQueue, Empty

from typing import Optional

def reader_thread(process_output, queue: SimpleQueue, stop_event: Event):
    while not stop_event.is_set():
        try:
            line = process_output.readline()
        except:
            return
        queue.put(line.strip())

class WalletCliController:

    def __init__(self, node, config, log):
        wallet_cli = os.path.join(config["environment"]["BUILDDIR"], "test_wallet"+config["environment"]["EXEEXT"] )
        cookie_file = os.path.join(node.datadir, ".cookie")
        wallet_args = ["--network", "regtest", "--rpc-address", node.url.split("@")[1], "--rpc-cookie-file", cookie_file]
        
        self.log = log
        self.process = subprocess.Popen([wallet_cli] + wallet_args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.node = node
        self.stop_event = Event()
        self.shared_queue = SimpleQueue()
        self.reader = Thread(target=reader_thread, args=(self.process.stdout, self.shared_queue, self.stop_event))
        self.reader.start()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.log.debug("exiting wallet")
        self._write_command("exit\n")
        self.stop_event.set()
        self.process.communicate()
        self.reader.join()

    def _read_available_output(self) -> str:
        output = self.shared_queue.get(timeout=30)
        try:
            while not self.shared_queue.empty():
                output += self.shared_queue.get_nowait()
        except Empty as _:
            pass

        return output

    def _read_n_lines(self, lines: int) -> str:
        output = ''
        try:
            for _ in range(lines):
                output += self.shared_queue.get(timeout=30)
        except Empty as _:
            pass

        return output

    def _write_command(self, cmd: str):
        self.process.stdin.write(cmd)
        self.process.stdin.flush()

    def create_wallet(self):
        wallet_file = os.path.join(self.node.datadir, "wallet")
        self._write_command(f"createwallet {wallet_file} store-seed-phrase\n")
        return self._read_available_output()

    def recover_wallet(self, mnemonic: str):
        wallet_file = os.path.join(self.node.datadir, "wallet")
        self._write_command(f"createwallet {wallet_file} store-seed-phrase \"{mnemonic}\"\n")
        return self._read_available_output()

    def close_wallet(self):
        self._write_command("closewallet\n")
        return self._read_available_output()

    def encrypt_private_keys(self, password: str):
        self._write_command(f"encryptprivatekeys {password}\n")
        return self._read_available_output()

    def unlock_private_keys(self, password: str):
        self._write_command(f"unlockprivatekeys {password}\n")
        return self._read_available_output()

    def lock_private_keys(self):
        self._write_command(f"lockprivatekeys\n")
        return self._read_available_output()

    def remove_private_keys_encryption(self):
        self._write_command(f"removeprivatekeysencryption\n")
        return self._read_available_output()

    def get_best_block_height(self):
        self._write_command("bestblockheight\n")
        return self._read_n_lines(1)

    def get_best_block(self):
        self._write_command("bestblock\n")
        return self._read_n_lines(1)

    def create_new_account(self, name: Optional[str] = ''):
        self._write_command(f"createnewaccount {name}\n")
        return self._read_available_output()

    def select_account(self, account_index: int):
        self._write_command(f"selectaccount {account_index}\n")
        return self._read_available_output()

    def new_public_key(self):
        self._write_command("newpublickey\n")

        public_key = self._read_n_lines(1)
        # remove the pub key enum value, the first one byte
        pub_key_bytes = bytes.fromhex(public_key)[1:]
        return pub_key_bytes

    def new_address(self):
        self._write_command(f"newaddress\n")
        return self._read_n_lines(1)

    def send_to_address(self, address: str, amount: int):
        self._write_command(f"sendtoaddress {address} {amount}\n")
        return self._read_available_output()

    def issue_new_token(self,
                        token_ticker: str,
                        amount_to_issue: str,
                        number_of_decimals: int,
                        metadata_uri: str,
                        destination_address: str):
        self._write_command(f"issuenewtoken {token_ticker} {amount_to_issue} {number_of_decimals} {metadata_uri} {destination_address}\n")
        return self._read_available_output()

    def issue_new_nft(self,
                      destination_address: str,
                      media_hash: str,
                      name: str,
                      description: str,
                      ticker: str,
                      creator: Optional[str] = '',
                      icon_uri: Optional[str] = '',
                      media_uri: Optional[str] = '',
                      additional_metadata_uri: Optional[str] = ''):
        self._write_command(f"issuenewnft {destination_address} {media_hash} {name} {description} {ticker} {creator} {icon_uri} {media_uri} {additional_metadata_uri}\n")
        return self._read_available_output()

    def create_stake_pool(self,
                          amount: str,
                          cost_per_block: str,
                          margin_ratio_per_thousand: str,
                          decommission_key: Optional[str] = ''):
        self._write_command(f"createstakepool {amount} {cost_per_block} {margin_ratio_per_thousand} {decommission_key}\n")
        return self._read_available_output()

    def sync(self):
        self._write_command("syncwallet\n")
        return self._read_available_output()

    def get_balance(self):
        self._write_command("getbalance\n")
        return self._read_available_output()

