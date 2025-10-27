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
"""A wrapper around a RPC wallet instance"""

import os
import asyncio
import http.client
import json
from dataclasses import dataclass
from tempfile import NamedTemporaryFile
import base64
from operator import itemgetter

from typing import Optional, List, Union, TypedDict

from test_framework.util import assert_in, rpc_port
from test_framework.wallet_controller_common import (
    PartialSigInfo, TokenTxOutput, UtxoOutpoint, WalletCliControllerBase,
    pub_key_hex_to_hexified_dest, to_json
)


ONE_MB = 2**20
READ_TIMEOUT_SEC = 30
DEFAULT_ACCOUNT_INDEX = 0


@dataclass
class TransferTxOutput:
    atoms: int
    pub_key_hex: str
    token_id: Optional[str]

    # This produces a serialized TxOutput::Transfer, which is usable e.g. with compose_transaction.
    def to_json(self):
        if self.token_id:
            return {'Transfer': [
                { 'TokenV1': [f"0x{self.token_id}", {"atoms": str(self.atoms)}] },
                pub_key_hex_to_hexified_dest(self.pub_key_hex)
            ]}
        else:
            return {'Transfer': [
                { 'Coin': {"atoms": str(self.atoms)} },
                pub_key_hex_to_hexified_dest(self.pub_key_hex)
            ]}


@dataclass
class Balances:
    coins: str
    tokens: dict


class NewTxResult(TypedDict):
    tx_id: str
    tx: str
    fees: Balances
    broadcasted: bool


@dataclass
class PoolData:
    pool_id: str
    pledge: str
    balance: str


@dataclass
class DelegationData:
    delegation_id: str
    balance: str


@dataclass
class CreatedBlockInfo:
    block_id: str
    block_height: str
    pool_id: str


@dataclass
class AccountInfo:
    index: int
    name: Optional[str]


class WalletRpcController(WalletCliControllerBase):
    def __init__(self, node, config, log, wallet_args: List[str] = [], chain_config_args: List[str] = []):
        self.log = log
        self.node = node
        self.config = config
        self.wallet_args = wallet_args
        self.chain_config_args = chain_config_args
        self.account = DEFAULT_ACCOUNT_INDEX

    async def __aenter__(self):
        cookie_file = os.path.join(self.node.datadir, ".cookie")

        self.log.info(f"node url: {self.node.url}")
        wallet_rpc = os.path.join(self.config["environment"]["BUILDDIR"], "test_rpc_wallet"+self.config["environment"]["EXEEXT"] )
        if "--rpc-username" in self.wallet_args:
            idx = self.wallet_args.index("--rpc-username")
            username = self.wallet_args[idx+1]
            idx = self.wallet_args.index("--rpc-password")
            password = self.wallet_args[idx+1]
            credentials = f"{username}:{password}"
            self.log.info(f'creds: {credentials}')
            credentials_encoded = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')

            def get_headers_user_pass():
                return {
                    'Authorization': f'Basic {credentials_encoded}',
                    'Content-Type': 'application/json'
                }

            self.headers = get_headers_user_pass
        elif "--rpc-cookie-file" in self.wallet_args:
            idx = self.wallet_args.index("--rpc-cookie-file")
            wallet_cookie_file = os.path.join(self.node.datadir, self.wallet_args[idx+1])
            def get_headers_cookie():
                with open(wallet_cookie_file, 'r') as f:
                    cookie = f.read().strip()
                credentials_encoded = base64.b64encode(cookie.encode('utf-8')).decode('utf-8')
                return {
                    'Authorization': f'Basic {credentials_encoded}',
                    'Content-Type': 'application/json'
                }
            self.headers = get_headers_cookie
        else:
            def get_headers():
                return {'Content-Type': 'application/json'}
            self.headers = get_headers

        if "--rpc-bind-address" in self.wallet_args:
            rpc_bind_addr_idx = self.wallet_args.index("--rpc-bind-address")
            bind_addr = self.wallet_args[rpc_bind_addr_idx+1]
            url, port = bind_addr.split(':')
            port = int(port)
            wallet_args = ["regtest"]
        else:
            port = rpc_port(10)
            url = "127.0.0.1"
            bind_addr = f"{url}:{port}"
            wallet_args = ["regtest", "--rpc-bind-address", bind_addr, "--rpc-no-authentication"]

        # if it is a cold wallet don't specify node address and cookie
        if "--cold-wallet" in self.wallet_args:
            wallet_args += self.wallet_args + self.chain_config_args
        else:
            wallet_args += ["--node-rpc-address", self.node.url.split("@")[1], "--node-rpc-cookie-file", cookie_file] + self.wallet_args + self.chain_config_args
        self.wallet_log_file = NamedTemporaryFile(prefix="wallet_stderr_rpc_", dir=os.path.dirname(self.node.datadir), delete=False)
        self.wallet_commands_file = NamedTemporaryFile(prefix="wallet_commands_responses_rpc_", dir=os.path.dirname(self.node.datadir), delete=False)

        self.process = await asyncio.create_subprocess_exec(
            wallet_rpc, *wallet_args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=self.wallet_log_file,
        )
        self.http_client = http.client.HTTPConnection(url, port)
        await asyncio.sleep(5)
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        self.log.debug("exiting wallet")
        self._write_command("shutdown")
        await self.process.communicate()
        self.http_client.close()
        self.wallet_log_file.close()
        self.wallet_commands_file.close()

    def _write_command(self, method: str, params = []) -> dict:
        encoded_cmd = method.encode()
        encoded_params = str(params).encode()
        self.wallet_commands_file.write(b"writing command: ")
        self.wallet_commands_file.write(encoded_cmd)
        self.wallet_commands_file.write(encoded_params)

        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1  # Adjust the id field as needed
        }
        encoded_payload = json.dumps(payload).encode('utf-8')
        self.http_client.request("POST", '', body=encoded_payload, headers=self.headers())
        response = self.http_client.getresponse()
        self.log.debug(f"method, {method}")
        self.log.debug(f'response, {response} status: {response.status}')
        body = response.read().decode('utf-8')
        self.log.debug(f'body, {body}')
        self.wallet_commands_file.write(response.read())
        return json.loads(body)

    async def create_wallet(self, name: str = "wallet", mnemonic: Optional[str] = None) -> str:
        wallet_file = os.path.join(self.node.datadir, name)
        self._write_command("wallet_create", [wallet_file, True, mnemonic])
        return "New wallet created successfully"

    async def open_wallet(self, name: str = "wallet", password: Optional[str] = None, force_change_wallet_type: bool = False) -> str:
        wallet_file = os.path.join(self.node.datadir, name)
        output = self._write_command("wallet_open", [wallet_file, password, force_change_wallet_type])
        if 'result' in output:
            return "Wallet loaded successfully"
        else:
            return output['error']['message']

    async def close_wallet(self) -> str:
        return self._write_command("wallet_close", [])['result']

    async def wallet_info(self) -> List[AccountInfo]:
        result = self._write_command("wallet_info", [])['result']
        return [AccountInfo(idx, name) for idx, name in enumerate(result['account_names'])]

    async def get_best_block_height(self) -> str:
        return str(self._write_command("wallet_best_block", [])['result']['height'])

    async def get_best_block(self) -> str:
        return self._write_command("wallet_best_block", [])['result']['id']

    async def create_new_account(self, name: Optional[str] = None) -> str:
        result = self._write_command("account_create", [name])['result']
        return f"Success, the new account index is: {result['account']}"

    async def rename_account(self, name: Optional[str] = None) -> str:
        self._write_command("account_rename", [self.account, name])
        return "Success, the account name has been successfully renamed"

    async def select_account(self, account_index: int) -> str:
        self.account = account_index
        return "Success"

    # Note: this function behaves identically both for wallet_cli_controller and wallet_rpc_controller.
    async def add_standalone_multisig_address_get_result(
            self, min_required_signatures: int, pub_keys: List[str], label: Optional[str] = None, no_rescan: Optional[bool] = None) -> str:

        result = self._write_command("standalone_add_multisig", [self.account, min_required_signatures, pub_keys, label, no_rescan])
        return result['result']

    async def new_public_key(self, address: Optional[str] = None, strip_encoded_enum_prefix: bool = True) -> bytes:
        if address is None:
            address = await self.new_address()
        public_key = self._write_command("address_reveal_public_key", [self.account, address])['result']['public_key_hex']

        if strip_encoded_enum_prefix:
            # Remove the first byte, which encodes the variant of PublicKeyHolder enum.
            return bytes.fromhex(public_key)[1:]
        else:
            return bytes.fromhex(public_key)

    async def reveal_public_key_as_address(self, address: Optional[str] = None) -> str:
        return self._write_command("address_reveal_public_key", [self.account, address])['result']['public_key_address']

    async def reveal_public_key_as_hex(self, address: Optional[str] = None) -> str:
        return self._write_command("address_reveal_public_key", [self.account, address])['result']['public_key_hex']

    async def new_address(self) -> str:
        return self._write_command("address_new", [self.account])['result']['address']

    async def add_standalone_multisig_address(self, min_required_signatures: int, pub_keys: List[str], label: Optional[str] = None) -> str:
        return self._write_command("standalone_add_multisig", [self.account, min_required_signatures, pub_keys, label, None])['result']

    async def list_utxos(self, utxo_types: str = '', with_locked: str = '', utxo_states: List[str] = []) -> List[UtxoOutpoint]:
        outputs = self._write_command("account_utxos", [self.account, utxo_types, with_locked, ''.join(utxo_states)])['result']
        return [UtxoOutpoint(id=match["outpoint"]["source_id"]["content"]['tx_id'], index=int(match["outpoint"]['index'])) for match in outputs]

    async def get_transaction(self, tx_id: str) -> str:
        return self._write_command("transaction_get", [self.account, tx_id])['result']

    async def get_raw_signed_transaction(self, tx_id: str) -> str:
        return self._write_command("transaction_get_signed_raw", [self.account, tx_id])['result']

    async def send_to_address(self, address: str, amount: int, selected_utxos: List[UtxoOutpoint] = []) -> str:
        self._write_command("address_send", [self.account, address, {'decimal': str(amount)}, selected_utxos, {'in_top_x_mb': 5}])
        return "The transaction was submitted successfully"

    async def send_tokens_to_address(self, token_id: str, address: str, amount: Union[float, str]):
        return self._write_command("token_send", [self.account, token_id, address, {'decimal': str(amount)}, {'in_top_x_mb': 5}])['result']

    # Note: unlike send_tokens_to_address, this function behaves identically both for wallet_cli_controller and wallet_rpc_controller.
    async def send_tokens_to_address_or_fail(self, token_id: str, address: str, amount: Union[float, str]):
        # send_tokens_to_address already fails on error.
        await self.send_tokens_to_address(token_id, address, amount)

    async def issue_new_token(self,
                              token_ticker: str,
                              number_of_decimals: int,
                              metadata_uri: str,
                              destination_address: str,
                              token_supply_fixed: Optional[int] = None,
                              is_freezable: bool = True):
        if token_supply_fixed is None:
            token_supply = { "type": "Lockable" }
        else:
            token_supply = { "type": "Fixed", "content": {'decimal': str(token_supply_fixed)} }

        result = self._write_command('token_issue_new', [
            self.account,
            destination_address,
            {
                'token_ticker': token_ticker,
                'number_of_decimals': number_of_decimals,
                'metadata_uri': metadata_uri,
                'token_supply': token_supply,
                'is_freezable': is_freezable,
            },
            {'in_top_x_mb': 5}
        ])

        if 'result' in result:
            return result['result']['token_id'], result['result']['tx_id'], None
        else:
            return None, None, result['error']

    async def mint_tokens(self, token_id: str, address: str, amount: int) -> NewTxResult:
        return self._write_command("token_mint", [self.account, token_id, address, {'decimal': str(amount)}, {'in_top_x_mb': 5}])['result']

    # Note: unlike mint_tokens, this function behaves identically both for wallet_cli_controller and wallet_rpc_controller.
    async def mint_tokens_or_fail(self, token_id: str, address: str, amount: int):
        # self.mint_tokens already fails on error
        await self.mint_tokens(token_id, address, amount)

    async def unmint_tokens(self, token_id: str, amount: int) -> NewTxResult:
        return self._write_command("token_unmint", [self.account, token_id, {'decimal': str(amount)}, {'in_top_x_mb': 5}])['result']

    async def lock_token_supply(self, token_id: str) -> NewTxResult:
        return self._write_command("token_lock_supply", [self.account, token_id, {'in_top_x_mb': 5}])['result']

    async def freeze_token(self, token_id: str, is_unfreezable: str) -> NewTxResult:
        return self._write_command("token_freeze", [self.account, token_id, is_unfreezable, {'in_top_x_mb': 5}])['result']

    async def unfreeze_token(self, token_id: str) -> NewTxResult:
        return self._write_command("token_unfreeze", [self.account, token_id, {'in_top_x_mb': 5}])['result']

    async def change_token_authority(self, token_id: str, new_authority: str) -> NewTxResult:
        return self._write_command("token_change_authority", [self.account, token_id, new_authority, {'in_top_x_mb': 5}])['result']

    async def change_token_metadata_uri(self, token_id: str, new_metadata_uri: str) -> NewTxResult:
        return self._write_command("token_change_metadata_uri", [self.account, token_id, new_metadata_uri, {'in_top_x_mb': 5}])['result']

    async def issue_new_nft(self,
                            destination_address: str,
                            media_hash: str,
                            name: str,
                            description: str,
                            ticker: str,
                            creator: Optional[str] = '',
                            icon_uri: Optional[str] = '',
                            media_uri: Optional[str] = '',
                            additional_metadata_uri: Optional[str] = ''):
        output = self._write_command("token_nft_issue_new", [
            self.account,
            destination_address,
            {
                'media_hash': media_hash,
                'name': name,
                'description': description,
                'ticker': ticker,
                'creator': creator,
                'icon_uri': icon_uri,
                'media_uri': media_uri,
                'additional_metadata_uri': additional_metadata_uri
            },
            {'in_top_x_mb': 5}
            ])['result']
        return output

    async def create_stake_pool(self,
                                amount: int,
                                cost_per_block: int,
                                margin_ratio_per_thousand: float,
                                decommission_key: Optional[str] = None,
                                staker_addr: Optional[str] = None,
                                vrf_pub_key: Optional[str] = None) -> str:
        self._write_command(
            "staking_create_pool",
            [
                self.account,
                {'decimal': str(amount)},
                {'decimal': str(cost_per_block)},
                str(margin_ratio_per_thousand),
                decommission_key,
                staker_addr,
                vrf_pub_key,
                {'in_top_x_mb': 5}
            ]
        )['result']
        return "The transaction was submitted successfully"

    async def decommission_stake_pool(self, pool_id: str, address: str) -> str:
        self._write_command("staking_decommission_pool", [self.account, pool_id, address, {'in_top_x_mb': 5}])['result']
        return "The transaction was submitted successfully"

    async def submit_transaction(self, transaction: str, do_not_store: bool = False) -> str:
        result = self._write_command("node_submit_transaction", [transaction, do_not_store, {}])
        if 'result' in result:
            return f"The transaction was submitted successfully\n\n{result['result']['tx_id']}"
        else:
            return result['error']['message']

    async def list_pool_ids(self) -> List[PoolData]:
        pools = self._write_command("staking_list_pools", [self.account])['result']
        return [PoolData(pool['pool_id'], pool['pledge']['decimal'], pool['balance']['decimal']) for pool in pools]

    async def list_pools_for_decommission(self) -> List[PoolData]:
        pools = self._write_command("staking_list_owned_pools_for_decommission", [self.account])['result']
        return [PoolData(pool['pool_id'], pool['pledge'], pool['balance']) for pool in pools]

    async def list_created_blocks_ids(self) -> List[CreatedBlockInfo]:
        output = self._write_command("staking_list_created_block_ids", [self.account])['result']
        return [CreatedBlockInfo(block['id'], block['height'], block['pool_id']) for block in output]

    async def create_delegation(self, address: str, pool_id: str) -> Optional[str]:
        return self._write_command("delegation_create", [self.account, address, pool_id, {'in_top_x_mb': 5}])['result']['delegation_id']

    async def stake_delegation(self, amount: int, delegation_id: str) -> str:
        self._write_command("delegation_stake", [self.account, {'decimal': str(amount)}, delegation_id, {'in_top_x_mb': 5}])['result']
        return "Success"

    async def list_delegation_ids(self) -> List[DelegationData]:
        delegations = self._write_command("delegation_list_ids", [self.account])['result']
        return [DelegationData(delegation['delegation_id'], delegation['balance']['decimal']) for delegation in delegations]

    async def deposit_data(self, data: str) -> str:
        return self._write_command("address_deposit_data", [self.account, data, {'in_top_x_mb': 5}])['result']

    async def sync(self) -> str:
        self._write_command("wallet_sync")
        return "Success"

    async def start_staking(self) -> str:
        self._write_command("staking_start", [self.account])['result']
        return "Staking started successfully"

    async def stop_staking(self) -> str:
        self._write_command("staking_stop", [self.account])['result']
        return "Success"

    async def staking_status(self) -> str:
        result = self._write_command("staking_status", [self.account])['result']
        if result == "Staking":
            return "Staking"
        else:
            return "Not staking"

    async def get_addresses_usage(self, with_change: bool = False) -> str:
        return self._write_command("address_show", [self.account, with_change])['result']

    async def get_balance(self, with_locked: str = 'unlocked', utxo_states: List[str] = ['confirmed']) -> str:
        with_locked = with_locked.capitalize()
        result = self._write_command("account_balance", [self.account, [state.title() for state in utxo_states], with_locked])
        result = result['result']

        coins = result['coins']['decimal']
        tokens = {}

        if 'tokens' in result:
            for (hexified_token_id, balance) in result['tokens'].items():
                token_id_as_addr = self.node.test_functions_dehexify_all_addresses(hexified_token_id)
                tokens[token_id_as_addr] = balance['decimal']

        # Mimic the output of wallet_cli_controller's 'get_balance'
        return "\n".join([f"Coins amount: {coins}"] + [f"Token: {token} amount: {amount}" for token, amount in tokens.items()])

    async def new_vrf_public_key(self) -> str:
        result = self._write_command("staking_new_vrf_public_key", [self.account])
        return result['result']['vrf_public_key']

    async def list_pending_transactions(self) -> List[str]:
        output = self._write_command("transaction_list_pending", [self.account])['result']
        return output

    async def abandon_transaction(self, tx_id: str) -> str:
        return self._write_command("transaction_abandon", [self.account, tx_id])['result']

    async def sign_raw_transaction(self, transaction: str) -> str:
        result = self._write_command("account_sign_raw_transaction", [self.account, transaction, {'in_top_x_mb': 5}])
        if 'result' in result:
            if result['result']['is_complete']:
                return f"The transaction has been fully signed and is ready to be broadcast to network\n\n{result['result']['hex']}"
            else:
                return f"Not all transaction inputs have been signed. This wallet does not have all the keys for that.\
                             Pass the following string into the wallet that has appropriate keys for the inputs to sign what is left:\n\n{result['result']['hex']}"
        else:
            return result['error']['message']

    async def sign_raw_transaction_expect_fully_signed(self, transaction: str) -> str:
        output = await self.sign_raw_transaction(transaction)
        assert_in("The transaction has been fully signed and is ready to be broadcast to network", output)

        lines = [s for s in output.splitlines() if s.strip()]
        return lines[1]

    async def sign_challenge_plain(self, message: str, address: str) -> str:
        result = self._write_command('challenge_sign_plain', [self.account, message, address])
        if 'result' in result:
            return f"The generated hex encoded signature is\n\n{result['result']}"
        else:
            return result['error']['message']

    async def sign_challenge_hex(self, message: str, address: str) -> str:
        result =  self._write_command('challenge_sign_hex', [self.account, message, address])
        if 'result' in result:
            return f"The generated hex encoded signature is\n\n{result['result']}"
        else:
            return result['error']['message']

    async def verify_challenge_plain(self, message: str, signature: str, address: str) -> str:
        result = self._write_command('challenge_verify_plain', [message, signature, address])
        if 'result' in result:
            return f"The provided signature is correct"
        else:
            return result['error']['message']

    async def verify_challenge_hex(self, message: str, signature: str, address: str) -> str:
        result = self._write_command('challenge_verify_hex', [message, signature, address])
        if 'result' in result:
            return f"The provided signature is correct"
        else:
            return result['error']['message']

    async def create_from_cold_address(self, address: str, amount: int, selected_utxo: UtxoOutpoint, change_address: Optional[str] = None) -> str:
        utxo = to_json(selected_utxo)
        result = self._write_command("transaction_create_from_cold_input", [self.account, address, {'decimal': str(amount)}, utxo, change_address, {'in_top_x_mb': 5}])
        if 'result' in result:
            return f"Send transaction created\n\n{result['result']['hex']}"
        else:
            return result['error']['message']

    async def make_tx_to_send_tokens_from_multisig_address(self, from_address: str, outputs: List[TokenTxOutput], fee_change_addr: Optional[str]):
        outputs = [
            {
                "token_id": output.token_id,
                "amount": output.amount,
                "destination": f"HexifiedDestination{{0x{self.node.test_functions_address_to_destination(output.address)}}}"
            }
            for output in outputs
        ]

        result = self._write_command(
            "make_tx_to_send_tokens_from_multisig_address",
            [self.account, from_address, fee_change_addr, outputs, {'in_top_x_mb': 5}])

        return result['result']

    async def make_tx_to_send_tokens_from_multisig_address_expect_fully_signed(
            self, from_address: str, outputs: List[TokenTxOutput], fee_change_addr: Optional[str]):

        result = await self.make_tx_to_send_tokens_from_multisig_address(from_address, outputs, fee_change_addr)

        for sig_status in result['current_signatures']:
            assert sig_status['type'] == 'FullySigned'

        tx_as_partially_signed = result['transaction']
        signed_tx = self.node.test_functions_partially_signed_tx_to_signed_tx(tx_as_partially_signed)

        return signed_tx

    async def make_tx_to_send_tokens_from_multisig_address_expect_partially_signed(
            self, from_address: str, outputs: List[TokenTxOutput], fee_change_addr: Optional[str]):

        result = await self.make_tx_to_send_tokens_from_multisig_address(from_address, outputs, fee_change_addr)

        siginfo = sorted(result['current_signatures'],  key=itemgetter('type'))

        siginfo_to_return = []
        for (idx, status) in enumerate(siginfo):
            if status['type'] == 'PartialMultisig':
                content = status['content']
                siginfo_to_return.append(PartialSigInfo(idx, content['num_signatures'], content['required_signatures']))

        return (result['transaction'], siginfo_to_return)

    async def compose_transaction(self,
                                  outputs: List[TransferTxOutput],
                                  selected_utxos: List[UtxoOutpoint],
                                  htlc_secrets: Optional[List[Optional[str]]] = None,
                                  only_transaction: bool = False) -> str:
        utxos = [to_json(utxo) for utxo in selected_utxos]
        outputs = [to_json(output) for output in outputs]
        print(f"outputs = {outputs}")
        print(f"selected_utxos = {selected_utxos}")
        result = self._write_command('transaction_compose', [utxos, outputs, htlc_secrets, only_transaction])
        return result

    async def create_htlc_transaction(self,
                         amount: int,
                         token_id: Optional[str],
                         secret_hash: str,
                         spend_address: str,
                         refund_address: str,
                         refund_lock_for_blocks: int) -> NewTxResult:
        timelock = { "type": "ForBlockCount", "content": refund_lock_for_blocks }
        htlc = { "secret_hash": secret_hash, "spend_address": spend_address, "refund_address": refund_address, "refund_timelock": timelock }
        object = [self.account, {'decimal': str(amount)}, token_id, htlc, {'in_top_x_mb': 5}]
        result = self._write_command("create_htlc_transaction", object)
        return result['result']

    async def create_order(self,
                         ask_token_id: Optional[str],
                         ask_amount: int,
                         give_token_id: Optional[str],
                         give_amount: int,
                         conclude_address: str) -> str:
        if ask_token_id is not None:
            ask = {"type": "Token", "content": {"id": ask_token_id, "amount": {'decimal': str(ask_amount)}}}
        else:
            ask = {"type": "Coin", "content": {"amount": {'decimal': str(ask_amount)}}}

        if give_token_id is not None:
            give = {"type": "Token", "content": {"id": give_token_id, "amount": {'decimal': str(give_amount)}}}
        else:
            give = {"type": "Coin", "content": {"amount": {'decimal': str(give_amount)}}}

        object = [self.account, ask, give, conclude_address, {'in_top_x_mb': 5}]
        result = self._write_command("create_order", object)
        return result

    async def fill_order(self,
                         order_id: str,
                         fill_amount: int,
                         output_address: Optional[str] = None) -> str:
        object = [self.account, order_id, {'decimal': str(fill_amount)}, output_address, {'in_top_x_mb': 5}]
        result = self._write_command("fill_order", object)
        return result

    async def freeze_order(self, order_id: str) -> str:
        object = [self.account, order_id, {'in_top_x_mb': 5}]
        result = self._write_command("freeze_order", object)
        return result

    async def conclude_order(self,
                         order_id: str,
                         output_address: Optional[str] = None) -> str:
        object = [self.account, order_id, output_address, {'in_top_x_mb': 5}]
        result = self._write_command("conclude_order", object)
        return result
