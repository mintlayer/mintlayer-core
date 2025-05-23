// Copyright (c) 2021-2025 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import {
  make_private_key,
  public_key_from_private_key,
  make_default_account_privkey,
  make_receiving_address,
  Network,
  encode_transaction,
  encode_signed_transaction,
  encode_lock_until_height,
  encode_output_htlc,
  encode_witness_htlc_secret,
  encode_multisig_challenge,
  encode_witness_htlc_multisig,
  extract_htlc_secret,
  SignatureHashType,
  Amount,
} from "../../pkg/wasm_wrappers.js";

import {
  assert_eq_arrays
} from "./utils.js";

import {
  MNEMONIC,
  TOKEN_ID,
} from "./defs.js";
import {
  ADDRESS
} from "./test_address_generation.js";
import {
  INPUTS,
  TX_OUTPOINT,
} from "./test_encode_other_inputs.js";
import {
  OUTPUTS,
} from "./test_encode_other_outputs.js";

export async function test_htlc() {
  const account_pubkey = make_default_account_privkey(
    MNEMONIC,
    Network.Testnet
  );
  const receiving_privkey = make_receiving_address(account_pubkey, 0);

  const secret = [0, 229, 233, 72, 110, 22, 64, 36, 69, 188, 238, 51, 130, 168, 185, 241, 73, 48, 120, 151, 140, 45, 46, 39, 50, 207, 18, 50, 243, 30, 115, 93]
  const secret_hash = "b5a48c7780e597de8012346fb30761965248e3f2"

  const htlc_coins_output = encode_output_htlc(
    Amount.from_atoms("40000"),
    undefined,
    secret_hash,
    ADDRESS,
    ADDRESS,
    encode_lock_until_height(BigInt(100)),
    Network.Testnet
  );
  console.log("htlc with coins encoding ok");

  const htlc_tokens_output = encode_output_htlc(
    Amount.from_atoms("40000"),
    TOKEN_ID,
    secret_hash,
    ADDRESS,
    ADDRESS,
    encode_lock_until_height(BigInt(100)),
    Network.Testnet
  );
  console.log("htlc with tokens encoding ok");

  const opt_htlc_utxos = [1, ...htlc_coins_output, 1, ...htlc_tokens_output];
  const tx = encode_transaction(Uint8Array.from(INPUTS), Uint8Array.from(OUTPUTS), BigInt(0));
  // encode witness with secret
  const witness_with_htlc_secret = encode_witness_htlc_secret(
    SignatureHashType.ALL,
    receiving_privkey,
    ADDRESS,
    tx,
    Uint8Array.from(opt_htlc_utxos),
    0,
    Uint8Array.from(secret),
    Network.Testnet
  );
  console.log("Tested encode witness with htlc secret successfully");

  // encode multisig challenge
  const alice_sk = make_private_key();
  const alice_pk = public_key_from_private_key(alice_sk);
  const bob_sk = make_private_key();
  const bob_pk = public_key_from_private_key(bob_sk);
  let challenge = encode_multisig_challenge(Uint8Array.from([...alice_pk, ...bob_pk]), 2, Network.Testnet);
  console.log("Tested multisig challenge successfully");

  // encode mutlisig witness
  const witness_with_htlc_multisig_1 = encode_witness_htlc_multisig(
    SignatureHashType.ALL,
    alice_sk,
    0,
    new Uint8Array([]),
    challenge,
    tx,
    Uint8Array.from(opt_htlc_utxos),
    1,
    Network.Testnet
  );
  console.log("Tested encode multisig witness 0 successfully");

  const witness_with_htlc_multisig = encode_witness_htlc_multisig(
    SignatureHashType.ALL,
    bob_sk,
    1,
    witness_with_htlc_multisig_1,
    challenge,
    tx,
    Uint8Array.from(opt_htlc_utxos),
    1,
    Network.Testnet
  );
  console.log("Tested encode multisig witness 1 successfully");

  // encode signed tx with secret and multi
  const htlc_signed_tx = encode_signed_transaction(tx, Uint8Array.from([...witness_with_htlc_secret, ...witness_with_htlc_multisig]));
  // extract secret from signed tx
  const secret_extracted = extract_htlc_secret(htlc_signed_tx, true, TX_OUTPOINT, 1);
  assert_eq_arrays(secret, secret_extracted);
}
