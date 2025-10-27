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
  Amount,
  encode_input_for_utxo,
  encode_lock_until_height,
  encode_multisig_challenge,
  encode_output_htlc,
  encode_signed_transaction,
  encode_transaction,
  encode_witness_htlc_refund_multisig,
  encode_witness_htlc_refund_single_sig,
  encode_witness_htlc_spend,
  extract_htlc_secret,
  internal_verify_witness,
  make_default_account_privkey,
  make_receiving_address,
  multisig_challenge_to_address,
  pubkey_to_pubkeyhash_address,
  public_key_from_private_key,
  Network,
  SignatureHashType,
} from "../../pkg/wasm_wrappers.js";

import {
  assert_eq_arrays,
  get_err_msg
} from "./utils.js";

import {
  HTLC_SECRET,
  HTLC_SECRET_HASH,
  MNEMONIC,
  RANDOM_HEIGHT,
  TOKEN_ID,
} from "./defs.js";
import {
  TX_OUTPOINT_INDEX,
  TX_OUTPOINT_SOURCE_ID,
} from "./test_encode_other_inputs.js";
import {
  OUTPUTS,
} from "./test_encode_other_outputs.js";

export function test_htlc() {
  const account_privkey = make_default_account_privkey(
    MNEMONIC,
    Network.Testnet
  );
  const priv_key1 = make_receiving_address(account_privkey, 0);
  const pub_key1 = public_key_from_private_key(priv_key1);
  const addr1 = pubkey_to_pubkeyhash_address(pub_key1, Network.Testnet);

  const priv_key2 = make_receiving_address(account_privkey, 2);
  const pub_key2 = public_key_from_private_key(priv_key2);
  const addr2 = pubkey_to_pubkeyhash_address(pub_key2, Network.Testnet);

  const multisig_challenge = encode_multisig_challenge(Uint8Array.from([...pub_key1, ...pub_key2]), 2, Network.Testnet);
  const multisig_addr = multisig_challenge_to_address(multisig_challenge, Network.Testnet);

  const tx_input = encode_input_for_utxo(TX_OUTPOINT_SOURCE_ID, TX_OUTPOINT_INDEX);
  const tx = encode_transaction(tx_input, Uint8Array.from(OUTPUTS), BigInt(0));

  for (const token of [null, TOKEN_ID]) {
    for (const refund_to_multisig of [true, false]) {
      console.log(`Testing htlc, token = ${token}, refund_to_multisig = ${refund_to_multisig}`);

      const refund_addr = refund_to_multisig ? multisig_addr : addr2;
      const htlc_output = encode_output_htlc(
        Amount.from_atoms("40000"),
        token,
        HTLC_SECRET_HASH,
        addr1,
        refund_addr,
        encode_lock_until_height(BigInt(100)),
        Network.Testnet
      );

      console.log("Htlc encoded successfully");

      const opt_utxos = Uint8Array.from([1, ...htlc_output]);

      const witness_with_htlc_spend = encode_witness_htlc_spend(
        SignatureHashType.ALL,
        priv_key1,
        addr1,
        tx,
        opt_utxos,
        0,
        Uint8Array.from(HTLC_SECRET),
        { pool_info: {}, order_info: {} },
        BigInt(RANDOM_HEIGHT),
        Network.Testnet
      );

      console.log("Witness with htlc spend encoded successfully");

      internal_verify_witness(
        SignatureHashType.ALL,
        null,
        witness_with_htlc_spend,
        tx,
        opt_utxos,
        0,
        { pool_info: {}, order_info: {} },
        BigInt(RANDOM_HEIGHT),
        Network.Testnet
      );

      console.log("Witness with htlc spend verified successfully");

      const htlc_signed_tx = encode_signed_transaction(tx, Uint8Array.from([...witness_with_htlc_spend]));

      const secret_extracted = extract_htlc_secret(htlc_signed_tx, true, TX_OUTPOINT_SOURCE_ID, TX_OUTPOINT_INDEX);
      assert_eq_arrays(HTLC_SECRET, secret_extracted);

      console.log("Htlc secret extracted successfully");

      try {
        extract_htlc_secret(htlc_signed_tx, true, TX_OUTPOINT_SOURCE_ID, TX_OUTPOINT_INDEX + 1)
        throw new Error("Extracting the Htlc secret using wrong utxo outpoint worked somehow!");
      } catch (e) {
        if (
          !get_err_msg(e).includes("No input outpoint found in transaction")
        ) {
          throw e;
        }
      }

      console.log("Invalid htlc secret extraction tested successfully");

      if (refund_to_multisig) {
        const partial_witness_with_htlc_refund = encode_witness_htlc_refund_multisig(
          SignatureHashType.ALL,
          priv_key1,
          0,
          new Uint8Array([]),
          multisig_challenge,
          tx,
          opt_utxos,
          0,
          { pool_info: {}, order_info: {} },
          BigInt(RANDOM_HEIGHT),
          Network.Testnet
        );

        console.log("Partial witness with htlc refund encoded successfully");

        const witness_with_htlc_refund = encode_witness_htlc_refund_multisig(
          SignatureHashType.ALL,
          priv_key2,
          1,
          partial_witness_with_htlc_refund,
          multisig_challenge,
          tx,
          opt_utxos,
          0,
          { pool_info: {}, order_info: {} },
          BigInt(RANDOM_HEIGHT),
          Network.Testnet
        );

        console.log("Witness with htlc refund encoded successfully");

        internal_verify_witness(
          SignatureHashType.ALL,
          null,
          witness_with_htlc_refund,
          tx,
          opt_utxos,
          0,
          { pool_info: {}, order_info: {} },
          BigInt(RANDOM_HEIGHT),
          Network.Testnet
        );

        console.log("Witness with htlc refund verified successfully");
      } else {
        const witness_with_htlc_refund = encode_witness_htlc_refund_single_sig(
          SignatureHashType.ALL,
          priv_key2,
          addr2,
          tx,
          opt_utxos,
          0,
          { pool_info: {}, order_info: {} },
          BigInt(RANDOM_HEIGHT),
          Network.Testnet
        );

        console.log("Witness with htlc refund encoded successfully");

        internal_verify_witness(
          SignatureHashType.ALL,
          null,
          witness_with_htlc_refund,
          tx,
          opt_utxos,
          0,
          { pool_info: {}, order_info: {} },
          BigInt(RANDOM_HEIGHT),
          Network.Testnet
        );

        console.log("Witness with htlc refund verified successfully");
      }
    }
  }
}
