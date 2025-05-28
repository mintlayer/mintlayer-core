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
  encode_signed_transaction,
  encode_transaction,
  encode_witness,
  encode_witness_no_signature,
  estimate_transaction_size,
  make_default_account_privkey,
  make_receiving_address,
  Network,
  SignatureHashType,
} from "../../pkg/wasm_wrappers.js";

import {
  assert_eq_arrays,
  get_err_msg,
  TEXT_ENCODER,
} from "./utils.js";

import {
  MNEMONIC,
} from "./defs.js";
import {
  ADDRESS
} from "./test_address_generation.js";
import {
  INPUTS,
} from "./test_encode_other_inputs.js";
import {
  OUTPUTS,
  OUTPUT_CREATE_STAKE_POOL,
  OUTPUT_LOCK_THEN_TRANSFER,
} from "./test_encode_other_outputs.js";

export function test_transaction_and_witness_encoding() {
  const account_pubkey = make_default_account_privkey(
    MNEMONIC,
    Network.Testnet
  );
  const receiving_privkey = make_receiving_address(account_pubkey, 0);

  try {
    const invalid_inputs = TEXT_ENCODER.encode("invalid inputs");
    encode_transaction(invalid_inputs, Uint8Array.from(OUTPUTS), BigInt(0));
    throw new Error("Invalid inputs worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Invalid transaction input encoding")) {
      throw e;
    }
    console.log("Tested invalid inputs successfully");
  }

  try {
    const invalid_outputs = TEXT_ENCODER.encode("invalid outputs");
    encode_transaction(Uint8Array.from(INPUTS), invalid_outputs, BigInt(0));
    throw new Error("Invalid outputs worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Invalid transaction output encoding")) {
      throw e;
    }
    console.log("Tested invalid outputs successfully");
  }

  const tx = encode_transaction(Uint8Array.from(INPUTS), Uint8Array.from(OUTPUTS), BigInt(0));
  const expected_tx = [
    1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 4, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 4, 8, 1, 0, 145, 1, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41, 193, 30,
    91, 4, 195, 202, 103, 207, 80, 217, 178, 0, 145, 1, 3, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 2, 113, 2, 0, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41, 193, 30, 91,
    4, 195, 202, 103, 207, 80, 217, 178, 0, 108, 245, 234, 97, 170, 9, 247,
    158, 169, 100, 84, 123, 235, 183, 147, 29, 136, 118, 203, 24, 146, 56, 60,
    217, 2, 198, 32, 133, 255, 240, 84, 123, 1, 91, 58, 110, 176, 100, 207, 6,
    194, 41, 193, 30, 91, 4, 195, 202, 103, 207, 80, 217, 178, 100, 0, 0,
  ];
  assert_eq_arrays(tx, expected_tx);
  console.log("tx encoding ok");

  const witness = encode_witness_no_signature();
  const expected_no_signature_witness = [0, 0];
  assert_eq_arrays(witness, expected_no_signature_witness);
  console.log("empty witness encoding ok");

  const opt_utxos = [1, ...OUTPUT_LOCK_THEN_TRANSFER, 1, ...OUTPUT_CREATE_STAKE_POOL];

  try {
    const invalid_private_key = TEXT_ENCODER.encode("invalid private key");
    encode_witness(
      SignatureHashType.ALL,
      invalid_private_key,
      ADDRESS,
      tx,
      Uint8Array.from(opt_utxos),
      0,
      Network.Testnet
    );
    throw new Error("Invalid private key worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Invalid private key encoding")) {
      throw e;
    }
    console.log("Tested invalid private key in encode witness successfully");
  }
  try {
    const invalid_address = "invalid address";
    encode_witness(
      SignatureHashType.ALL,
      receiving_privkey,
      invalid_address,
      tx,
      Uint8Array.from(opt_utxos),
      0,
      Network.Testnet
    );
    throw new Error("Invalid address worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Invalid addressable")) {
      throw e;
    }
    console.log("Tested invalid address in encode witness successfully");
  }
  try {
    const invalid_tx = TEXT_ENCODER.encode("invalid tx");
    encode_witness(
      SignatureHashType.ALL,
      receiving_privkey,
      ADDRESS,
      invalid_tx,
      Uint8Array.from(opt_utxos),
      0,
      Network.Testnet
    );
    throw new Error("Invalid transaction worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Invalid transaction encoding")) {
      throw e;
    }
    console.log("Tested invalid transaction in encode witness successfully");
  }
  try {
    const invalid_utxos = TEXT_ENCODER.encode("invalid utxos");
    encode_witness(
      SignatureHashType.ALL,
      receiving_privkey,
      ADDRESS,
      tx,
      invalid_utxos,
      0,
      Network.Testnet
    );
    throw new Error("Invalid utxo worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Invalid transaction input utxo encoding")) {
      throw e;
    }
    console.log("Tested invalid utxo in encode witness successfully");
  }
  try {
    const invalid_utxos_count = Uint8Array.from([0]);
    encode_witness(
      SignatureHashType.ALL,
      receiving_privkey,
      ADDRESS,
      tx,
      invalid_utxos_count,
      0,
      Network.Testnet
    );
    throw new Error("Invalid utxo worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Utxos count does not match inputs count")) {
      throw e;
    }
    console.log("Tested invalid utxo count in encode witness successfully");
  }
  try {
    const invalid_input_idx = 999;
    encode_witness(
      SignatureHashType.ALL,
      receiving_privkey,
      ADDRESS,
      tx,
      Uint8Array.from(opt_utxos),
      invalid_input_idx,
      Network.Testnet
    );
    throw new Error("Invalid address worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Invalid input index")) {
      throw e;
    }
    console.log("Tested invalid input index in encode witness successfully");
  }
  // all ok
  encode_witness(
    SignatureHashType.ALL,
    receiving_privkey,
    ADDRESS,
    tx,
    Uint8Array.from(opt_utxos),
    0,
    Network.Testnet
  );

  // as signatures are random, hardcode one so we can test the encodings for the signed transaction
  const random_witness2 = [
    1, 1, 141, 1, 0, 2, 227, 252, 33, 195, 223, 44, 38, 35, 73, 145, 212, 180,
    49, 115, 4, 150, 204, 250, 205, 123, 131, 201, 114, 130, 186, 209, 98,
    181, 118, 233, 133, 89, 0, 99, 87, 109, 227, 15, 21, 164, 83, 151, 14,
    235, 106, 83, 230, 40, 64, 146, 112, 52, 103, 203, 31, 216, 54, 141, 223,
    27, 175, 133, 164, 172, 239, 122, 121, 17, 88, 114, 99, 6, 19, 220, 156,
    167, 40, 17, 211, 196, 45, 209, 111, 170, 161, 2, 254, 122, 169, 127, 235,
    158, 62, 127, 177, 12, 228,
  ];

  try {
    const invalid_witnesses = TEXT_ENCODER.encode("invalid witnesses");
    encode_signed_transaction(tx, invalid_witnesses);
    throw new Error("Invalid witnesses worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Invalid transaction witness encoding")) {
      throw e;
    }
    console.log("Tested invalid witnesses successfully");
  }

  try {
    encode_signed_transaction(tx, witness);
    throw new Error("Invalid number of witnesses worked somehow!");
  } catch (e) {
    if (
      !get_err_msg(e).includes(
        "The number of signatures does not match the number of inputs"
      )
    ) {
      throw e;
    }
    console.log("Tested invalid number of witnesses successfully");
  }

  try {
    const invalid_tx = TEXT_ENCODER.encode("invalid tx");
    encode_signed_transaction(invalid_tx, witness);
    throw new Error("Invalid transaction worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Invalid transaction encoding")) {
      throw e;
    }
    console.log("Tested invalid transaction successfully");
  }

  let witnesses = [...random_witness2, ...random_witness2];
  const signed_tx = encode_signed_transaction(tx, Uint8Array.from(witnesses));
  const expected_signed_tx = [
    1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 4, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 4, 8, 1, 0, 145, 1, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41, 193, 30,
    91, 4, 195, 202, 103, 207, 80, 217, 178, 0, 145, 1, 3, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 2, 113, 2, 0, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41, 193, 30, 91,
    4, 195, 202, 103, 207, 80, 217, 178, 0, 108, 245, 234, 97, 170, 9, 247,
    158, 169, 100, 84, 123, 235, 183, 147, 29, 136, 118, 203, 24, 146, 56, 60,
    217, 2, 198, 32, 133, 255, 240, 84, 123, 1, 91, 58, 110, 176, 100, 207, 6,
    194, 41, 193, 30, 91, 4, 195, 202, 103, 207, 80, 217, 178, 100, 0, 0, 8,
    1, 1, 141, 1, 0, 2, 227, 252, 33, 195, 223, 44, 38, 35, 73, 145, 212, 180,
    49, 115, 4, 150, 204, 250, 205, 123, 131, 201, 114, 130, 186, 209, 98,
    181, 118, 233, 133, 89, 0, 99, 87, 109, 227, 15, 21, 164, 83, 151, 14,
    235, 106, 83, 230, 40, 64, 146, 112, 52, 103, 203, 31, 216, 54, 141, 223,
    27, 175, 133, 164, 172, 239, 122, 121, 17, 88, 114, 99, 6, 19, 220, 156,
    167, 40, 17, 211, 196, 45, 209, 111, 170, 161, 2, 254, 122, 169, 127, 235,
    158, 62, 127, 177, 12, 228, 1, 1, 141, 1, 0, 2, 227, 252, 33, 195, 223,
    44, 38, 35, 73, 145, 212, 180, 49, 115, 4, 150, 204, 250, 205, 123, 131,
    201, 114, 130, 186, 209, 98, 181, 118, 233, 133, 89, 0, 99, 87, 109, 227,
    15, 21, 164, 83, 151, 14, 235, 106, 83, 230, 40, 64, 146, 112, 52, 103,
    203, 31, 216, 54, 141, 223, 27, 175, 133, 164, 172, 239, 122, 121, 17, 88,
    114, 99, 6, 19, 220, 156, 167, 40, 17, 211, 196, 45, 209, 111, 170, 161,
    2, 254, 122, 169, 127, 235, 158, 62, 127, 177, 12, 228,
  ];
  assert_eq_arrays(signed_tx, expected_signed_tx);

  const estimated_size = estimate_transaction_size(
    Uint8Array.from(INPUTS),
    [ADDRESS, ADDRESS],
    Uint8Array.from(OUTPUTS),
    Network.Testnet
  );
  if (estimated_size != expected_signed_tx.length) {
    throw new Error("wrong estimated size");
  }
  console.log(
    `estimated size ${estimated_size} vs real ${expected_signed_tx.length}`
  );
}
