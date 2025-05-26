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

// Here we test outputs encoding, except for orders and htlcs, which have their separate test files.

import {
  public_key_from_private_key,
  make_default_account_privkey,
  make_receiving_address,
  Network,
  encode_output_coin_burn,
  encode_output_token_burn,
  encode_lock_until_height,
  encode_output_token_transfer,
  encode_output_lock_then_transfer,
  encode_output_token_lock_then_transfer,
  encode_stake_pool_data,
  encode_output_create_stake_pool,
  Amount,
  TotalSupply,
  FreezableToken,
  encode_output_issue_nft,
  encode_output_issue_fungible_token,
} from "../../pkg/wasm_wrappers.js";

import {
  TEXT_ENCODER,
  assert_eq_arrays,
  run_one_test,
  get_err_msg
} from "./utils.js";

import {
  MNEMONIC,
  POOL_ID,
  TOKEN_ID,
} from "./defs.js";
import { ADDRESS } from "./test_address_generation.js";

export const OUTPUT_LOCK_THEN_TRANSFER = [
  1, 0, 145, 1, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41, 193, 30, 91, 4,
  195, 202, 103, 207, 80, 217, 178, 0, 145, 1
];

export const OUTPUT_CREATE_STAKE_POOL = [
  3, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
  113, 2, 0, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41, 193, 30, 91, 4, 195,
  202, 103, 207, 80, 217, 178, 0, 108, 245, 234, 97, 170, 9, 247, 158, 169,
  100, 84, 123, 235, 183, 147, 29, 136, 118, 203, 24, 146, 56, 60, 217, 2,
  198, 32, 133, 255, 240, 84, 123, 1, 91, 58, 110, 176, 100, 207, 6, 194,
  41, 193, 30, 91, 4, 195, 202, 103, 207, 80, 217, 178, 100, 0, 0,
];

// Some tx outputs - LockThenTransfer and CreateStakePool
export const OUTPUTS = [...OUTPUT_LOCK_THEN_TRANSFER, ...OUTPUT_CREATE_STAKE_POOL];

export async function test_encode_other_outputs() {
  run_one_test(create_stake_pool_test);
  run_one_test(stake_pool_data_test);
  run_one_test(coin_burn_test);
  run_one_test(token_burn_test);
  run_one_test(lock_then_transfer_test);
  run_one_test(token_lock_then_transfer_test);
  run_one_test(token_transfer_test);
  run_one_test(issue_fungible_token_test);
  run_one_test(issue_nft_test);
}

async function create_stake_pool_test() {
  const vrf_public_key =
    "tvrfpk1qpk0t6np4gyl084fv328h6ahjvwcsaktrzfrs0xeqtrzpp0l7p28knrnn57";

  const pool_data = encode_stake_pool_data(
    Amount.from_atoms("40000"),
    ADDRESS,
    vrf_public_key,
    ADDRESS,
    100,
    Amount.from_atoms("0"),
    Network.Testnet
  );
  const expected_pool_data = [
    2, 113, 2, 0, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41, 193, 30, 91, 4,
    195, 202, 103, 207, 80, 217, 178, 0, 108, 245, 234, 97, 170, 9, 247, 158,
    169, 100, 84, 123, 235, 183, 147, 29, 136, 118, 203, 24, 146, 56, 60, 217,
    2, 198, 32, 133, 255, 240, 84, 123, 1, 91, 58, 110, 176, 100, 207, 6, 194,
    41, 193, 30, 91, 4, 195, 202, 103, 207, 80, 217, 178, 100, 0, 0,
  ];

  assert_eq_arrays(pool_data, expected_pool_data);

  const lock = encode_lock_until_height(BigInt(100));
  const output = encode_output_lock_then_transfer(
    Amount.from_atoms("100"),
    ADDRESS,
    lock,
    Network.Testnet
  );

  try {
    const invalid_pool_data = TEXT_ENCODER.encode("invalid pool data");
    encode_output_create_stake_pool(
      POOL_ID,
      invalid_pool_data,
      Network.Testnet
    );
    throw new Error("Invalid pool data worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Invalid stake pool data encoding")) {
      throw e;
    }
    console.log("Tested invalid pool data successfully");
  }
  const stake_pool_output = encode_output_create_stake_pool(
    POOL_ID,
    pool_data,
    Network.Testnet
  );
  const outputs = [...output, ...stake_pool_output];

  assert_eq_arrays(outputs, OUTPUTS);
}

async function stake_pool_data_test() {
  const vrf_public_key =
    "tvrfpk1qpk0t6np4gyl084fv328h6ahjvwcsaktrzfrs0xeqtrzpp0l7p28knrnn57";

  try {
    const invalid_margin_ratio_per_thousand = 2000;
    encode_stake_pool_data(
      Amount.from_atoms("40000"),
      ADDRESS,
      vrf_public_key,
      ADDRESS,
      invalid_margin_ratio_per_thousand,
      Amount.from_atoms("0"),
      Network.Testnet
    );
    throw new Error("Invalid margin_ratio_per_thousand worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Invalid per thousand 2000, valid range is [0, 1000]")) {
      throw e;
    }
    console.log("Tested invalid margin_ratio_per_thousand successfully");
  }
}

async function coin_burn_test() {
  try {
    encode_output_coin_burn(Amount.from_atoms("invalid amount"));
    throw new Error("Invalid value for amount worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Invalid atoms amount")) {
      throw e;
    }
    console.log("Tested invalid amount successfully");
  }
}

async function token_burn_test() {
  try {
    encode_output_token_burn(
      Amount.from_atoms("invalid amount"),
      TOKEN_ID,
      Network.Testnet
    );
    throw new Error("Invalid value for amount worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Invalid atoms amount")) {
      throw e;
    }
    console.log("Tested invalid amount successfully");
  }
  try {
    const invalid_token_id = "asd";
    encode_output_token_burn(
      Amount.from_atoms("100"),
      invalid_token_id,
      Network.Testnet
    );
    throw new Error("Invalid token id worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Invalid addressable")) {
      throw e;
    }
    console.log("Tested invalid token id successfully for token burn");
  }

  const token_burn = encode_output_token_burn(
    Amount.from_atoms("100"),
    TOKEN_ID,
    Network.Testnet
  );
  const expected_token_burn = [
    2, 2, 162, 208, 145, 194, 165, 27, 14, 118, 31, 139, 199, 254, 11, 190,
    108, 15, 64, 180, 50, 106, 211, 26, 107, 242, 121, 29, 55, 172, 185, 5,
    196, 119, 145, 1,
  ];
  assert_eq_arrays(token_burn, expected_token_burn);
}

async function lock_then_transfer_test() {
  try {
    const invalid_lock = TEXT_ENCODER.encode("invalid lock");
    encode_output_lock_then_transfer(
      Amount.from_atoms("100"),
      ADDRESS,
      invalid_lock,
      Network.Testnet
    );
    throw new Error("Invalid lock worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Invalid time lock encoding")) {
      throw e;
    }
    console.log("Tested invalid lock successfully");
  }
}

async function token_lock_then_transfer_test() {
  try {
    const invalid_lock = TEXT_ENCODER.encode("invalid lock");
    encode_output_token_lock_then_transfer(
      Amount.from_atoms("100"),
      ADDRESS,
      TOKEN_ID,
      invalid_lock,
      Network.Testnet
    );
    throw new Error("Invalid lock worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Invalid time lock encoding")) {
      throw e;
    }
    console.log("Tested invalid token lock successfully");
  }

  try {
    const invalid_token_id = "asd";
    const lock = encode_lock_until_height(BigInt(100));
    encode_output_token_lock_then_transfer(
      Amount.from_atoms("100"),
      ADDRESS,
      invalid_token_id,
      lock,
      Network.Testnet
    );
    throw new Error("Invalid token id worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Invalid addressable")) {
      throw e;
    }
    console.log("Tested invalid token id successfully");
  }

  const lock = encode_lock_until_height(BigInt(100));

  const token_lock_transfer_out = encode_output_token_lock_then_transfer(
    Amount.from_atoms("100"),
    ADDRESS,
    TOKEN_ID,
    lock,
    Network.Testnet
  );
  const expected_token_lock_transfer_out = [
    1, 2, 162, 208, 145, 194, 165, 27, 14, 118, 31, 139, 199, 254, 11, 190,
    108, 15, 64, 180, 50, 106, 211, 26, 107, 242, 121, 29, 55, 172, 185, 5,
    196, 119, 145, 1, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41, 193, 30, 91,
    4, 195, 202, 103, 207, 80, 217, 178, 0, 145, 1,
  ];
  assert_eq_arrays(token_lock_transfer_out, expected_token_lock_transfer_out);
}

async function token_transfer_test() {
  try {
    const invalid_address = "invalid address";
    encode_output_token_transfer(
      Amount.from_atoms("100"),
      invalid_address,
      TOKEN_ID,
      Network.Testnet
    );
    throw new Error("Invalid address worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Invalid addressable")) {
      throw e;
    }
    console.log(
      "Tested invalid address in encode output token transfer successfully"
    );
  }

  try {
    const invalid_token_id = "invalid token";
    encode_output_token_transfer(
      Amount.from_atoms("100"),
      ADDRESS,
      invalid_token_id,
      Network.Testnet
    );
    throw new Error("Invalid token id worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Invalid addressable")) {
      throw e;
    }
    console.log(
      "Tested invalid token id successfully in output token transfer"
    );
  }

  const token_transfer_out = encode_output_token_transfer(
    Amount.from_atoms("100"),
    ADDRESS,
    TOKEN_ID,
    Network.Testnet
  );
  const expected_token_transfer_out = [
    0, 2, 162, 208, 145, 194, 165, 27, 14, 118, 31, 139, 199, 254, 11, 190,
    108, 15, 64, 180, 50, 106, 211, 26, 107, 242, 121, 29, 55, 172, 185, 5,
    196, 119, 145, 1, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41, 193, 30, 91,
    4, 195, 202, 103, 207, 80, 217, 178,
  ];

  assert_eq_arrays(token_transfer_out, expected_token_transfer_out);
}

async function issue_fungible_token_test() {
  let encoded_fungible_token = encode_output_issue_fungible_token(
    ADDRESS,
    "XXX",
    "http://uri.com",
    2,
    TotalSupply.Unlimited,
    null,
    FreezableToken.Yes,
    BigInt(1),
    Network.Testnet
  );

  const expected_fungible_token = [
    7, 1, 12, 88, 88, 88, 2, 56, 104, 116,
    116, 112, 58, 47, 47, 117, 114, 105, 46, 99,
    111, 109, 2, 1, 91, 58, 110, 176, 100, 207,
    6, 194, 41, 193, 30, 91, 4, 195, 202, 103,
    207, 80, 217, 178, 1
  ];

  assert_eq_arrays(encoded_fungible_token, expected_fungible_token);
}

async function issue_nft_test() {
  const account_pubkey = make_default_account_privkey(
    MNEMONIC,
    Network.Testnet
  );
  const receiving_privkey = make_receiving_address(account_pubkey, 0);
  const receiving_pubkey = public_key_from_private_key(receiving_privkey);

  let encoded_nft = encode_output_issue_nft(
    TOKEN_ID,
    ADDRESS,
    "nft",
    "XXX",
    "desc",
    Uint8Array.from([1, 2, 3, 4]),
    receiving_pubkey,
    "http://uri",
    "http://icon",
    "http://foo",
    BigInt(1),
    Network.Testnet
  );

  const expected_nft_encoding = [
    8, 162, 208, 145, 194, 165, 27, 14, 118, 31, 139, 199,
    254, 11, 190, 108, 15, 64, 180, 50, 106, 211, 26, 107,
    242, 121, 29, 55, 172, 185, 5, 196, 119, 0, 1, 0,
    2, 227, 252, 33, 195, 223, 44, 38, 35, 73, 145, 212,
    180, 49, 115, 4, 150, 204, 250, 205, 123, 131, 201, 114,
    130, 186, 209, 98, 181, 118, 233, 133, 89, 12, 110, 102,
    116, 16, 100, 101, 115, 99, 12, 88, 88, 88, 44, 104,
    116, 116, 112, 58, 47, 47, 105, 99, 111, 110, 40, 104,
    116, 116, 112, 58, 47, 47, 102, 111, 111, 40, 104, 116,
    116, 112, 58, 47, 47, 117, 114, 105, 16, 1, 2, 3,
    4, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41, 193,
    30, 91, 4, 195, 202, 103, 207, 80, 217, 178
  ];

  assert_eq_arrays(encoded_nft, expected_nft_encoding);

  try {
    const invalid_token_id = "asd";
    encode_output_issue_nft(
      invalid_token_id,
      ADDRESS,
      "nft",
      "XXX",
      "desc",
      Uint8Array.from([1, 2, 3, 4, 5]),
      undefined,
      undefined,
      undefined,
      undefined,
      BigInt(1),
      Network.Testnet
    );
    throw new Error("Invalid token id worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Invalid addressable")) {
      throw e;
    }
    console.log("Tested invalid token id successfully");
  }

  try {
    const creator_public_key_hash = Uint8Array.from([1, 2, 3, 4, 5]);
    encode_output_issue_nft(
      TOKEN_ID,
      ADDRESS,
      "nft",
      "XXX",
      "desc",
      Uint8Array.from([1, 2, 3]),
      creator_public_key_hash,
      undefined,
      undefined,
      undefined,
      BigInt(1),
      Network.Testnet
    );
    throw new Error("Invalid creator worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Cannot decode NFT creator as a public key")) {
      throw e;
    }
    console.log("Tested invalid creator successfully");
  }

  try {
    const empty_ticker = "";
    encode_output_issue_nft(
      TOKEN_ID,
      ADDRESS,
      "nft",
      empty_ticker,
      "desc",
      Uint8Array.from([1, 2, 3]),
      undefined,
      undefined,
      undefined,
      undefined,
      BigInt(1),
      Network.Testnet
    );
    throw new Error("Invalid ticker worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Invalid ticker length")) {
      throw e;
    }
    console.log("Tested invalid ticker successfully");
  }

  try {
    const empty_name = "";
    encode_output_issue_nft(
      TOKEN_ID,
      ADDRESS,
      empty_name,
      "xxx",
      "desc",
      Uint8Array.from([1, 2, 3]),
      undefined,
      undefined,
      undefined,
      undefined,
      BigInt(1),
      Network.Testnet
    );
    throw new Error("Invalid name worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Invalid name length")) {
      throw e;
    }
    console.log("Tested invalid name successfully");
  }

  try {
    const empty_description = "";
    encode_output_issue_nft(
      TOKEN_ID,
      ADDRESS,
      "name",
      "XXX",
      empty_description,
      Uint8Array.from([1, 2, 3]),
      undefined,
      undefined,
      undefined,
      undefined,
      BigInt(1),
      Network.Testnet
    );
    throw new Error("Invalid description worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Invalid description length")) {
      throw e;
    }
    console.log("Tested invalid description successfully");
  }
}
