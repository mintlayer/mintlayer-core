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

// Here we have some general definitions that are used by other tests.

import {
  make_private_key,
  public_key_from_private_key,
} from "../../pkg/wasm_wrappers.js";

// Taken from TESTNET_FORK_HEIGHT_5_ORDERS_V1 in common/src/chain/config/builder.rs.
// This will be updated to the actual height after we choose one.
export const ORDERS_V1_TESTNET_FORK_HEIGHT = 999_999_999;

export const MNEMONIC =
  "walk exile faculty near leg neutral license matrix maple invite cupboard hat opinion excess coffee leopard latin regret document core limb crew dizzy movie";

// A random private key that is generated only once and printed to the console.
// Note: simply putting `const PRIVATE_KEY = make_private_key()` to the global scope won't
// work if the tests are run in the browser.
export const get_predefined_prv_key = (function () {
  let PRIVATE_KEY: Uint8Array | null = null;
  return function () {
    if (!PRIVATE_KEY) {
      PRIVATE_KEY = make_private_key();
      console.log(`PRIVATE_KEY = ${PRIVATE_KEY}`);
    }
    return PRIVATE_KEY;
  }
})();

// The public key corresponding to get_predefined_prv_key().
export const get_predefined_pub_key = (function () {
  let PUBLIC_KEY: Uint8Array | null = null;
  return function () {
    if (!PUBLIC_KEY) {
      PUBLIC_KEY = public_key_from_private_key(get_predefined_prv_key());
      console.log(`PUBLIC_KEY = ${PUBLIC_KEY}`);
    }
    return PUBLIC_KEY;
  }
})();

// Some token id.
export const TOKEN_ID = "tmltk15tgfrs49rv88v8utcllqh0nvpaqtgvn26vdxhuner5m6ewg9c3msn9fxns";

// Some pool id
export const POOL_ID = "tpool1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqza035u";

// Some order id
export const ORDER_ID = "tordr1xxt0avjtt4flkq0tnlyphmdm4aaj9vmkx5r2m4g863nw3lgf7nzs7mlkqc";
