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

import {
  gen_random_int,
} from "./utils.js";

// Taken from TESTNET_FORK_HEIGHT_5_ORDERS_V1 in common/src/chain/config/builder.rs
// (which corresponds both to the orders and input commitments upgrade).
const ORDERS_V1_INPUT_COMMITMENTS_V1_TESTNET_FORK_HEIGHT = 566060;
export const ORDERS_V1_TESTNET_FORK_HEIGHT = ORDERS_V1_INPUT_COMMITMENTS_V1_TESTNET_FORK_HEIGHT;
export const SIGHASH_INPUT_COMMITMENTS_V1_TESTNET_FORK_HEIGHT = ORDERS_V1_INPUT_COMMITMENTS_V1_TESTNET_FORK_HEIGHT;

// A random height for cases where the height doesn't matter.
export const RANDOM_HEIGHT = gen_random_int(0, 10_000_000_000, "RANDOM_HEIGHT");

export const MNEMONIC =
  "walk exile faculty near leg neutral license matrix maple invite cupboard hat opinion excess coffee leopard latin regret document core limb crew dizzy movie";

// A random private key that is generated only once and printed to the console.
// Note: simply putting `const PRIVATE_KEY = make_private_key()` to the global scope won't
// work if the tests are run in the browser.
export const get_predefined_random_prv_key = (function () {
  let PRIVATE_KEY: Uint8Array | null = null;
  return function () {
    if (!PRIVATE_KEY) {
      PRIVATE_KEY = make_private_key();
      console.log(`PRIVATE_KEY = ${PRIVATE_KEY}`);
    }
    return PRIVATE_KEY;
  }
})();

// The public key corresponding to get_predefined_random_prv_key().
export const get_predefined_random_pub_key = (function () {
  let PUBLIC_KEY: Uint8Array | null = null;
  return function () {
    if (!PUBLIC_KEY) {
      PUBLIC_KEY = public_key_from_private_key(get_predefined_random_prv_key());
      console.log(`PUBLIC_KEY = ${PUBLIC_KEY}`);
    }
    return PUBLIC_KEY;
  }
})();

export function generate_prv_key(description: string) {
  const result = make_private_key();
  console.log(`Generated ${description} private key: ${result}`);
  return result;
}

// Some token id.
export const TOKEN_ID = "tmltk15tgfrs49rv88v8utcllqh0nvpaqtgvn26vdxhuner5m6ewg9c3msn9fxns";

// Some pool id
export const POOL_ID = "tpool1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqza035u";

// Some order ids
export const ORDER_ID = "tordr1xxt0avjtt4flkq0tnlyphmdm4aaj9vmkx5r2m4g863nw3lgf7nzs7mlkqc";
export const ANOTHER_ORDER_ID = "tordr1mslcn8z774t3ug9zcxa6mqr9yc29r60fg8fkhajnngc98ryh5m3sqz6jvz";

// Some HTLC secret and its hash
export const HTLC_SECRET = [
  0, 229, 233, 72, 110, 22, 64, 36, 69, 188, 238, 51, 130, 168, 185, 241,
  73, 48, 120, 151, 140, 45, 46, 39, 50, 207, 18, 50, 243, 30, 115, 93
]
export const HTLC_SECRET_HASH = "b5a48c7780e597de8012346fb30761965248e3f2"

// Some predefined key pairs (note that the prv keys are unused at the moment, so they are marked
// with `/** @public */` to pacify knip).
/** @public */
export const PRV_KEY_A = [
  0, 155, 37, 209, 155, 128, 40, 223, 139, 200, 13, 149, 126, 93, 4, 44,
  190, 53, 102, 135, 246, 42, 84, 200, 61, 221, 125, 104, 135, 142, 0, 42, 12
]
export const PUB_KEY_A = [
  0, 2, 204, 229, 50, 59, 113, 11, 253, 127, 50, 216, 85, 175, 139, 202,
  118, 28, 122, 51, 91, 43, 137, 206, 188, 119, 57, 86, 49, 215, 37, 5, 134, 195
]
/** @public */
export const PRV_KEY_B = [
  0, 181, 124, 242, 82, 150, 38, 29, 109, 72, 118, 47, 37, 55, 218, 146,
  84, 200, 134, 132, 108, 202, 174, 86, 48, 160, 159, 211, 78, 99, 66, 6, 173
]
export const PUB_KEY_B = [
  0, 3, 68, 225, 99, 228, 45, 76, 242, 134, 151, 216, 99, 225, 215, 59,
  77, 101, 3, 191, 248, 212, 205, 172, 178, 252, 65, 140, 255, 213, 205, 49, 234, 81
]
