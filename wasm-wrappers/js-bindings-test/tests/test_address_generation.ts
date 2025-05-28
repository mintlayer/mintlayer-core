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
  extended_public_key_from_extended_private_key,
  make_change_address,
  make_change_address_public_key,
  make_default_account_privkey,
  make_receiving_address,
  make_receiving_address_public_key,
  Network,
  public_key_from_private_key,
  pubkey_to_pubkeyhash_address,
} from "../../pkg/wasm_wrappers.js";

import {
  assert_eq_arrays,
  get_err_msg,
  run_one_test,
  TEXT_ENCODER,
} from "./utils.js";

import {
  MNEMONIC,
} from "./defs.js";

// Some address.
// It corresponds to `make_receiving_address(make_default_account_privkey(MNEMONIC,Network.Testnet), 0)`,
// but most tests don't care.
export const ADDRESS = "tmt1q9dn5m4svn8sds3fcy09kpxrefnu75xekgr5wa3n";

export function test_address_generation() {
  run_one_test(predefined_address_test);
  run_one_test(general_test);
}

export function predefined_address_test() {
  const account_private_key = make_default_account_privkey(
    MNEMONIC,
    Network.Testnet
  );
  console.log(`acc private key = ${account_private_key}`);

  const receiving_privkey = make_receiving_address(account_private_key, 0);
  console.log(`receiving privkey = ${receiving_privkey}`);

  const receiving_pubkey = public_key_from_private_key(receiving_privkey);
  const address = pubkey_to_pubkeyhash_address(
    receiving_pubkey,
    Network.Testnet
  );
  console.log(`address = ${address}`);
  if (address != ADDRESS) {
    throw new Error("Incorrect address generated");
  }
}

export function general_test() {
  const bad_priv_key = TEXT_ENCODER.encode("bad");

  try {
    make_receiving_address(bad_priv_key, 0);
    throw new Error("Invalid private key worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Invalid private key encoding")) {
      throw e;
    }
    console.log("Tested decoding bad account private key successfully");
  }

  try {
    make_change_address(bad_priv_key, 0);
    throw new Error("Invalid private key worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Invalid private key encoding")) {
      throw e;
    }
    console.log("Tested decoding bad account private key successfully");
  }

  {
    const account_private_key = make_default_account_privkey(
      MNEMONIC,
      Network.Mainnet
    );
    console.log(`acc private key = ${account_private_key}`);

    const extended_public_key = extended_public_key_from_extended_private_key(account_private_key);

    const receiving_privkey = make_receiving_address(account_private_key, 0);
    console.log(`receiving privkey = ${receiving_privkey}`);

    // test bad key index
    try {
      make_receiving_address(account_private_key, 1 << 31);
      throw new Error("Invalid key index worked somehow!");
    } catch (e) {
      if (!get_err_msg(e).includes("Invalid key index, MSB bit set")) {
        throw e;
      }
      console.log("Tested invalid key index with set MSB bit successfully");
    }

    const receiving_pubkey = public_key_from_private_key(receiving_privkey);
    const receiving_pubkey2 = make_receiving_address_public_key(extended_public_key, 0);
    assert_eq_arrays(receiving_pubkey, receiving_pubkey2);

    const address = pubkey_to_pubkeyhash_address(
      receiving_pubkey,
      Network.Mainnet
    );
    console.log(`address = ${address}`);
    if (address != "mtc1qyqmdpxk2w42w37qsdj0e8g54ysvnlvpny3svzqx") {
      throw new Error("Incorrect address generated");
    }

    const change_privkey = make_change_address(account_private_key, 0);
    console.log(`change privkey = ${change_privkey}`);

    // test bad key index
    try {
      make_change_address(account_private_key, 1 << 31);
      throw new Error("Invalid key index worked somehow!");
    } catch (e) {
      if (!get_err_msg(e).includes("Invalid key index, MSB bit set")) {
        throw e;
      }
      console.log("Tested invalid key index with set MSB bit successfully");
    }

    const change_pubkey = public_key_from_private_key(change_privkey);
    const change_pubkey2 = make_change_address_public_key(extended_public_key, 0);
    assert_eq_arrays(change_pubkey, change_pubkey2);

    const caddress = pubkey_to_pubkeyhash_address(
      change_pubkey,
      Network.Mainnet
    );
    console.log(`address = ${caddress}`);
    if (caddress != "mtc1qxyhrpytqrvjalg2dzw4tdvzt2zz8ps6nyav2n56") {
      throw new Error("Incorrect address generated");
    }
  }
}
