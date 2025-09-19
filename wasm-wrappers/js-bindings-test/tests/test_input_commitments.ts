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
  encode_input_for_conclude_order,
  encode_input_for_fill_order,
  encode_input_for_utxo,
  encode_lock_until_height,
  encode_multisig_challenge,
  encode_output_htlc,
  encode_output_produce_block_from_stake,
  encode_transaction,
  encode_witness,
  encode_witness_htlc_multisig,
  encode_witness_htlc_secret,
  internal_verify_witness,
  make_default_account_privkey,
  make_receiving_address,
  multisig_challenge_to_address,
  Network,
  public_key_from_private_key,
  SignatureHashType,
  TxAdditionalInfo,
} from "../../pkg/wasm_wrappers.js";

import {
  expect_exception,
  gen_random_int,
  run_one_test,
} from "./utils.js";

import {
  ANOTHER_ORDER_ID,
  MNEMONIC,
  POOL_ID,
  ORDER_ID,
  SIGHASH_INPUT_COMMITMENTS_V1_TESTNET_FORK_HEIGHT,
  TOKEN_ID,
  HTLC_SECRET_HASH,
  HTLC_SECRET,
  generate_prv_key,
} from "./defs.js";
import {
  ADDRESS
} from "./test_address_generation.js";
import {
  OUTPUTS,
} from "./test_encode_other_outputs.js";

// Note: the exact heights don't matter as long as they are at the "correct side" of the fork.
const SIGHASH_INPUT_COMMITMENTS_V0_HEIGHT =
  gen_random_int(0, SIGHASH_INPUT_COMMITMENTS_V1_TESTNET_FORK_HEIGHT - 1, "SIGHASH_INPUT_COMMITMENTS_V0_HEIGHT");
const SIGHASH_INPUT_COMMITMENTS_V1_HEIGHT = SIGHASH_INPUT_COMMITMENTS_V0_HEIGHT + SIGHASH_INPUT_COMMITMENTS_V1_TESTNET_FORK_HEIGHT;

export function test_input_commitments() {
  function v0() {
    test_impl(false);
  }
  function v1() {
    test_impl(true);
  }

  run_one_test(v0);
  run_one_test(v1);
}

const POOL_INFO = {
  staker_balance: { atoms: "4000000000000000" }
};

const DIFFERENT_POOL_INFO = {
  staker_balance: { atoms: "5000000000000000" }
};

const ORDER1_INFO = {
  initially_asked: {
    coins: { atoms: "3000000000000000" },
  },
  initially_given: {
    tokens: {
      token_id: TOKEN_ID,
      amount: { atoms: "3000000000000000" }
    }
  },
  ask_balance: { atoms: "3000000000000000" },
  give_balance: { atoms: "3000000000000000" }
};

const ORDER2_INFO = {
  initially_asked: {
    coins: { atoms: "4000000000000000" },
  },
  initially_given: {
    tokens: {
      token_id: TOKEN_ID,
      amount: { atoms: "4000000000000000" }
    }
  },
  ask_balance: { atoms: "4000000000000000" },
  give_balance: { atoms: "4000000000000000" }
};

const DIFFERENT_ORDER_INFO = {
  initially_asked: {
    coins: { atoms: "5000000000000000" },
  },
  initially_given: {
    tokens: {
      token_id: TOKEN_ID,
      amount: { atoms: "5000000000000000" }
    }
  },
  ask_balance: { atoms: "5000000000000000" },
  give_balance: { atoms: "5000000000000000" }
};

function test_impl(is_v1: boolean) {
  let height: number;
  if (is_v1) {
    height = SIGHASH_INPUT_COMMITMENTS_V1_HEIGHT;
  } else {
    height = SIGHASH_INPUT_COMMITMENTS_V0_HEIGHT;
  };

  const account_privkey = make_default_account_privkey(
    MNEMONIC,
    Network.Testnet
  );
  const receiving_privkey = make_receiving_address(account_privkey, 0);

  const produce_block_from_stake_output = encode_output_produce_block_from_stake(
    POOL_ID,
    ADDRESS,
    Network.Testnet
  );
  const block_outpoint = new Uint8Array(33).fill(1);
  const tx_outpoint = new Uint8Array(33).fill(0);
  const produce_block_from_stake_input = encode_input_for_utxo(block_outpoint, 1);

  const fill_order_input = encode_input_for_fill_order(
    ORDER_ID,
    Amount.from_atoms("40000"),
    ADDRESS,
    BigInt(1),
    BigInt(height),
    Network.Testnet
  );

  const conclude_order_input = encode_input_for_conclude_order(
    ANOTHER_ORDER_ID,
    BigInt(1),
    BigInt(height),
    Network.Testnet
  );

  const alice_sk = generate_prv_key("alice_sk");
  const alice_pk = public_key_from_private_key(alice_sk);
  const bob_sk = generate_prv_key("bob_sk");
  const bob_pk = public_key_from_private_key(bob_sk);
  const htlc_challenge = encode_multisig_challenge(Uint8Array.from([...alice_pk, ...bob_pk]), 2, Network.Testnet);
  const htlc_multisig_destination = multisig_challenge_to_address(htlc_challenge, Network.Testnet);

  const htlc_output = encode_output_htlc(
    Amount.from_atoms("40000"),
    undefined,
    HTLC_SECRET_HASH,
    ADDRESS,
    htlc_multisig_destination,
    encode_lock_until_height(BigInt(100)),
    Network.Testnet
  );
  const htlc_input = encode_input_for_utxo(tx_outpoint, 1);

  const inputs = [...produce_block_from_stake_input, ...fill_order_input, ...conclude_order_input, ...htlc_input];
  const input_opt_utxos = [1, ...produce_block_from_stake_output, 0, 0, 1, ...htlc_output];
  const htlc_input_index = 3;

  const tx = encode_transaction(Uint8Array.from(inputs), Uint8Array.from(OUTPUTS), BigInt(0));

  function do_verify_witness(
    witness: Uint8Array,
    input_index: number,
    input_destination: string | null,
    additional_info: TxAdditionalInfo) {
    return internal_verify_witness(
      SignatureHashType.ALL,
      input_destination,
      witness,
      tx,
      Uint8Array.from(input_opt_utxos),
      input_index,
      additional_info,
      BigInt(height),
      Network.Testnet
    );
  }

  function do_test(
    subtest_description: string,
    witness_creation_func: (additional_info: TxAdditionalInfo) => Uint8Array,
    witness_verification_func: (witness: Uint8Array, additional_info: TxAdditionalInfo) => void,
    signature_verification_failure_msg: string) {
    console.group(`Testing ${subtest_description}`);

    console.log("Testing missing pool info");
    expect_exception(
      () => {
        witness_creation_func(
          {
            pool_info: {},
            order_info: {
              [ORDER_ID]: ORDER1_INFO,
              [ANOTHER_ORDER_ID]: ORDER2_INFO
            }
          }
        );
      },
      "Error creating sighash input commitments: Pool not found"
    );

    console.log("Testing missing order 1 info");
    expect_exception(
      () => {
        witness_creation_func(
          {
            pool_info: { [POOL_ID]: POOL_INFO },
            order_info: { [ANOTHER_ORDER_ID]: ORDER2_INFO }
          }
        );
      },
      "Error creating sighash input commitments: Order not found"
    );

    console.log("Testing missing order 2 info");
    expect_exception(
      () => {
        witness_creation_func(
          {
            pool_info: { [POOL_ID]: POOL_INFO },
            order_info: { [ORDER_ID]: ORDER1_INFO }
          }
        );
      },
      "Error creating sighash input commitments: Order not found"
    );

    console.log("Testing the successful case");

    const correct_tx_info = {
      pool_info: { [POOL_ID]: POOL_INFO },
      order_info: {
        [ORDER_ID]: ORDER1_INFO,
        [ANOTHER_ORDER_ID]: ORDER2_INFO
      }
    };
    const different_tx_info = {
      pool_info: { [POOL_ID]: DIFFERENT_POOL_INFO },
      order_info: {
        [ORDER_ID]: DIFFERENT_ORDER_INFO,
        [ANOTHER_ORDER_ID]: DIFFERENT_ORDER_INFO
      }
    };

    const witness = witness_creation_func(correct_tx_info);

    console.log("Testing verification with correct tx info");
    witness_verification_func(witness, correct_tx_info);

    console.log("Testing verification with incorrect tx info");
    if (is_v1) {
      // In v1 we do commit to the info, so passing incorrect info should result in verification
      // failure.
      expect_exception(
        () => {
          witness_verification_func(witness, different_tx_info);
        },
        signature_verification_failure_msg
      );
    } else {
      // In v0, we only commit to UTXOs, so passing incorrect info won't cause the verification
      // to fail.
      // Note though that *some* info has to be passed anyway. This is because we want the input
      // commitment construction to have the same requirements on the provided objects both in V0
      // and V1. See the note and the TODO in `make_sighash_input_commitments_for_transaction_inputs`
      // in `common`.
      witness_verification_func(witness, different_tx_info);
    }

    console.groupEnd();
  }

  do_test(
    "encode_witness",
    (additional_info: TxAdditionalInfo) => {
      return encode_witness(
        SignatureHashType.ALL,
        receiving_privkey,
        ADDRESS,
        tx,
        Uint8Array.from(input_opt_utxos),
        0,
        additional_info,
        BigInt(height),
        Network.Testnet
      );
    },
    (witness: Uint8Array, additional_info: TxAdditionalInfo) => {
      do_verify_witness(witness, 0, ADDRESS, additional_info);
    },
    "Signature verification failed"
  );

  do_test(
    "encode_witness_htlc_secret",
    (additional_info: TxAdditionalInfo) => {
      return encode_witness_htlc_secret(
        SignatureHashType.ALL,
        receiving_privkey,
        ADDRESS,
        tx,
        Uint8Array.from(input_opt_utxos),
        htlc_input_index,
        Uint8Array.from(HTLC_SECRET),
        additional_info,
        BigInt(height),
        Network.Testnet
      );
    },
    (witness: Uint8Array, additional_info: TxAdditionalInfo) => {
      do_verify_witness(witness, htlc_input_index, null, additional_info);
    },
    "Signature verification failed"
  );

  do_test(
    "encode_witness_htlc_multisig",
    (additional_info: TxAdditionalInfo) => {
      const partial_witness = encode_witness_htlc_multisig(
        SignatureHashType.ALL,
        alice_sk,
        0,
        new Uint8Array([]),
        htlc_challenge,
        tx,
        Uint8Array.from(input_opt_utxos),
        htlc_input_index,
        additional_info,
        BigInt(height),
        Network.Testnet
      );

      return encode_witness_htlc_multisig(
        SignatureHashType.ALL,
        bob_sk,
        1,
        partial_witness,
        htlc_challenge,
        tx,
        Uint8Array.from(input_opt_utxos),
        htlc_input_index,
        additional_info,
        BigInt(height),
        Network.Testnet
      );
    },
    (witness: Uint8Array, additional_info: TxAdditionalInfo) => {
      do_verify_witness(witness, htlc_input_index, null, additional_info);
    },
    "Invalid classical multisig signature(s)"
  );
}
