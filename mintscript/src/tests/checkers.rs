// Copyright (c) 2024 RBB S.r.l
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

use std::borrow::Cow;

use super::*;

fn make_dummy_tx(
    mut rng: impl Rng + CryptoRng,
    privkeys: &[&PrivateKey],
) -> (SignedTransaction, Vec<SighashInputCommitment<'static>>) {
    // Create a simple single output transaction. We can afford to put dummy data
    // here since we construct the script manually, not from the transaction, so most of it is
    // ignored by the evaluator. It's used mostly to get the hash for signing.

    let n_inputs = privkeys.len();

    let mut gen_value = {
        let mut rng = make_seedable_rng(rng.gen());
        move || OutputValue::Coin(Amount::from_atoms(rng.gen_range(0..10_u128.pow(20))))
    };

    let utxos: Vec<_> = (0_usize..n_inputs)
        .map(|_| TxOutput::Transfer(gen_value(), Destination::AnyoneCanSpend))
        .collect();

    let output = TxOutput::Burn(gen_value());
    let inputs = (0..n_inputs).map(|_| {
        let outpoint = OutPointSourceId::Transaction(Id::new(rng.gen()));
        TxInput::from_utxo(outpoint, rng.gen_range(0u32..200))
    });
    let input_commitments = utxos
        .iter()
        .map(|utxo| SighashInputCommitment::<'static>::Utxo(Cow::Owned(utxo.clone())))
        .collect::<Vec<_>>();
    let tx = Transaction::new(0, inputs.collect(), vec![output]).unwrap();

    let witnesses = privkeys
        .iter()
        .enumerate()
        .map(|(input_num, private_key)| {
            let sig = StandardInputSignature::produce_uniparty_signature_for_input(
                private_key,
                SigHashType::default(),
                Destination::PublicKey(PublicKey::from_private_key(private_key)),
                &tx,
                &input_commitments,
                input_num,
                &mut rng,
            )
            .unwrap();
            InputWitness::Standard(sig)
        })
        .collect();

    let transaction = SignedTransaction::new(tx, witnesses).unwrap();

    (transaction, input_commitments)
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_sig(#[case] seed: Seed) {
    use common::chain::signature::EvaluatedInputWitness;

    let mut rng = make_seedable_rng(seed);
    let n_inputs = rng.gen_range(1..5);

    let keypairs: Vec<_> = (0..n_inputs)
        .map(|_| PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr))
        .collect();
    let privkeys: Vec<_> = keypairs.iter().map(|(priv_k, _pub_k)| priv_k).collect();
    let pubkey0 = &keypairs[0].1;

    let (transaction, input_commitments) = make_dummy_tx(&mut rng, &privkeys);
    let sig0 = &transaction.signatures()[0];

    let eval_witness = match sig0.clone() {
        InputWitness::NoSignature(d) => EvaluatedInputWitness::NoSignature(d),
        InputWitness::Standard(s) => EvaluatedInputWitness::Standard(s),
    };
    let script = WitnessScript::signature(Destination::PublicKey(pubkey0.clone()), eval_witness);

    // Test a successful check
    let mut checker = MockContext::new(0, &transaction, input_commitments.clone()).into_checker();
    script.verify(&mut checker).expect("Check to succeed");

    // Test checks which mutate the original transaction, the signature check should fail
    for bad_tx in test_utils::all_single_bit_mutations(transaction.transaction()) {
        let bad_tx = match SignedTransaction::new(bad_tx, transaction.signatures().to_vec()) {
            Ok(tx) => tx,
            Err(_) => continue,
        };

        let mut checker = MockContext::new(0, &bad_tx, input_commitments.clone()).into_checker();
        match script.verify(&mut checker).expect_err("this should fail") {
            ScriptError::Signature(_e) => (),
            e @ (ScriptError::Timelock(_)
            | ScriptError::Threshold(_)
            | ScriptError::Hashlock(_)) => {
                panic!("Unexpected error {e}")
            }
        }
    }
}

fn check_timelocks(
    rng: &mut (impl Rng + CryptoRng),
    timelock: OutputTimeLock,
    (utxo_height, spend_height, utxo_time, spend_time): (u64, u64, u64, u64),
    expected_ok: bool,
) {
    let n_inputs = rng.gen_range(1..5);
    let utxo_height = BlockHeight::new(utxo_height);
    let spend_height = BlockHeight::new(spend_height);
    let utxo_time = BlockTimestamp::from_int_seconds(utxo_time);
    let spend_time = BlockTimestamp::from_int_seconds(spend_time);

    let keypairs: Vec<_> = (0..n_inputs)
        .map(|_| PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr))
        .collect();
    let privkeys: Vec<_> = keypairs.iter().map(|(priv_k, _pub_k)| priv_k).collect();
    let (transaction, input_commitments) = make_dummy_tx(rng, &privkeys);

    let script = WitnessScript::timelock(timelock);

    // Test a successful check
    let mut checker = MockContext::new(0, &transaction, input_commitments)
        .with_block_heights(utxo_height, spend_height)
        .with_timestamps(utxo_time, spend_time)
        .into_checker();
    let result = script.verify(&mut checker);
    assert_eq!(result.is_ok(), expected_ok);
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy(), tl_until_height(1), (0, 1, 8, 15), true)]
#[case(Seed::from_entropy(), tl_until_height(2), (0, 1, 3, 19), false)]
#[case(Seed::from_entropy(), tl_until_height(2), (0, 2, 3, 19), true)]
#[case(Seed::from_entropy(), tl_until_height(2), (0, 3, 3, 19), true)]
#[case(Seed::from_entropy(), tl_until_height(100), (12, 99, 1, 2), false)]
#[case(Seed::from_entropy(), tl_until_height(100), (25, 100, 3, 5), true)]
#[case(Seed::from_entropy(), tl_until_height(100), (41, 101, 1, 2), true)]
#[case(Seed::from_entropy(), tl_for_blocks(1), (5, 6, 3, 9), true)]
#[case(Seed::from_entropy(), tl_for_blocks(1), (5, 5, 4, 7), false)]
#[case(Seed::from_entropy(), tl_for_blocks(0), (5, 5, 1, 2), true)]
#[case(Seed::from_entropy(), tl_for_blocks(0), (5, 6, 1, 2), true)]
#[case(Seed::from_entropy(), tl_for_blocks(100), (12, 111, 3, 4), false)]
#[case(Seed::from_entropy(), tl_for_blocks(100), (25, 125, 5, 6), true)]
#[case(Seed::from_entropy(), tl_for_blocks(100), (41, 142, 7, 8), true)]
#[case(Seed::from_entropy(), tl_until_time(1), (8, 15, 0, 1), true)]
#[case(Seed::from_entropy(), tl_until_time(2), (3, 19, 0, 1), false)]
#[case(Seed::from_entropy(), tl_until_time(2), (3, 19, 0, 2), true)]
#[case(Seed::from_entropy(), tl_until_time(2), (3, 19, 0, 3), true)]
#[case(Seed::from_entropy(), tl_until_time(100), (1, 2, 12, 99), false)]
#[case(Seed::from_entropy(), tl_until_time(100), (3, 5, 25, 100), true)]
#[case(Seed::from_entropy(), tl_until_time(100), (1, 2, 41, 101), true)]
#[case(Seed::from_entropy(), tl_for_secs(0), (8, 15, 9, 9), true)]
#[case(Seed::from_entropy(), tl_for_secs(0), (3, 19, 8, 9), true)]
#[case(Seed::from_entropy(), tl_for_secs(1), (8, 15, 0, 1), true)]
#[case(Seed::from_entropy(), tl_for_secs(2), (3, 19, 0, 1), false)]
#[case(Seed::from_entropy(), tl_for_secs(2), (3, 19, 0, 2), true)]
#[case(Seed::from_entropy(), tl_for_secs(2), (3, 19, 0, 3), true)]
#[case(Seed::from_entropy(), tl_for_secs(100), (1, 2, 12, 111), false)]
#[case(Seed::from_entropy(), tl_for_secs(100), (3, 5, 25, 125), true)]
#[case(Seed::from_entropy(), tl_for_secs(100), (1, 2, 41, 142), true)]
fn check_timelocks_corner_cases(
    #[case] seed: Seed,
    #[case] timelock: OutputTimeLock,
    #[case] ctx_info: (u64, u64, u64, u64),
    #[case] expected_ok: bool,
) {
    let mut rng = make_seedable_rng(seed);
    check_timelocks(&mut rng, timelock, ctx_info, expected_ok)
}

fn check_timelocks_rand(
    seed: Seed,
    lock_fn: impl FnOnce(&mut TestRng, u64, u64, u64, u64) -> OutputTimeLock,
    expected_ok: bool,
) {
    let mut rng = TestRng::new(seed);

    let utxo_height = rng.gen_range(0..100_000);
    let spend_dist = rng.gen_range(1..100_000);
    let utxo_time = rng.gen_range(0..10_000_000);
    let spend_delay = rng.gen_range(1..10_000_000);
    let ctx_info = (
        utxo_height,
        utxo_height + spend_dist,
        utxo_time,
        utxo_time + spend_delay,
    );

    let timelock = lock_fn(&mut rng, utxo_height, spend_dist, utxo_time, spend_delay);
    check_timelocks(&mut rng, timelock, ctx_info, expected_ok);
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
fn timelock_rand_abs_height_ok(#[case] seed: Seed) {
    check_timelocks_rand(
        seed,
        |r, h, d, _, _| tl_until_height(h + r.gen_range(0..=d)),
        true,
    )
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
fn timelock_rand_abs_height_fail(#[case] seed: Seed) {
    check_timelocks_rand(
        seed,
        |r, h, d, _, _| tl_until_height(h + d + r.gen_range(1..1_000)),
        false,
    )
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
fn timelock_rand_rel_height_ok(#[case] seed: Seed) {
    check_timelocks_rand(
        seed,
        |r, _, d, _, _| tl_for_blocks(r.gen_range(0..=d)),
        true,
    )
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
fn timelock_rand_rel_height_fail(#[case] seed: Seed) {
    check_timelocks_rand(
        seed,
        |r, _, d, _, _| tl_for_blocks(d + r.gen_range(1..1_000)),
        false,
    )
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
fn timelock_rand_abs_time_ok(#[case] seed: Seed) {
    check_timelocks_rand(
        seed,
        |r, _, _, t, d| tl_until_time(t + r.gen_range(0..=d)),
        true,
    )
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
fn timelock_rand_abs_time_fail(#[case] seed: Seed) {
    check_timelocks_rand(
        seed,
        |r, _, _, t, d| tl_until_time(t + d + r.gen_range(1..1_000)),
        false,
    )
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
fn timelock_rand_rel_time_ok(#[case] seed: Seed) {
    check_timelocks_rand(seed, |r, _, _, _, d| tl_for_secs(r.gen_range(0..=d)), true)
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
fn timelock_rand_rel_time_fail(#[case] seed: Seed) {
    check_timelocks_rand(
        seed,
        |r, _, _, _, d| tl_for_secs(d + r.gen_range(1..100_000)),
        false,
    )
}
