// Copyright (c) 2022 RBB S.r.l
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

use common::chain::signed_transaction::SignedTransaction;
use common::primitives::Idable;
use common::{
    chain::{
        signature::{
            inputsig::{InputWitness, StandardInputSignature},
            sighashtype::SigHashType,
        },
        tokens::OutputValue,
        Destination, OutPointSourceId, OutputPurpose, TxInput, TxOutput,
    },
    primitives::Amount,
};
use crypto::key::{KeyKind, PrivateKey};

use chainstate_test_framework::TestFramework;
use chainstate_test_framework::TransactionBuilder;
use rstest::rstest;
use test_utils::random::Seed;

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn signed_tx(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut tf = TestFramework::default();
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let (private_key, public_key) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);

        // The first transaction uses the `AnyoneCanSpend` output of the transaction from the
        // genesis block.
        let tx_1 = TransactionBuilder::new()
            .add_input(
                TxInput::new(
                    OutPointSourceId::BlockReward(
                        tf.chainstate.get_chain_config().genesis_block_id(),
                    ),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(100)),
                OutputPurpose::Transfer(Destination::PublicKey(public_key.clone())),
            ))
            .build();

        // The second transaction has the signed input.
        let tx_2 = {
            let tx = TransactionBuilder::new()
                .add_input(
                    TxInput::new(
                        OutPointSourceId::Transaction(tx_1.transaction().get_id()),
                        0,
                    ),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::new(
                    OutputValue::Coin(Amount::from_atoms(100)),
                    OutputPurpose::Transfer(Destination::PublicKey(public_key.clone())),
                ))
                .build()
                .transaction()
                .clone();
            let input_sign = StandardInputSignature::produce_signature_for_input(
                &private_key,
                SigHashType::try_from(SigHashType::ALL).unwrap(),
                Destination::PublicKey(public_key),
                &tx,
                0,
            )
            .unwrap();
            SignedTransaction::new(tx, vec![InputWitness::Standard(input_sign)])
                .expect("invalid witness count")
        };

        tf.make_block_builder()
            .with_transactions(vec![tx_1, tx_2])
            .build_and_process()
            .unwrap();
    });
}
