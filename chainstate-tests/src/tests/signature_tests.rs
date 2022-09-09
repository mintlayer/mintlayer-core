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

#[test]
fn signed_tx() {
    utils::concurrency::model(|| {
        let mut tf = TestFramework::default();

        let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);

        // The first transaction uses the `AnyoneCanSpend` output of the transaction from the
        // genesis block.
        let tx_1 = TransactionBuilder::new()
            .add_input(TxInput::new(
                OutPointSourceId::BlockReward(tf.chainstate.get_chain_config().genesis_block_id()),
                0,
                InputWitness::NoSignature(None),
            ))
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(100)),
                OutputPurpose::Transfer(Destination::PublicKey(public_key.clone())),
            ))
            .build();

        // The second transaction has the signed input.
        let tx_2 = {
            let mut tx = TransactionBuilder::new()
                .add_input(TxInput::new(
                    OutPointSourceId::Transaction(tx_1.get_id()),
                    0,
                    InputWitness::NoSignature(None),
                ))
                .add_output(TxOutput::new(
                    OutputValue::Coin(Amount::from_atoms(100)),
                    OutputPurpose::Transfer(Destination::PublicKey(public_key.clone())),
                ))
                .build();
            let input_sign = StandardInputSignature::produce_signature_for_input(
                &private_key,
                SigHashType::try_from(SigHashType::ALL).unwrap(),
                Destination::PublicKey(public_key),
                &tx,
                0,
            )
            .unwrap();
            tx.update_witness(0, InputWitness::Standard(input_sign)).unwrap();
            tx
        };

        tf.make_block_builder()
            .with_transactions(vec![tx_1, tx_2])
            .build_and_process()
            .unwrap();
    });
}
