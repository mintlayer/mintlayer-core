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

use common::chain::signature::inputsig::InputWitness;
use common::chain::signed_transaction::SignedTransaction;
use common::chain::DelegationId;
use common::chain::{output_value::OutputValue, transaction::*};
use common::primitives::{Amount, Id, Idable, H256};
use expect_test::expect;

#[test]
fn transaction_id_snapshots() {
    let hash0 = H256([0x50; 32]);
    let hash1 = H256([0x51; 32]);
    let hash2 = H256([0x52; 32]);

    let outs0: Vec<TxOutput> = [TxOutput::Transfer(
        OutputValue::Coin(Amount::from_atoms(25)),
        Destination::ScriptHash(Id::new(hash0)),
    )]
    .to_vec();
    let utxo_ins0: Vec<TxInput> =
        [TxInput::from_utxo(Id::<Transaction>::new(hash0).into(), 5)].to_vec();
    let utxo_ins1: Vec<TxInput> = [
        TxInput::from_utxo(Id::<Transaction>::new(hash1).into(), 3),
        TxInput::from_utxo(Id::<Transaction>::new(hash2).into(), 0),
    ]
    .to_vec();

    let account_ins0: Vec<TxInput> = [TxInput::from_account(
        AccountNonce::new(0),
        AccountSpending::DelegationBalance(DelegationId::new(hash0), Amount::from_atoms(15)),
    )]
    .to_vec();
    let account_ins1: Vec<TxInput> = [
        TxInput::from_account(
            AccountNonce::new(1),
            AccountSpending::DelegationBalance(DelegationId::new(hash1), Amount::from_atoms(35)),
        ),
        TxInput::from_account(
            AccountNonce::new(2),
            AccountSpending::DelegationBalance(DelegationId::new(hash2), Amount::from_atoms(55)),
        ),
    ]
    .to_vec();

    // empty inputs/outputs
    let tx = Transaction::new(0x00, vec![], vec![]).unwrap();
    let signed_tx = SignedTransaction::new(tx, vec![]).unwrap();
    expect![[r#"
        0x3db1faf0caf4f929459d5709c7f5e88c83b0c172ffc995a89035055ffadf7e2d
    "#]]
    .assert_debug_eq(&signed_tx.transaction().get_id().to_hash());

    // single utxo input / empty outputs
    let tx = Transaction::new(0x00, utxo_ins0.clone(), vec![]).unwrap();
    let signed_tx = SignedTransaction::new(tx, vec![InputWitness::NoSignature(None)]).unwrap();
    expect![[r#"
        0xbcd223a8ae03b116d255db0d7e2cc5a0570cde789813dd4d6ecd5f6f4d8585b5
    "#]]
    .assert_debug_eq(&signed_tx.transaction().get_id().to_hash());

    // two utxo inputs / empty outputs
    let tx = Transaction::new(0x00, utxo_ins1.clone(), vec![]).unwrap();
    let signed_tx = SignedTransaction::new(
        tx,
        vec![
            InputWitness::NoSignature(Some(vec![0x01, 0x05, 0x09])),
            InputWitness::NoSignature(Some(vec![0x91, 0x55, 0x19, 0x00])),
        ],
    )
    .unwrap();
    expect![[r#"
        0x1e2a16bdf1f663e8065e6c541d1d45196001471be9c94d1d87ebf84b4f1206a4
    "#]]
    .assert_debug_eq(&signed_tx.transaction().get_id().to_hash());

    // single utxo inputs / single output
    let tx = Transaction::new(0x00, utxo_ins0, outs0.clone()).unwrap();
    let signed_tx = SignedTransaction::new(tx, vec![InputWitness::NoSignature(None)]).unwrap();
    expect![[r#"
        0x8ade05e1e0c8b77a86a8848f8a3c236e5b4666c71f01fc6a48174b553fc9e92f
    "#]]
    .assert_debug_eq(&signed_tx.transaction().get_id().to_hash());

    // two utxo inputs / single output
    let tx = Transaction::new(0x00, utxo_ins1, outs0.clone()).unwrap();
    let signed_tx = SignedTransaction::new(
        tx,
        vec![
            InputWitness::NoSignature(Some(vec![0x01, 0x05, 0x09])),
            InputWitness::NoSignature(Some(vec![0x91, 0x55, 0x19, 0x00])),
        ],
    )
    .unwrap();
    expect![[r#"
        0xe576d18773468bfbd828eb181106cc417e83a7852b659ffd5943351388b73559
    "#]]
    .assert_debug_eq(&signed_tx.transaction().get_id().to_hash());

    // single account input / empty outputs
    let tx = Transaction::new(0x00, account_ins0.clone(), vec![]).unwrap();
    let signed_tx = SignedTransaction::new(tx, vec![InputWitness::NoSignature(None)]).unwrap();
    expect![[r#"
        0x74e8d5d826597b52493fc7488fcc63f3f2f44a6c457abf8713f1cc5d353872c7
    "#]]
    .assert_debug_eq(&signed_tx.transaction().get_id().to_hash());

    // single account input / single output
    let tx = Transaction::new(0x00, account_ins0, outs0.clone()).unwrap();
    let signed_tx = SignedTransaction::new(tx, vec![InputWitness::NoSignature(None)]).unwrap();
    expect![[r#"
        0x093479a8a5b7e276db9d9fb205f0cfb7c826567a5fd412e91a1c6f10b5528e82
    "#]]
    .assert_debug_eq(&signed_tx.transaction().get_id().to_hash());

    // two account inputs / single output
    let tx = Transaction::new(0x00, account_ins1, outs0).unwrap();
    let signed_tx = SignedTransaction::new(
        tx,
        vec![
            InputWitness::NoSignature(Some(vec![0x01, 0x05, 0x09])),
            InputWitness::NoSignature(Some(vec![0x91, 0x55, 0x19, 0x00])),
        ],
    )
    .unwrap();
    expect![[r#"
        0xa17efbc0f7ec4ac790bae3c235328535f403da62f80d4a8b282a817daf55bdfd
    "#]]
    .assert_debug_eq(&signed_tx.transaction().get_id().to_hash());
}
