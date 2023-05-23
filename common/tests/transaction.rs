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
use common::chain::{tokens::OutputValue, transaction::*};
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
    let ins0: Vec<TxInput> = [TxInput::new(Id::<Transaction>::new(hash0).into(), 5)].to_vec();
    let ins1: Vec<TxInput> = [
        TxInput::new(Id::<Transaction>::new(hash1).into(), 3),
        TxInput::new(Id::<Transaction>::new(hash2).into(), 0),
    ]
    .to_vec();

    let tx = Transaction::new(0x00, vec![], vec![]).unwrap();
    let signed_tx = SignedTransaction::new(tx, vec![]).unwrap();
    expect![[r#"
        0xf368cfd2546f0256af55a6bf332f3c464891033cca644c4b00c3a0f06c2f09ff
    "#]]
    .assert_debug_eq(&signed_tx.transaction().get_id().get());

    let tx = Transaction::new(0x00, vec![], vec![]).unwrap();
    let signed_tx = SignedTransaction::new(tx, vec![]).unwrap();
    expect![[r#"
        0xf368cfd2546f0256af55a6bf332f3c464891033cca644c4b00c3a0f06c2f09ff
    "#]]
    .assert_debug_eq(&signed_tx.transaction().get_id().get());

    let tx = Transaction::new(0x00, ins0.clone(), vec![]).unwrap();
    let signed_tx = SignedTransaction::new(tx, vec![InputWitness::NoSignature(None)]).unwrap();
    expect![[r#"
        0xc851295108ff12448c11ca0a32daec8f373f23b44fa8359158d00e09910cce68
    "#]]
    .assert_debug_eq(&signed_tx.transaction().get_id().get());

    let tx = Transaction::new(0x00, ins1.clone(), vec![]).unwrap();
    let signed_tx = SignedTransaction::new(
        tx,
        vec![
            InputWitness::NoSignature(Some(vec![0x01, 0x05, 0x09])),
            InputWitness::NoSignature(Some(vec![0x91, 0x55, 0x19, 0x00])),
        ],
    )
    .unwrap();
    expect![[r#"
        0x390f0465b617605e9b54bf8e7835c77790eb7b8547f9c7fa90d0efa636f45877
    "#]]
    .assert_debug_eq(&signed_tx.transaction().get_id().get());

    let tx = Transaction::new(0x00, ins0, outs0.clone()).unwrap();
    let signed_tx = SignedTransaction::new(tx, vec![InputWitness::NoSignature(None)]).unwrap();
    expect![[r#"
        0x336a72e22d0536c1b00d75f97aed03bfaa2f3ef2ae1a292a60a2e8ca2eed2347
    "#]]
    .assert_debug_eq(&signed_tx.transaction().get_id().get());

    let tx = Transaction::new(0x00, ins1, outs0).unwrap();
    let signed_tx = SignedTransaction::new(
        tx,
        vec![
            InputWitness::NoSignature(Some(vec![0x01, 0x05, 0x09])),
            InputWitness::NoSignature(Some(vec![0x91, 0x55, 0x19, 0x00])),
        ],
    )
    .unwrap();
    expect![[r#"
        0xe60afd411a245203e062d8b4af1bd8661f7b9632816ec0c6150f9ba974ee8883
    "#]]
    .assert_debug_eq(&signed_tx.transaction().get_id().get());
}
