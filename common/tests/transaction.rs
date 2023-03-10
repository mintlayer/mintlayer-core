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

    let outs0: Vec<TxOutput> = [TxOutput::new(
        OutputValue::Coin(Amount::from_atoms(25)),
        OutputPurpose::Transfer(Destination::ScriptHash(Id::new(hash0))),
    )]
    .to_vec();
    let ins0: Vec<TxInput> = [TxInput::new(Id::<Transaction>::new(hash0).into(), 5)].to_vec();
    let ins1: Vec<TxInput> = [
        TxInput::new(Id::<Transaction>::new(hash1).into(), 3),
        TxInput::new(Id::<Transaction>::new(hash2).into(), 0),
    ]
    .to_vec();

    let tx = Transaction::new(0x00, vec![], vec![], 0x01).unwrap();
    let signed_tx = SignedTransaction::new(tx, vec![]).unwrap();
    expect![[r#"
        0x28d1bb2ad7ae6ef483389ca2435b137a21cf362c9d697b24a356a3b5dc4a7ea8
    "#]]
    .assert_debug_eq(&signed_tx.transaction().get_id().get());

    let tx = Transaction::new(0x00, vec![], vec![], 0x02).unwrap();
    let signed_tx = SignedTransaction::new(tx, vec![]).unwrap();
    expect![[r#"
        0x62c656b7cfff992d9a57822cd53bb4443422deabcc80c57e64153e9954ea8f22
    "#]]
    .assert_debug_eq(&signed_tx.transaction().get_id().get());

    let tx = Transaction::new(0x00, ins0.clone(), vec![], 0x00).unwrap();
    let signed_tx = SignedTransaction::new(tx, vec![InputWitness::NoSignature(None)]).unwrap();
    expect![[r#"
        0xfc685449a89c79298273e765eceaa0f81f6b3863b70429820a07626b9d271852
    "#]]
    .assert_debug_eq(&signed_tx.transaction().get_id().get());

    let tx = Transaction::new(0x00, ins1.clone(), vec![], 0x00).unwrap();
    let signed_tx = SignedTransaction::new(
        tx,
        vec![
            InputWitness::NoSignature(Some(vec![0x01, 0x05, 0x09])),
            InputWitness::NoSignature(Some(vec![0x91, 0x55, 0x19, 0x00])),
        ],
    )
    .unwrap();
    expect![[r#"
        0xb54806907fa4d0763489320a6fd9f3836c560f06313a41318c32d321973ad944
    "#]]
    .assert_debug_eq(&signed_tx.transaction().get_id().get());

    let tx = Transaction::new(0x00, ins0, outs0.clone(), 0x123456).unwrap();
    let signed_tx = SignedTransaction::new(tx, vec![InputWitness::NoSignature(None)]).unwrap();
    expect![[r#"
        0x1205cd5f2da893cc6b48946309c5c5e5f2d97ecc475b47e3f7ffff0db0b126e0
    "#]]
    .assert_debug_eq(&signed_tx.transaction().get_id().get());

    let tx = Transaction::new(0x00, ins1, outs0, 0x00).unwrap();
    let signed_tx = SignedTransaction::new(
        tx,
        vec![
            InputWitness::NoSignature(Some(vec![0x01, 0x05, 0x09])),
            InputWitness::NoSignature(Some(vec![0x91, 0x55, 0x19, 0x00])),
        ],
    )
    .unwrap();
    expect![[r#"
        0xed07c7ea4e6e70715dc0a02883966eea60c33d5aa83f50fe5c87bc3b54e4e775
    "#]]
    .assert_debug_eq(&signed_tx.transaction().get_id().get());
}
