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

    let tx = Transaction::new(0x00, vec![], vec![], 0x01).unwrap();
    let signed_tx = SignedTransaction::new(tx, vec![]).unwrap();
    expect![[r#"
        0xa87e4adcb5a356a3247b699d2c36cf217a135b43a29c3883f46eaed72abbd128
    "#]]
    .assert_debug_eq(&signed_tx.transaction().get_id().get());

    let tx = Transaction::new(0x00, vec![], vec![], 0x02).unwrap();
    let signed_tx = SignedTransaction::new(tx, vec![]).unwrap();
    expect![[r#"
        0x228fea54993e15647ec580ccabde223444b43bd52c82579a2d99ffcfb756c662
    "#]]
    .assert_debug_eq(&signed_tx.transaction().get_id().get());

    let tx = Transaction::new(0x00, ins0.clone(), vec![], 0x00).unwrap();
    let signed_tx = SignedTransaction::new(tx, vec![InputWitness::NoSignature(None)]).unwrap();
    expect![[r#"
        0x5218279d6b62070a822904b763386b1ff8a0eaec65e7738229799ca8495468fc
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
        0x44d93a9721d3328c31413a31060f566c83f3d96f0a32893476d0a47f900648b5
    "#]]
    .assert_debug_eq(&signed_tx.transaction().get_id().get());

    let tx = Transaction::new(0x00, ins0, outs0.clone(), 0x123456).unwrap();
    let signed_tx = SignedTransaction::new(tx, vec![InputWitness::NoSignature(None)]).unwrap();
    expect![[r#"
        0x565499df46b89728096fbf8a46da64c7ffbb7a0087b031ec5b4f0690939902c7
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
        0x23f411d22d3a23692e507e69d8f6c6fe4025a395b4de3b733d7e5845db212450
    "#]]
    .assert_debug_eq(&signed_tx.transaction().get_id().get());
}
