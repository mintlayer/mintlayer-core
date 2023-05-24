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
        0x3db1faf0caf4f929459d5709c7f5e88c83b0c172ffc995a89035055ffadf7e2d
    "#]]
    .assert_debug_eq(&signed_tx.transaction().get_id().get());

    let tx = Transaction::new(0x00, vec![], vec![]).unwrap();
    let signed_tx = SignedTransaction::new(tx, vec![]).unwrap();
    expect![[r#"
        0x3db1faf0caf4f929459d5709c7f5e88c83b0c172ffc995a89035055ffadf7e2d
    "#]]
    .assert_debug_eq(&signed_tx.transaction().get_id().get());

    let tx = Transaction::new(0x00, ins0.clone(), vec![]).unwrap();
    let signed_tx = SignedTransaction::new(tx, vec![InputWitness::NoSignature(None)]).unwrap();
    expect![[r#"
        0xbfda14833ab08e9819fdf0b899adf0dc38655255619538a015c2b1dcc74bcc34
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
        0x679ac36cd1dd5c6f53aa532d01f96c61f4ff37eb1e71219ee38a2af19198e64a
    "#]]
    .assert_debug_eq(&signed_tx.transaction().get_id().get());

    let tx = Transaction::new(0x00, ins0, outs0.clone()).unwrap();
    let signed_tx = SignedTransaction::new(tx, vec![InputWitness::NoSignature(None)]).unwrap();
    expect![[r#"
        0x4ef0c69971c04aeb22c95c657c0dc92477ec8944edac0a4cc7642d944ecd815c
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
        0x566a068e9f4a13b6ce758a1f9ca2262d87db71e6bd82a102303fd1b5ac860f22
    "#]]
    .assert_debug_eq(&signed_tx.transaction().get_id().get());
}
