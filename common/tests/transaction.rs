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
use common::chain::tokens::OutputValue;
use common::chain::transaction::*;
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
    let ins0: Vec<TxInput> = [TxInput::new(
        Id::<Transaction>::new(hash0).into(),
        5,
        InputWitness::NoSignature(None),
    )]
    .to_vec();
    let ins1: Vec<TxInput> = [
        TxInput::new(
            Id::<Transaction>::new(hash1).into(),
            3,
            InputWitness::NoSignature(Some(vec![0x01, 0x05, 0x09])),
        ),
        TxInput::new(
            Id::<Transaction>::new(hash2).into(),
            0,
            InputWitness::NoSignature(Some(vec![0x91, 0x55, 0x19, 0x00])),
        ),
    ]
    .to_vec();

    let tx = Transaction::new(0x00, vec![], vec![], 0x01).unwrap();
    expect![[r#"
        0x28d1bb2ad7ae6ef483389ca2435b137a21cf362c9d697b24a356a3b5dc4a7ea8
    "#]]
    .assert_debug_eq(&tx.get_id().get());

    let tx = Transaction::new(0x00, vec![], vec![], 0x02).unwrap();
    expect![[r#"
        0x62c656b7cfff992d9a57822cd53bb4443422deabcc80c57e64153e9954ea8f22
    "#]]
    .assert_debug_eq(&tx.get_id().get());

    let tx = Transaction::new(0x00, ins0.clone(), vec![], 0x00).unwrap();
    expect![[r#"
        0xfc685449a89c79298273e765eceaa0f81f6b3863b70429820a07626b9d271852
    "#]]
    .assert_debug_eq(&tx.get_id().get());

    let tx = Transaction::new(0x00, ins1.clone(), vec![], 0x00).unwrap();
    expect![[r#"
        0xb54806907fa4d0763489320a6fd9f3836c560f06313a41318c32d321973ad944
    "#]]
    .assert_debug_eq(&tx.get_id().get());

    let tx = Transaction::new(0x00, ins0, outs0.clone(), 0x123456).unwrap();
    expect![[r#"
        0x6e05b8807d81956bda8ed231cfe4ffeb50f193af6bd3d441185470905486145f
    "#]]
    .assert_debug_eq(&tx.get_id().get());

    let tx = Transaction::new(0x00, ins1, outs0, 0x00).unwrap();
    expect![[r#"
        0x425ca11b436a48b832e35475fa808fa9de0f8513ce9b4dd9cef39fccb2342c71
    "#]]
    .assert_debug_eq(&tx.get_id().get());
}
