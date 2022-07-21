// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): S. Tkach

use crate::detail::tests::*;
use common::{
    chain::{
        signature::{
            inputsig::{InputWitness, StandardInputSignature},
            sighashtype::SigHashType,
        },
        Destination, OutPointSourceId, OutputPurpose, TxInput, TxOutput,
    },
    primitives::Amount,
};
use crypto::key::{KeyKind, PrivateKey};

#[test]
fn signed_tx() {
    common::concurrency::model(|| {
        let mut chainstate = setup_chainstate();

        let genesis_tx = chainstate.chain_config.genesis_block().transactions().get(0).unwrap();
        let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);

        // The first transaction uses the `AnyoneCanSpend` output of the transaction from the
        // genesis block.
        let tx_1 = {
            let input = TxInput::new(
                OutPointSourceId::Transaction(genesis_tx.get_id()),
                0,
                InputWitness::NoSignature(None),
            );
            let output = TxOutput::new(
                Amount::from_atoms(100),
                OutputPurpose::Transfer(Destination::PublicKey(public_key.clone())),
            );
            Transaction::new(0, vec![input], vec![output], 0).unwrap()
        };

        // The second transaction has the signed input.
        let tx_2 = {
            let input = TxInput::new(
                OutPointSourceId::Transaction(tx_1.get_id()),
                0,
                InputWitness::NoSignature(None),
            );
            let output = TxOutput::new(
                Amount::from_atoms(100),
                OutputPurpose::Transfer(Destination::PublicKey(public_key.clone())),
            );
            let mut tx = Transaction::new(0, vec![input], vec![output], 0).unwrap();
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

        let block = Block::new(
            vec![tx_1, tx_2],
            Some(chainstate.chain_config.genesis_block().get_id()),
            BlockTimestamp::from_duration_since_epoch(time::get()),
            ConsensusData::None,
        )
        .unwrap();
        chainstate.process_block(block, BlockSource::Local).unwrap();
    });
}
